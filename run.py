import json
import numpy as np
import keras as K
import time
import random
import sys
import threading
from datetime import datetime
from scapy.all import *
from flask import *
import prctl

polling_interval = 5
feature_set = ['AIT', 'PSP', 'BS', 'FPS', 'NNP', 'DPL', 'IOPR_B', 'APL', 'PPS', 'TBT', 'Duration', 'IOPR_P', 'PV', 'NSP', 'PX']
timestep = 7
memory_data = [{} for x in range(timestep)]
hq = []
warning_list = []

start_flag = False
app = Flask(__name__)
@app.route('/task', methods=['POST'])
def task():
    global start_flag, flow_statics, t_dojob, t_sniff, t_calculate, e
    task = request.values['action']
    if task == 'stop':
        if start_flag == False:
            return 'service is not running'
        e.set()
        t_dojob.join()
        t_sniff.join()
        t_calculate.join()
        start_flag = False
        return 'service stop'
    elif task == 'start':
        if start_flag == True:
            return 'service is already running'
        flow_statics = {}
        start_flag = True
        
        model_path = 'model.hdf5'
        model = K.models.load_model(model_path)
        model.predict(np.array([[feature_default() for x in range(timestep)]]))

        e = threading.Event()
        iface = sys.argv[1]
        t_sniff = threading.Thread(target=_sniff, args=(e, iface, ), name='t_sniff')
        t_calculate = threading.Thread(target=_calculate, args=(e, ), name='t_calculate')
        t_dojob = threading.Thread(target=_dojob, args=(e, model, ), name='t_dojob')

        t_dojob.start()
        t_sniff.start()
        t_calculate.start()
        return 'service start'

@app.route('/warning', methods=['GET'])
def warning():
    global warn_lock, warning_list
    warn_lock.acquire()
    tmp = str(warning_list)
    warn_lock.release()
    return tmp

dic = {}
with open('mean_std.json', 'r') as f:
    dic = json.load(f)

def main():
    if len(sys.argv) != 3:
        print 'Usage: python run.py {mirror_interface} {manage_interface_ip}'
        sys.exit(1)

    global lock, warn_lock
    lock = threading.Lock()
    warn_lock = threading.Lock()


    app.run(host=sys.argv[2], port=9999)


def _dojob(e, model):
    prctl.set_name('AI detector - do job')
    global lock
    while e.is_set() == False:
        lock.acquire()
        if len(hq) != 0:
            obj = hq.pop(0)
            lock.release()
            if type(obj) == str:
                global flow_statics
                tmp_flow_statics = flow_statics
                flow_statics = {}

                # calculate features in last 5 seconds
                result = calculate_feature(tmp_flow_statics)
                memory_data.pop(0)
                memory_data.append(result)
                run_exp(model)
            else:
                feature_extract(obj)
        else:
            lock.release()
    K.backend.clear_session()
    del model

def _calculate(e):
    prctl.set_name('AI detector - schedule calculate feature')
    while e.is_set() == False:
        time.sleep(5)
        global lock
        lock.acquire()
        hq.insert(0, 'calculate')
        lock.release()

def _sniff(e, iface):
    prctl.set_name('AI detector - sniff packet')
    num = sniff(iface=iface, filter='ip', store=False, prn=process, stop_filter=lambda x: e.is_set())

def feature_default():
    data = []
    for feature in feature_set:
        if feature == 'AIT' or feature == 'Duration':
            value = 5.0
        elif feature == 'IOPR_B' or feature == 'IOPR_P':
            value = 1.0
        else:
            value = 0.0
        norm = (value-float(dic[feature]['m']))/float(dic[feature]['s'])
        data.append(norm)
    return data

def run_exp(model):
    print 'start testing'
    # get 5-tuple in last memory data
    global memory_data
    tuples = memory_data[-1].keys()
    # traceback memory data
    print 'test targets num: ', str(len(tuples))
    tmp_warning_list = []
    for t in tuples:
        datas = []
        for mem in memory_data:
            if t in mem:
                datas.append(mem[t])
            else:
                datas.append(feature_default())
        result = np.argmax(model.predict(np.array([datas])), axis=1)
        print str(t), str(np.argmax(model.predict(np.array([datas])), axis=1))
        if result == 1:
            tmp_warning_list.append(str(t))

    global warn_lock, warning_list
    warn_lock.acquire()
    warning_list = tmp_warning_list
    warn_lock.release()
    return

def process(packet):
    global lock
    lock.acquire()
    hq.append(packet)
    lock.release()

def feature_extract(pkt):
    global flow_statics
    # params. of epochs
    if pkt.haslayer(IP):
        sip = pkt[IP].src
        dip = pkt[IP].dst

        protocol = None
        if pkt.haslayer(UDP):
            protocol = 'UDP'
        elif pkt.haslayer(TCP):
            protocol = 'TCP'
        else:
            return
        sport = pkt[protocol].sport
        dport = pkt[protocol].dport
        # 5-tuple
        if (sip, dip, sport, dport, protocol) not in flow_statics:
            flow_statics[(sip, dip, sport, dport, protocol)] = {
                'PX': 0,
                'NNP': 0,
                'NSP': 0,
                'PSP': 0,
                'IOPR_P': 0,
                'IOPR_B': 0,
                'Duration': polling_interval,
                'FPS': 0,
                'TBT': 0,
                'Payloads': [],
                'APL': 0,
                'DPL': 0,
                'PV': 0,
                'BS': 0,
                'last_seen': 0,
                'first_seen': 0,
                'inter_arrival': [],
                'AIT': 0,
                'PPS': 0}
        flow_statics[(sip, dip, sport, dport, protocol)]['PX'] += 1
        if len(pkt[protocol].payload) == 0:
            flow_statics[(sip, dip, sport, dport, protocol)]['NNP'] += 1
        elif len(pkt[protocol].payload) >= 63 and len(pkt[protocol].payload) <= 400:
            flow_statics[(sip, dip, sport, dport, protocol)]['NSP'] += 1
        else:
            pass
        if flow_statics[(sip, dip, sport, dport, protocol)]['first_seen'] == 0:
            flow_statics[(sip, dip, sport, dport, protocol)]['first_seen'] = pkt.time
        if flow_statics[(sip, dip, sport, dport, protocol)]['FPS'] == 0:
            flow_statics[(sip, dip, sport, dport, protocol)]['FPS'] = len(pkt.payload)
        flow_statics[(sip, dip, sport, dport, protocol)]['TBT'] += len(pkt.payload)
        flow_statics[(sip, dip, sport, dport, protocol)]['Payloads'].append(len(pkt[protocol].payload))
        if flow_statics[(sip, dip, sport, dport, protocol)]['last_seen'] != 0:
            flow_statics[(sip, dip, sport, dport, protocol)]['inter_arrival'].append(pkt.time-flow_statics[(sip, dip, sport, dport, protocol)]['last_seen'])
        flow_statics[(sip, dip, sport, dport, protocol)]['last_seen'] = pkt.time

# TODO every 5 seconds calculate once
def calculate_feature(flow_statics):
    for key in flow_statics:
        flow_statics[key]['PSP'] = round(float(flow_statics[key]['NSP']) / flow_statics[key]['PX'], 2)
        asymmetric = (key[1], key[0], key[3], key[2], key[4])
        if asymmetric in flow_statics:
            flow_statics[key]['IOPR_P'] = round(float(flow_statics[key]['PX']) / flow_statics[asymmetric]['PX'], 2)
            flow_statics[key]['IOPR_B'] = round(float(flow_statics[key]['TBT']) / flow_statics[asymmetric]['TBT'], 2)
        else:
            flow_statics[key]['IOPR_P'] = 1.0
            flow_statics[key]['IOPR_B'] = 1.0

        if flow_statics[key]['last_seen'] - flow_statics[key]['first_seen'] != 0:
            flow_statics[key]['Duration'] = flow_statics[key]['last_seen'] - flow_statics[key]['first_seen']
            if flow_statics[key]['Duration'] < 0:
                print key, flow_statics[key]['last_seen'], flow_statics[key]['first_seen']

        flow_statics[key]['APL'] = round(float(sum(flow_statics[key]['Payloads']))/len(flow_statics[key]['Payloads']), 2)
        counts = dict((x, flow_statics[key]['Payloads'].count(x)) for x in flow_statics[key]['Payloads'])
        flow_statics[key]['DPL'] = round(float(max(counts.iteritems(), key=operator.itemgetter(1))[0]) / flow_statics[key]['PX'], 2)
        flow_statics[key]['PV'] = round(np.std(flow_statics[key]['Payloads']), 2)
        if len(flow_statics[key]['inter_arrival']) != 0:
            flow_statics[key]['AIT'] = round(sum(flow_statics[key]['inter_arrival']) / len(flow_statics[key]['inter_arrival']), 2)
        else:
            flow_statics[key]['AIT'] = polling_interval
        flow_statics[key]['BS'] = round(flow_statics[key]['TBT'] / flow_statics[key]['Duration'], 2)
        flow_statics[key]['PPS'] = round(flow_statics[key]['PX'] / flow_statics[key]['Duration'], 2)
        flow_statics[key]['Duration'] = flow_statics[key]['Duration']
        flow_statics[key].pop('Payloads', None)
        flow_statics[key].pop('last_seen', None)
        flow_statics[key].pop('first_seen', None)
        flow_statics[key].pop('inter_arrival', None)

    flow_statics = {str(key): value for key, value in flow_statics.items()}
    return normalize(flow_statics)

def normalize(flow_statics):
    for index in flow_statics:
        data = []
        for feature in feature_set:
            norm = (float(flow_statics[index][feature])-float(dic[feature]['m']))/float(dic[feature]['s'])
            data.append(norm)
        flow_statics[index] = data
    return flow_statics
            
if __name__ == '__main__':
    main()
