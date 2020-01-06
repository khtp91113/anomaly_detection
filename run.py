import json
import numpy as np
import keras as K
import time
import random
import sys
import gc
import threading
from scapy.all import *

polling_interval = 5
feature_set = ['AIT', 'PSP', 'BS', 'FPS', 'NNP', 'DPL', 'IOPR_B', 'APL', 'PPS', 'TBT', 'Duration', 'IOPR_P', 'PV', 'NSP', 'PX']
timestep = 7
memory_data = [{} for x in range(timestep)]
min_dict = {}
max_dict = {}
with open('min.json', 'r') as fo:
    d = json.load(fo)
    min_dict = d
with open('max.json', 'r') as fo:
    d = json.load(fo)
    max_dict = d

def main():
    if len(sys.argv) != 2:
        print 'Usage: python run.py {interface}'
        sys.exit(1)

    model_path = 'gru_best_weight_1_7_640u.hdf5'
    model = K.models.load_model(model_path)
    global flow_statics, lock1, lock2, lock_count, memory_data, timestep
    lock1 = threading.Lock()
    lock2 = threading.Lock()
    lock_count = 0
    flow_statics = {}
    e = threading.Event()
    iface = sys.argv[1]
    t = threading.Thread(target=_sniff, args=(e, iface, ))
    # start sniffing
    t.start()
    stop_flag = False
    count = 0
    while stop_flag == False:
        time.sleep(5)

        lock1.acquire()
        lock_count += 1
        if lock_count == 1:
            lock2.acquire()
        lock1.release()

        tmp_flow_statics = flow_statics
        flow_statics = {}
        
        lock1.acquire()
        lock_count -= 1
        if lock_count == 0:
            lock2.release()
        lock1.release()

        # calculate features in last 5 seconds
        result = calculate_feature(tmp_flow_statics)
        memory_data.pop(0)
        memory_data.append(result)
        run_exp(model)

        count += 1
        if count == 12:
            stop_flag = True
    # stop sniffing
    e.set()

def _sniff(e, iface):
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
        norm = (value-min_dict[feature])/(max_dict[feature]-min_dict[feature])
        data.append(norm)
    return data

def run_exp(model):
    num_feature = 15
    print 'start testing'
    # get 5-tuple in last memory data
    global memory_data
    tuples = memory_data[-1].keys()
    # traceback memory data
    print 'test targets num: ', str(len(tuples))
    for t in tuples:
        datas = []
        for mem in memory_data:
            if t in mem:
                datas.append(mem[t])
            else:
                datas.append(feature_default())   

        print str(t), str(np.argmax(model.predict(np.array([datas])), axis=1))
    return

def process(packet):
    feature_extract(packet)

def feature_extract(pkt):
    global lock2
    lock2.acquire()
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
            flow_statics[(sip, dip, sport, dport, protocol)]['first_seen'] = pkt.time
        if flow_statics[(sip, dip, sport, dport, protocol)]['FPS'] == 0:
            flow_statics[(sip, dip, sport, dport, protocol)]['FPS'] = len(pkt.payload)
        flow_statics[(sip, dip, sport, dport, protocol)]['TBT'] += len(pkt.payload)
        flow_statics[(sip, dip, sport, dport, protocol)]['Payloads'].append(len(pkt[protocol].payload))
        if flow_statics[(sip, dip, sport, dport, protocol)]['last_seen'] != 0:
            flow_statics[(sip, dip, sport, dport, protocol)]['inter_arrival'].append(pkt.time-flow_statics[(sip, dip, sport, dport, protocol)]['last_seen'])
        flow_statics[(sip, dip, sport, dport, protocol)]['last_seen'] = pkt.time
    lock2.release()

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
            norm = (flow_statics[index][feature]-min_dict[feature])/(max_dict[feature]-min_dict[feature])
            if norm > 1:
                norm = 1
            elif norm < 0:
                norm = 0
            else:
                pass
            data.append(norm)
        flow_statics[index] = data
    return flow_statics
            

if __name__ == '__main__':
    main()
