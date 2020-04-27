import json
import numpy as np
import keras as K
import time
import random
import sys
import threading
import pcap
import prctl
from tensorflow import Graph, Session, ConfigProto
import pcap
import Queue
import dpkt
from dpkt.compat import compat_ord
import signal
import netifaces as ni
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
import socket
import operator
import multiprocessing as mp
import math
polling_interval = 5
feature_set = ['AIT', 'PSP', 'BS', 'FPS', 'NNP', 'DPL', 'IOPR_B', 'APL', 'PPS', 'TBT', 'Duration', 'IOPR_P', 'PV', 'NSP', 'PX', 'src_dst_ratio', 'proto1', 'proto2', 'proto3','proto4']
#feature_dis = [1, 2,3,4,7,8,9,10,12,15,16,17,18,19]
#feature_dis = [15,16,17,18,19]
feature_dis = [2,3,4,7,8,9,10,12,15,16,17,18,19]
timestep = 12
memory_data = [{} for x in range(timestep)]
miss_count = 0
start_flag = False

mapping = {'None':[1,0,0,0],'ICMP':[0,1,0,0],'TCP':[0,0,1,0],'UDP':[0,0,0,1]}
ignore_packet = {}
src_addr_list = {}
info = {}
flow_statics = {}
last_warning = {}
mac_dic = {}
with open('mean_std_mac_new.json', 'r') as f:
    mac_dic = json.load(f)

ip_dic = {}
with open('mean_std_ip_new.json', 'r') as f:
    ip_dic = json.load(f)

def feature_default(dic):
    data = []
    for feature in feature_set:
        if feature == 'AIT' or feature == 'Duration':
            value = 5.0
        elif feature == 'IOPR_B' or feature == 'IOPR_P' or feature == 'src_dst_ratio':
            value = 1.0
        else:
            value = 0.0
        if 'proto' not in feature:
            norm = (value-float(dic[feature]['m']))/float(dic[feature]['s'])
            data.append(norm)
        else:
            data.append(0)
    return data

ip_default_feature = feature_default(ip_dic)
mac_default_feature = feature_default(mac_dic)
class attention(K.layers.Layer):
    def __init__(self,**kwargs):
        super(attention,self).__init__(**kwargs)

    def build(self,input_shape):
        self.W=self.add_weight(name="att_weight",shape=(input_shape[-1],1),initializer="normal")
        self.b=self.add_weight(name="att_bias",shape=(input_shape[1],1),initializer="zeros")
        super(attention, self).build(input_shape)

    def call(self,x):
        et=K.backend.squeeze(K.backend.tanh(K.backend.dot(x,self.W)+self.b),axis=-1)
        at=K.backend.softmax(et)
        at=K.backend.expand_dims(at,axis=-1)
        output=x*at
        return K.backend.sum(output,axis=1)

    def compute_output_shape(self,input_shape):
        return (input_shape[0],input_shape[-1])

    def get_config(self):
        return super(attention,self).get_config()

def on_connect(mq, userdata, flags, rc):
    mq.subscribe('action')

def on_message(mq, userdata, msg):
    print 'topic: ', msg.topic
    print 'payload: ', msg.payload
    global start_flag, flow_statics, p_dojob, p_sniff, e, queue, client, listen_ip
    if msg.topic == 'action':
        if msg.payload == 'start':
            if start_flag == True:
                print 'service is already running'
                return
            flow_statics = {}
            start_flag = True
           
            iface = sys.argv[3]
            listen_ip = ni.ifaddresses(iface)[2][0]['addr']
            print 'listen ip', listen_ip
           
            e = mp.Event()
            ready = mp.Event()
            queue = mp.Queue()
            p_sniff = mp.Process(target=_sniff, args=(e, iface, queue, ), name='t_sniff')
            p_dojob = mp.Process(target=_dojob, args=(ready, e, queue, ), name='t_dojob')
            print 'start dojob'
            p_dojob.start()
            print 'wait ready'
            while ready.is_set() == False:
                pass
            p_sniff.start()
            print 'service start'
            return
        elif msg.payload == 'stop':
            if start_flag == False:
                print 'service is not running'
                return
            e.set()
            p_dojob.join()
            print 'dojob end'
            p_sniff.join()
            print 'sniff end'
            start_flag = False
            print 'service stop'
            del queue
            return

def exit(signum, frame):
    global client
    client.disconnect()
    print 'mqtt disconnect'
    sys.exit(1)

class Packet:
    def __init__(self, tup=None, data=None, ptime=None):
        self.tup = tup
        self.data = data
        self.ptime = ptime
        self.next = None
        return

def main():
    if len(sys.argv) != 4:
        print 'Usage: python run.py {broker_ip} {broker_port} {NIC_name}'
        sys.exit(1)

    global client
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(sys.argv[1], sys.argv[2])
    except:
        print 'can\'t connect to broker'
        return

    signal.signal(signal.SIGINT, exit)
    signal.signal(signal.SIGTERM, exit)

    client.loop_forever()


def _dojob(ready, e, queue):
    prctl.set_name('AI detector - do job')
    global session1, session2, ip_model, mac_model
    ip_graph = Graph()
    config = ConfigProto()
    config.gpu_options.allow_growth = True
    with ip_graph.as_default():
        session1 = Session(config=config)
        with session1.as_default():
            ip_model = K.models.load_model('gru_ip_4tuple.hdf5', custom_objects={'attention':attention})
            ip_model._make_predict_function()

    mac_graph = Graph()
    with mac_graph.as_default():
        session2 = Session(config=config)
        with session2.as_default():
            mac_model = K.models.load_model('gru_mac_4tuple.hdf5', custom_objects={'attention':attention})
            mac_model._make_predict_function()
    ready.set()
    print 'set ready'
    last = time.time()
    global ignore_packet
    while e.is_set() == False:
        if queue.empty() == False:
            obj = queue.get()
            if (obj[0], obj[1]) in ignore_packet:
                if obj[3] <= ignore_packet[(obj[0], obj[1])]:
                    continue
            feature_extract((obj[2], obj[3]))
        if time.time() - last >= polling_interval:
            print queue.qsize()
            global flow_statics, src_addr_list, memory_data

            # calculate features in last 5 seconds
            result = calculate_feature(flow_statics)
            memory_data.pop(0)
            memory_data.append(result)
            t_run_exp = threading.Thread(target=_run_exp, args=(result, src_addr_list, memory_data, ))
            t_run_exp.start()
            t_run_exp.join()
            flow_statics = {}
            src_addr_list = {}
            last = time.time()
    K.backend.clear_session()
    del ip_model
    del mac_model
            
def _sniff(e, iface, queue):
    prctl.set_name('AI detector - sniff packet')
    pc = pcap.pcap(iface, promisc=True, immediate=True)
    pc.setfilter('ip')
    for ptime, pdata in pc:
        eth = dpkt.ethernet.Ethernet(pdata)
        ip = eth.data
        sip = socket.inet_ntoa(ip.src)
        smac = ':'.join('%02x' % compat_ord(b) for b in eth.src)
        queue.put((sip, smac, str(pdata), ptime))
        if e.is_set():
            break

def post_broker(warning_list):
    topic = 'blocklists'
    payload = json.dumps(warning_list)
    host = sys.argv[1]
    port = sys.argv[2]
    try:
        publish.single(topic, payload, hostname=host, port=port)
    except:
        print 'publish warning failed'
    return

def _run_exp(flow_statics, src_addr_list, memory_data):
    global session1, session2, ip_model, mac_model
    print 'start testing'
    # get 4-tuple in last memory data
    tuples = memory_data[-1].keys()
    # traceback memory data
    print 'test targets num: ', str(len(tuples))
    tmp_warning_list = []

    src_IP_port_result = {}
    src_MAC_port_result = {}
    ip_data = []
    mac_data = []
    ip_tuples = []
    mac_tuples = []
    ## predict only once
    for t in tuples:
        datas = []
        # ip 4-tuple
        if '.' in t[0]:
            for mem in memory_data:
                if t in mem:
                    datas.append(mem[t])
                else:
                    datas.append(ip_default_feature)
            ip_data.append(datas)
            ip_tuples.append(t)
        # mac 4-tuple
        else:
            for mem in memory_data:
                if t in mem:
                    datas.append(mem[t])
                else:
                    datas.append(mac_default_feature)
            mac_data.append(datas)
            mac_tuples.append(t)
    if len(ip_data) == 0 or len(mac_data) == 0:
        return
    ip_data = np.delete(ip_data, feature_dis, 2)
    mac_data = np.delete(mac_data, feature_dis, 2)
    K.backend.set_session(session1)
    ip_model._make_predict_function()
    ip_result = ip_model.predict(np.array(ip_data))
    K.backend.set_session(session2)
    mac_model._make_predict_function()
    mac_result = mac_model.predict(np.array(mac_data))
    #del ip_data
    #del mac_data
    ip_index = 0
    mac_index = 0
    global listen_ip
    for ind in range(len(ip_tuples)):
        tuples = ip_tuples[ind]
        flag = False
            
        for m_tuples in src_addr_list[tuples]:
            mac_ind = mac_tuples.index(m_tuples)
            ip_pre = ip_result[ind]
            mac_pre = mac_result[mac_ind]
            result = ip_pre+mac_pre
            if result[1] >= result[0]:
                flag = True
                break
        if flag and tuples[0] != listen_ip:
            if (tuples[0], m_tuples[0]) not in tmp_warning_list:
                tmp_warning_list.append((tuples[0], m_tuples[0]))
    if len(tmp_warning_list) == 0:
        return
    d = {"blocklists": []}
    global ignore_packet
    stop_time = time.time()
    for data in tmp_warning_list:
        d["blocklists"].append({"mac": data[1], "ipv4": data[0]})
        ignore_packet[data] = stop_time
    post_broker(d)
    return

def feature_extract(pkt_tuple):
    global flow_statics, src_addr_list, info
    raw_pkt = pkt_tuple[0]
    pkt_time = pkt_tuple[1]
    eth = dpkt.ethernet.Ethernet(raw_pkt)
    try:
        ip = eth.data
        sip = socket.inet_ntoa(ip.src)
        dip = socket.inet_ntoa(ip.dst)
    except:
        return

    smac = ':'.join('%02x' % compat_ord(b) for b in eth.src)
    dmac = ':'.join('%02x' % compat_ord(b) for b in eth.dst)
    protocol = None
    global miss_count
    if ip.p == dpkt.ip.IP_PROTO_UDP:
        protocol = 'UDP'
    elif ip.p == dpkt.ip.IP_PROTO_TCP:
        protocol = 'TCP'
    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        protocol = 'ICMP'
        return

    proto = ip.data
    try:
        sport = str(proto.sport)
    except:
        sport = None
    try:
        dport = str(proto.dport)
    except:
        dport = None

    ip_key = None
    mac_key = None
    pid = str(ip.id)
    if sport != None or protocol == 'ICMP':
        ip_key = (sip, dip, dport, protocol)
        mac_key = (smac, dmac, dport, protocol)
    if ip.off & dpkt.ip.IP_MF:
        if (sip, pid) not in info:
            if sport == None:
                ip_key = (sip, dip, dport, protocol, pid)
            info[(sip, pid)] = ip_key
        else:
            ip_key = info[(sip, pid)]
        if (smac, pid) not in info:
            if sport == None:
                mac_key = (smac, dmac, dport, protocol, pid)
            info[(smac, pid)] = mac_key
        else:
            mac_key = info[(smac, pid)]
    else:
        pass

    # fragment packet has no UDP/TCP layer
    if ip.off & dpkt.ip.IP_MF and sport != None:
        if (sip, pid) in info:
            old_key = info[(sip, pid)]
            if old_key in flow_statics:
                flow_statics[ip_key] = flow_statics[old_key].copy()
                del flow_statics[old_key]
            info[(sip, pid)] = ip_key
        if (smac, pid) in info:
            old_key = info[(smac, pid)]
            if old_key in flow_statics:
                flow_statics[mac_key] = flow_statics[old_key].copy()
                del flow_statics[old_key]
            info[(smac, pid)] = mac_key
            
    elif ip.off & dpkt.ip.IP_MF == 0:
        if (sip, pid) in info:
            if sport == None:
                ip_key = info[(sip, pid)]
            else:
                if info.get((sip, pid), None):
                    old_key = info[(sip, pid)]
                    if old_key in flow_statics:
                        flow_statics[ip_key] = flow_statics[old_key].copy()
                        del flow_statics[old_key]
            info.pop((sip, pid), None)
        if (smac, pid) in info:
            if sport == None:
                mac_key = info[(smac, pid)]
            else:
                if info.get((smac, pid), None):
                    old_key = info[(smac, pid)]
                    if old_key in flow_statics:
                        flow_statics[mac_key] = flow_statics[old_key].copy()
                        del flow_statics[old_key]
            info.pop((smac, pid), None)
    if ip_key == None or mac_key == None:
        miss_count += 1
        return
    if ip_key not in src_addr_list:
        src_addr_list[ip_key] = [mac_key]

    update_data(ip_key, eth, protocol, pkt_time, sport)
    update_data(mac_key, eth, protocol, pkt_time, sport)

def update_data(key, eth, protocol, pkt_time, sport):
    global flow_statics
    # 4-tuple
    ip = eth.data
    proto = ip.data
    if key not in flow_statics:
        flow_statics[key] = {
            'PX': 0,
            'NNP': 0,
            'NSP': 0,
            'PSP': 0,
            'IOPR_P': 0,
            'IOPR_B': 0,
            'Duration': polling_interval,
            'FPS': 0,
            'TBT': 0,
            'APL': 0,
            'DPL': 0,
            'PV': 0,
            'BS': 0,
            'last_seen': 0,
            'first_seen': 0,
            'inter_arrival': [],
            'AIT': 0,
            'PPS': 0,
            'src_dst_ratio': 0,
            'proto1': 0,
            'proto2': 0,
            'proto3': 0,
            'proto4': 0,
            'pay_sum': 0,
            'pay_square': 0,
            'pay_dict': {},
            'src_port_list': []}

    flow_statics[key]['PX'] += 1
    # no protocol layer
    if type(proto) == str:
        data = proto
    else:
        data = proto.data
    if len(data) == 0:
        flow_statics[key]['NNP'] += 1
    elif len(data) >= 63 and len(data) <= 400:
        flow_statics[key]['NSP'] += 1
    else:
        pass
    if flow_statics[key]['first_seen'] == 0:
        flow_statics[key]['first_seen'] = pkt_time
    if flow_statics[key]['FPS'] == 0:
        flow_statics[key]['FPS'] = len(eth)
    flow_statics[key]['TBT'] += len(eth)
    if len(data) not in flow_statics[key]['pay_dict']:
        flow_statics[key]['pay_dict'][len(data)] = 0
    flow_statics[key]['pay_dict'][len(data)] += 1
    if flow_statics[key]['last_seen'] != 0:
        flow_statics[key]['inter_arrival'].append(pkt_time-flow_statics[key]['last_seen'])
    flow_statics[key]['last_seen'] = pkt_time
    flow_statics[key]['pay_sum'] += len(data)
    flow_statics[key]['pay_square'] += len(data)**2
    if sport not in flow_statics[key]['src_port_list']:
        flow_statics[key]['src_port_list'].append(sport)

# TODO every 5 seconds calculate once
def calculate_feature(flow_statics):
    dst_dic = {}
    src_dic = {}
    for key in flow_statics:

        flow_statics[key]['PSP'] = float(flow_statics[key]['NSP']) / flow_statics[key]['PX']
        # deal with assymetric
        if key[2] == None and key[3] != 'ICMP':
            flow_statics[key]['IOPR_P'] = flow_statics[key]['PX']
            flow_statics[key]['IOPR_B'] = flow_statics[key]['TBT']
        else:
            asy_pkt = 0
            asy_byte = 0
            for src_port in flow_statics[key]['src_port_list']:
                asymmetric = (key[1], key[0], src_port, key[3])
                if asymmetric in flow_statics:
                    asy_pkt += flow_statics[asymmetric]['PX']
                    asy_byte += flow_statics[asymmetric]['TBT']
            if asy_pkt != 0:
                flow_statics[key]['IOPR_P'] = float(flow_statics[key]['PX']) / asy_pkt
            else:
                flow_statics[key]['IOPR_P'] = flow_statics[key]['PX']
            if asy_byte != 0:
                flow_statics[key]['IOPR_B'] = float(flow_statics[key]['TBT']) / asy_byte
            else:
                flow_statics[key]['IOPR_B'] = flow_statics[key]['TBT']

        if flow_statics[key]['last_seen'] - flow_statics[key]['first_seen'] != 0:
            flow_statics[key]['Duration'] = flow_statics[key]['last_seen'] - flow_statics[key]['first_seen']
            if flow_statics[key]['Duration'] < 0:
                print key, flow_statics[key]['last_seen'], flow_statics[key]['first_seen']

        #flow_statics[key]['APL'] = str(float(flow_statics[key]['pay_sum'])/len(flow_statics[key]['Payloads']))
        flow_statics[key]['APL'] = float(flow_statics[key]['pay_sum'])/flow_statics[key]['PX']

        h = 0
        n = flow_statics[key]['PX']
        for p, l in flow_statics[key]['pay_dict'].iteritems():
            h += (float(l)/n) * math.log(float(l)/n, 2)
        h *= -1
        flow_statics[key]['DPL'] = h
        flow_statics[key]['PV'] = (float(flow_statics[key]['pay_square']) / flow_statics[key]['PX'] - float(flow_statics[key]['APL'])**2)**0.5

        if len(flow_statics[key]['inter_arrival']) != 0:
            flow_statics[key]['AIT'] = sum(flow_statics[key]['inter_arrival']) / len(flow_statics[key]['inter_arrival'])
        else:
            flow_statics[key]['AIT'] = polling_interval
        flow_statics[key]['BS'] = flow_statics[key]['TBT'] / flow_statics[key]['Duration']
        flow_statics[key]['PPS'] = flow_statics[key]['PX'] / flow_statics[key]['Duration']
        flow_statics[key].pop('pay_dict', None)
        flow_statics[key].pop('last_seen', None)
        flow_statics[key].pop('first_seen', None)
        flow_statics[key].pop('inter_arrival', None)
        flow_statics[key].pop('pay_sum', None)
        flow_statics[key].pop('pay_square', None)
        dst = key[1]
        if dst not in dst_dic:
            dst_dic[dst] = 0
        dst_dic[dst] += len(flow_statics[key]['src_port_list'])
        if dst not in src_dic:
            src_dic[dst] = 1

        flow_statics[key]['proto1'] = mapping[str(key[3])][0]
        flow_statics[key]['proto2'] = mapping[str(key[3])][1]
        flow_statics[key]['proto3'] = mapping[str(key[3])][2]
        flow_statics[key]['proto4'] = mapping[str(key[3])][3]
    for key in flow_statics:
        src = key[0]
        if src in src_dic:
            src_dic[src] += len(flow_statics[key]['src_port_list'])
    for key in flow_statics:
        dst = key[1]
        flow_statics[key]['src_dst_ratio'] = float(dst_dic[dst])/src_dic[dst]
        flow_statics[key].pop('src_port_list', None)
    return normalize(flow_statics)

def normalize(flow_statics):
    for index in flow_statics:
        data = []
        if '.' in index[0]:
            for feature in feature_set:
                if 'proto' not in feature:
                    norm = (float(flow_statics[index][feature])-float(ip_dic[feature]['m']))/float(ip_dic[feature]['s'])
                    data.append(norm)
                else:
                    data.append(flow_statics[index][feature])
            flow_statics[index] = data
        else:
            for feature in feature_set:
                if 'proto' not in feature:
                    norm = (float(flow_statics[index][feature])-float(mac_dic[feature]['m']))/float(mac_dic[feature]['s'])
                    data.append(norm)
                else:
                    data.append(flow_statics[index][feature])
            flow_statics[index] = data
    return flow_statics

if __name__ == '__main__':
    main()
