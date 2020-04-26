import json
import numpy as np
import keras as K
import time
import random
import sys
import threading
import pcap
import prctl
from tensorflow import Graph, Session
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

polling_interval = 5
feature_set = ['AIT', 'PSP', 'BS', 'FPS', 'NNP', 'DPL', 'IOPR_B', 'APL', 'PPS', 'TBT', 'Duration', 'IOPR_P', 'PV', 'NSP', 'PX']
timestep = 7
memory_data = [{} for x in range(timestep)]
warning_list = []
miss_count = 0
start_flag = False

ignore_packet = {}
src_addr_list = []
info = {}
flow_statics = {}
mac_dic = {}
with open('mean_std_mac.json', 'r') as f:
    mac_dic = json.load(f)

ip_dic = {}
with open('mean_std_ip.json', 'r') as f:
    ip_dic = json.load(f)

def feature_default(dic):
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

ip_default_feature = feature_default(ip_dic)
mac_default_feature = feature_default(mac_dic)

def on_connect(mq, userdata, flags, rc):
    mq.subscribe('action')

def on_message(mq, userdata, msg):
    print 'topic: ', msg.topic
    print 'payload: ', msg.payload
    global start_flag, flow_statics, p_dojob, p_sniff, e, queue, client
    if msg.topic == 'action':
        if msg.payload == 'start':
            if start_flag == True:
                print 'service is already running'
                return
            flow_statics = {}
            start_flag = True
            
            
            iface = sys.argv[3]
            ip = ni.ifaddresses(iface)[2][0]['addr']
            print 'listen ip', ip
           
            e = mp.Event()
            queue = mp.Queue()
            p_sniff = mp.Process(target=_sniff, args=(e, iface, queue, ), name='t_sniff')
            p_dojob = mp.Process(target=_dojob, args=(e, queue, ), name='t_dojob')

            p_dojob.start()
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


def _dojob(e, queue):
    prctl.set_name('AI detector - do job')
    global session1, session2, ip_model, mac_model
    ip_graph = Graph()
    with ip_graph.as_default():
        session1 = Session()
        with session1.as_default():
            ip_model = K.models.load_model('gru_add_ip.hdf5')
            ip_model._make_predict_function()

    mac_graph = Graph()
    with mac_graph.as_default():
        session2 = Session()
        with session2.as_default():
            mac_model = K.models.load_model('gru_add_mac.hdf5')
            mac_model._make_predict_function()
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
            src_addr_list = []
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
    # get 5-tuple in last memory data
    start = time.time()
    tuples = memory_data[-1].keys()
    # traceback memory data
    print 'test targets num: ', str(len(tuples))
    tmp_warning_list = []

    src_IP_port_result = {}
    src_MAC_port_result = {}
    ip_data = []
    mac_data = []
    ## predict only once
    for t in tuples:
        datas = []
        # ip 5-tuple
        if '.' in t:
            for mem in memory_data:
                if t in mem:
                    datas.append(mem[t]+[0])
                else:
                    datas.append(ip_default_feature+[0])
            ip_data.append(datas)
        # mac 5-tuple
        else:
            for mem in memory_data:
                if t in mem:
                    datas.append(mem[t]+[0])
                else:
                    datas.append(mac_default_feature+[0])
            mac_data.append(datas)
    if len(ip_data) == 0 or len(mac_data) == 0:
        return
    K.backend.set_session(session1)
    ip_model._make_predict_function()
    ip_result = ip_model.predict(np.array(ip_data))
    K.backend.set_session(session2)
    mac_model._make_predict_function()
    mac_result = mac_model.predict(np.array(mac_data))
    del ip_data
    del mac_data
    ip_index = 0
    mac_index = 0
    for t in tuples:
        # ip 5-tuple
        if '.' in t:
            tmp = t.split('\'')

            #print tmp
            src_IP = tmp[1]
            src_port = None
            pkt_id = None
            # ICMP
            if len(tmp) == 7:
                src_port = None
            elif len(tmp) == 9:
                # no port, has pkt ID => fragment
                pkt_id = tmp[7]
            # normal 5-tuple
            else:
                src_port = tmp[5]
            if src_IP not in src_IP_port_result:
                src_IP_port_result[src_IP] = {}
            l = ip_result[ip_index].tolist()
            if src_port == None:
                src_IP_port_result[src_IP][(src_port, pkt_id)] = l
            else:
                src_IP_port_result[src_IP][src_port] = l
            ip_index += 1
                
        # mac 5-tuple
        else:
            tmp = t.split('\'')
            src_MAC = tmp[1]
            src_port = None
            pkt_id = None
            if len(tmp) == 7:
                src_port = None
            elif len(tmp) == 9:
                pkt_id = tmp[7]
            else:
                src_port = tmp[5]

            if src_MAC not in src_MAC_port_result:
                src_MAC_port_result[src_MAC] = {}
            l = mac_result[mac_index].tolist()
            if src_port == None:
                src_MAC_port_result[src_MAC][(src_port, pkt_id)] = l
            else:
                src_MAC_port_result[src_MAC][src_port] = l
            mac_index += 1
    del ip_result
    del mac_result
    for src in src_addr_list:
        same_ports = set(src_IP_port_result[src[0]]).intersection(set(src_MAC_port_result[src[1]]))
        for port in same_ports:
            benign_prob = src_IP_port_result[src[0]][port][0] + src_MAC_port_result[src[1]][port][0]
            ddos_prob = src_IP_port_result[src[0]][port][1] + src_MAC_port_result[src[1]][port][1]
            if ddos_prob >= benign_prob:
                if src not in tmp_warning_list:
                    tmp_warning_list.append(src)
                break
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
    ip = eth.data
    sip = socket.inet_ntoa(ip.src)
    dip = socket.inet_ntoa(ip.dst)

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

    proto = ip.data
    try:
        sport = str(proto.sport)
    except:
        sport = None
    try:
        dport = str(proto.dport)
    except:
        dport = None

    if (sip, smac) not in src_addr_list:
        src_addr_list.append((sip, smac))
    ip_key = None
    mac_key = None
    pid = str(ip.id)
    if sport != None or protocol == 'ICMP':
        ip_key = (sip, dip, sport, dport, protocol)
        mac_key = (smac, dmac, sport, dport, protocol)
    if ip.off & dpkt.ip.IP_MF:
        if (sip, pid) not in info:
            if sport == None:
                ip_key = (sip, dip, sport, dport, protocol, pid)
            info[(sip, pid)] = ip_key
        else:
            ip_key = info[(sip, pid)]
        if (smac, pid) not in info:
            if sport == None:
                mac_key = (smac, dmac, sport, dport, protocol, pid)
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
            info.pop((sip, pid), None)
    if ip_key == None or mac_key == None:
        miss_count += 1
        return
    update_data(ip_key, eth, protocol, pkt_time)
    update_data(mac_key, eth, protocol, pkt_time)

def update_data(key, eth, protocol, pkt_time):
    global flow_statics
    # 5-tuple
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
            'Payloads': {},
            'pay_sum': 0,
            'pay_sq': 0,
            'APL': 0,
            'DPL': 0,
            'PV': 0,
            'BS': 0,
            'last_seen': 0,
            'first_seen': 0,
            'inter_arrival': [],
            'AIT': 0,
            'PPS': 0}
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
    if len(data) not in flow_statics[key]['Payloads']:
        flow_statics[key]['Payloads'][len(data)] = 1
    else:
        flow_statics[key]['Payloads'][len(data)] += 1
    flow_statics[key]['pay_sum'] += len(data)
    flow_statics[key]['pay_sq'] += len(data)**2
    if flow_statics[key]['last_seen'] != 0:
        flow_statics[key]['inter_arrival'].append(pkt_time-flow_statics[key]['last_seen'])
    flow_statics[key]['last_seen'] = pkt_time

# TODO every 5 seconds calculate once
def calculate_feature(flow_statics):
    dst_dic = {}
    src_dic = {}
    for key in flow_statics:
        flow_statics[key]['PSP'] = float(flow_statics[key]['NSP']) / flow_statics[key]['PX']
        asymmetric = (key[1], key[0], key[3], key[2], key[4])
        if asymmetric in flow_statics:
            flow_statics[key]['IOPR_P'] = float(flow_statics[key]['PX']) / flow_statics[asymmetric]['PX']
            flow_statics[key]['IOPR_B'] = float(flow_statics[key]['TBT']) / flow_statics[asymmetric]['TBT']
        else:
            flow_statics[key]['IOPR_P'] = flow_statics[key]['PX']
            flow_statics[key]['IOPR_B'] = flow_statics[key]['TBT']

        if flow_statics[key]['last_seen'] - flow_statics[key]['first_seen'] != 0:
            flow_statics[key]['Duration'] = flow_statics[key]['last_seen'] - flow_statics[key]['first_seen']
            if flow_statics[key]['Duration'] < 0:
                print key, flow_statics[key]['last_seen'], flow_statics[key]['first_seen']

        flow_statics[key]['APL'] = float(flow_statics[key]['pay_sum'])/flow_statics[key]['PX']
        #counts = dict((x, flow_statics[key]['Payloads'].count(x)) for x in flow_statics[key]['Payloads'])
        #flow_statics[key]['DPL'] = round(float(max(counts.iteritems(), key=operator.itemgetter(1))[0]) / flow_statics[key]['PX'], 2)
        flow_statics[key]['DPL'] = float(max(flow_statics[key]['Payloads'].values()))/flow_statics[key]['PX']
        #flow_statics[key]['PV'] = np.std(flow_statics[key]['Payloads'])
        flow_statics[key]['PV'] = (float(flow_statics[key]['pay_sq'])/flow_statics[key]['PX'] - flow_statics[key]['APL']**2)**0.5
        if len(flow_statics[key]['inter_arrival']) != 0:
            flow_statics[key]['AIT'] = sum(flow_statics[key]['inter_arrival']) / len(flow_statics[key]['inter_arrival'])
        else:
            flow_statics[key]['AIT'] = polling_interval
        flow_statics[key]['BS'] = flow_statics[key]['TBT'] / flow_statics[key]['Duration']
        flow_statics[key]['PPS'] = flow_statics[key]['PX'] / flow_statics[key]['Duration']
        flow_statics[key].pop('Payloads', None)
        flow_statics[key].pop('last_seen', None)
        flow_statics[key].pop('first_seen', None)
        flow_statics[key].pop('inter_arrival', None)
    flow_statics = {str(key): value for key, value in flow_statics.items()}
    return normalize(flow_statics)

def normalize(flow_statics):
    for index in flow_statics:
        data = []
        if '.' in index[0]:
            for feature in feature_set:
                norm = (float(flow_statics[index][feature])-float(ip_dic[feature]['m']))/float(ip_dic[feature]['s'])
                data.append(norm)
            flow_statics[index] = data
        else:
            for feature in feature_set:
                norm = (float(flow_statics[index][feature])-float(mac_dic[feature]['m']))/float(mac_dic[feature]['s'])
                data.append(norm)
            flow_statics[index] = data
    return flow_statics
            
if __name__ == '__main__':
    main()
