import json
import numpy as np
import keras as K
import time
import random
import sys
import threading
from datetime import datetime
from scapy.all import *
import pcap
import prctl
from tensorflow import Graph, Session
import pcap
from scapy.layers.l2 import Ether
import Queue
import dpkt
from dpkt.compat import compat_ord
import signal
import socket
import multiprocessing as mp

polling_interval = 5
feature_set = ['AIT', 'PSP', 'BS', 'FPS', 'NNP', 'DPL', 'IOPR_B', 'APL', 'PPS', 'TBT', 'Duration', 'IOPR_P', 'PV', 'NSP', 'PX', 'src_dst_ratio']
timestep = 7
memory_data = [{} for x in range(timestep)]
warning_list = []
miss_count = 0
start_flag = False

outputfile = open('output_add_ddos4.txt', 'w')
ip_model_path = 'gru_add_ip.hdf5'
mac_model_path = 'gru_add_mac.hdf5'

attacker = []
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


src_addr_list = []
info = {}
flow_statics = {}
total_count = 0
ddos_target1=[]
ddos_target2=[]
#ddos_target1 = [('172.20.200.209', '501'), ('172.20.200.209', '31020'), ('172.20.200.209','10022'), ('172.20.200.209', '3060'), ('172.20.200.209', '5560'), ('172.20.200.209', '52')]
#ddos_target2 = [('172.20.200.217', '192.20.200.219'), ('172.20.200.211', '172.20.200.209'), ('172.20.200.219', '172.20.200.209'), ('172.20.200.221', '172.20.200.209'), ('172.20.200.218', '172.20.200.209')]
#ddos_target2 = [('10.0.0.2', '10.0.0.1'), ('10.0.0.3', '10.0.0.1'), ('10.0.0.4', '10.0.0.1')]
def exit(signum, frame):
    global e
    e.set()
    sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print 'Usage: python run.py {mirror_interface}'
        sys.exit(1)

    signal.signal(signal.SIGINT, exit)
    signal.signal(signal.SIGTERM, exit)
    start_flag = True
    queue = mp.Queue()
    global e
    e = mp.Event()
    iface = sys.argv[1]
    #t_sniff = threading.Thread(target=_sniff, args=(e, iface, queue, ), name='t_sniff')
    #t_dojob = threading.Thread(target=_dojob, args=(e, queue, ), name='t_dojob')

    #t_dojob.start()
    #t_sniff.start()
    p_sniff = mp.Process(target=_sniff, args=(e, iface, queue, ))
    p_dojob = mp.Process(target=_dojob, args=(e, queue, ))
    p_sniff.start()
    p_dojob.start()


def _dojob(e, queue):
    prctl.set_name('AI detector - do job')
    global session1, session2, ip_model, mac_model
    ip_graph = Graph()
    with ip_graph.as_default():
        session1 = Session()
        with session1.as_default():
            ip_model = K.models.load_model(ip_model_path)
            ip_model._make_predict_function()

    mac_graph = Graph()
    with mac_graph.as_default():
        session2 = Session()
        with session2.as_default():
            mac_model = K.models.load_model(mac_model_path)
            mac_model._make_predict_function()
    #pcap_file = open('test.pcap', 'wb')
    #writer = dpkt.pcap.Writer(pcap_file)
    global total_tp, total_tn, total_fp, total_fn 
    total_tp = 0
    total_tn = 0
    total_fp = 0
    total_fn = 0
    last = time.time()
    #count_lock = threading.Lock()
    while e.is_set() == False:
        if queue.empty() == False:
            obj = queue.get()
            feature_extract(obj)
            current = obj[1]
        else:
            current = time.time()
        if current - last >= polling_interval:
            global flow_statics, src_addr_list, attacker
            #calculate features in last 5 seconds
            result = calculate_feature(flow_statics)
            memory_data.pop(0)
            memory_data.append(result)
            #t_run_exp = threading.Thread(target=_run_exp, args=(flow_statics, src_addr_list, attacker, memory_data, count_lock, ))
            t_run_exp = threading.Thread(target=_run_exp, args=(flow_statics, src_addr_list, attacker, memory_data, ))
            t_run_exp.start()
            t_run_exp.join()
            flow_statics = {}
            src_addr_list = []
            attacker = []
            last = current
            
    K.backend.clear_session()
    del ip_model
    del mac_model

def _sniff(e, iface, queue):
    prctl.set_name('AI detector - sniff packet')
    pc = pcap.pcap(iface, promisc=True, immediate=True)
    print iface
    pc.setfilter('ip')
    count = 0
    #pcap_file = open('test.pcap', 'wb')
    #writer = dpkt.pcap.Writer(pcap_file)
    for ptime, pdata in pc:
        #lock.acquire()
        count += 1
        if count % 10000 == 0:
            print 'sniff count ', count
        #if (pdata, ptime) not in queue.queue:
        #if ptime != last_time and pdata != last_data:
        queue.put((str(pdata), ptime))
        #tmp = queue.get()
        #writer.writepkt(tmp[0], tmp[1])
        #    last_time = ptime
        #    last_data = pdata
        #feature_extract((pdata, ptime))
        #lock.release()
        if e.is_set():
            break

def _run_exp(flow_statics, src_addr_list, attacker, memory_data):
    global session1, session2, ip_model, mac_model
    print 'start testing'
    outputfile.write('start testing\n')
    # get 5-tuple in last memory data
    tuples = memory_data[-1].keys()
    # traceback memory data
    print 'test targets num: ', str(len(tuples))
    outputfile.write('test targets num: '+ str(len(tuples))+'\n')
    tmp_warning_list = []

    src_IP_port_result = {}
    src_MAC_port_result = {}
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    ip_data = []
    mac_data = []
    #outputfile.write(str(flow_statics)+'\n')
    ## predict only once
    for t in tuples:
        datas = []
        # ip 5-tuple
        if '.' in t:
            for mem in memory_data:
                if t in mem:
                    datas.append(mem[t])
                else:
                    datas.append(ip_default_feature)
            ip_data.append(datas)
        # mac 5-tuple
        else:
            for mem in memory_data:
                if t in mem:
                    datas.append(mem[t])
                else:
                    datas.append(mac_default_feature)
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
    #print attacker
    #outputfile.write('attacker: '+str(attacker)+'\n')
    ip_index = 0
    mac_index = 0
    for t in tuples:
        flag = False
        if t in attacker:
            flag = True
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
            l.append(flag)
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
            l.append(flag)
            if src_port == None:
                src_MAC_port_result[src_MAC][(src_port, pkt_id)] = l
            else:
                src_MAC_port_result[src_MAC][src_port] = l
            mac_index += 1
    del ip_result
    del mac_result
    #print src_IP_port_result
    #print src_MAC_port_result
    #outputfile.write('src_IP_port_result '+ str(src_IP_port_result)+'\n')
    #outputfile.write('src_MAC_port_result '+ str(src_MAC_port_result)+'\n')
    #outputfile.flush()
    for src in src_addr_list:
        same_ports = set(src_IP_port_result[src[0]]).intersection(set(src_MAC_port_result[src[1]]))
        for port in same_ports:
            benign_prob = src_IP_port_result[src[0]][port][0] + src_MAC_port_result[src[1]][port][0]
            ddos_prob = src_IP_port_result[src[0]][port][1] + src_MAC_port_result[src[1]][port][1]
            if src_IP_port_result[src[0]][port][2] != src_MAC_port_result[src[1]][port][2]:
                outputfile.write('label not match\n')
            label = src_IP_port_result[src[0]][port][2] | src_MAC_port_result[src[1]][port][2]
            if ddos_prob >= benign_prob:
                if label == True:
                    tp += 2
                else:
                    fp += 2
                #if src not in tmp_warning_list:
                #    tmp_warning_list.append(src)
                #break
            else:
                if label == True:
                    fn += 2
                else:
                    tn += 2
    global total_tp, total_tn, total_fp, total_fn
    #count_lock.acquire()
    total_tp += tp
    total_tn += tn
    total_fp += fp
    total_fn += fn
    print 'total_tp ', total_tp, ', total_tn ', total_tn, ', total_fp ', total_fp, ',total_fn ', total_fn
    outputfile.write('total_tp '+ str(total_tp)+ ', total_tn '+ str(total_tn)+ ', total_fp '+ str(total_fp)+ ',total_fn '+ str(total_fn) + '\n')
    outputfile.flush()
    #count_lock.release()
    #d = {"blocklists": []}
    #for data in tmp_warning_list:
    #    d["blocklists"].append({"mac": data[1], "ipv4": data[0]})
    #print(json.dumps(d, indent=4, sort_keys=True))
    #global warn_lock, warning_list
    #warn_lock.acquire()
    #warning_list = tmp_warning_list
    #warn_lock.release()
    return

#def process(packet, ts):
    #global lock
    #lock.acquire()
    #global total_count
    #total_count += 1
    #if total_count % 10000 == 0:
    #    print total_count
    #lock.release()

def feature_extract(pkt_tuple):
    global flow_statics, src_addr_list, total_count, info
    total_count += 1
    #outputfile.write('new packet\n')
    if total_count % 10000 == 0:
        print total_count
    tmp = time.time()
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
    #outputfile.write('count ' + sip + ' ' + dip + ' ' + str(sport) + ' ' + pid + ' ' + str(ip.off) + '\n')
    #outputfile.flush()
    #if protocol == 'UDP' or protocol == 'TCP' or protocol == 'ICMP':
    if sport != None or protocol == 'ICMP':
        ip_key = (sip, dip, sport, dport, protocol)
        mac_key = (smac, dmac, sport, dport, protocol)
    if ip.off & dpkt.ip.IP_MF:
        if (sip, pid) not in info:
            #if protocol == None:
            if sport == None:
                ip_key = (sip, dip, sport, dport, protocol, pid)
            #outputfile.write('Add ' + str((sip, pid)) + ' ' + str(ip_key) + '\n')
            #outputfile.flush()
            info[(sip, pid)] = ip_key
        else:
            ip_key = info[(sip, pid)]
        if (smac, pid) not in info:
            #if protocol == None:
            if sport == None:
                mac_key = (smac, dmac, sport, dport, protocol, pid)
            info[(smac, pid)] = mac_key
        else:
            mac_key = info[(smac, pid)]
    else:
        pass

    # fragment packet has no UDP/TCP layer
    #if ip.off & dpkt.ip.IP_MF and protocol != None:
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
            #if protocol == None:
            #outputfile.write('info\n')
            #outputfile.write(str(info)+'\n')
            #outputfile.flush()
            if sport == None:
                #outputfile.write('info: '+str(info[(sip, pid)]) + '\n')
                ip_key = info[(sip, pid)]
            else:
                if info.get((sip, pid), None):
                    old_key = info[(sip, pid)]
                    if old_key in flow_statics:
                        flow_statics[ip_key] = flow_statics[old_key].copy()
                        del flow_statics[old_key]
            #del info[(sip, pid)]
            info.pop((sip, pid), None)
            #outputfile.write('Remove ' + str((sip, pid)) + '\n')
            #outputfile.write('IP key: '+str(ip_key)+'\n')
            #outputfile.flush()
        if (smac, pid) in info:
            #if protocol == None:
            if sport == None:
                #outputfile.write('info: '+str(info[(smac, pid)]) + '\n')
                mac_key = info[(smac, pid)]
            else:
                if info.get((smac, pid), None):
                    old_key = info[(smac, pid)]
                    if old_key in flow_statics:
                        flow_statics[mac_key] = flow_statics[old_key].copy()
                        del flow_statics[old_key]
            #del info[(smac, pid)]
            info.pop((smac, pid), None)
            #outputfile.write('Remove ' + str((smac, pid)) + '\n')
            #outputfile.write('MAC key: '+str(mac_key)+'\n')
            #outputfile.flush()
    else:
        pass
    #outputfile.write(str(ip_key)+'\n')
    #outputfile.write(str(mac_key)+'\n')
    if ip_key == None or mac_key == None:
        miss_count += 1
        #print miss_count, pkt.time
        outputfile.write('miss_count ' + str(miss_count)+' '+ str(pkt_time)+'\n')
        #outputfile.write(str(ip_key)+'\n')
        #outputfile.write(str(mac_key)+'\n')
        #outputfile.write(str(sport)+' '+str(protocol)+' '+str(pid) + ' '+str(ip.off)+'\n')
        #outputfile.write(str(info)+'\n')
        outputfile.flush()
        return
    global attacker
    if protocol == 'TCP' and proto.flags & dpkt.tcp.TH_SYN:
        if (dip, dport) in ddos_target1:
            if str(ip_key) not in attacker:
                attacker.append(str(ip_key))
            if str(mac_key) not in attacker:
                attacker.append(str(mac_key))
    if (sip, dip) in ddos_target2:
        if str(ip_key) not in attacker:
            attacker.append(str(ip_key))
        if str(mac_key) not in attacker:
            attacker.append(str(mac_key))
    update_data(ip_key, eth, protocol, pkt_time)
    update_data(mac_key, eth, protocol, pkt_time)
    return

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
            'Payloads': [],
            'APL': 0,
            'DPL': 0,
            'PV': 0,
            'BS': 0,
            'last_seen': 0,
            'first_seen': 0,
            'inter_arrival': [],
            'AIT': 0,
            'PPS': 0,
            'src_dst_ratio': 0}
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
    flow_statics[key]['Payloads'].append(len(data))
    if flow_statics[key]['last_seen'] != 0:
        flow_statics[key]['inter_arrival'].append(pkt_time-flow_statics[key]['last_seen'])
    flow_statics[key]['last_seen'] = pkt_time

# TODO every 5 seconds calculate once
def calculate_feature(flow_statics):
    dic = {}
    for key in flow_statics:
        flow_statics[key]['PSP'] = round(float(flow_statics[key]['NSP']) / flow_statics[key]['PX'], 2)
        asymmetric = (key[1], key[0], key[3], key[2], key[4])
        if asymmetric in flow_statics:
            flow_statics[key]['IOPR_P'] = round(float(flow_statics[key]['PX']) / flow_statics[asymmetric]['PX'], 2)
            flow_statics[key]['IOPR_B'] = round(float(flow_statics[key]['TBT']) / flow_statics[asymmetric]['TBT'], 2)
        else:
            flow_statics[key]['IOPR_P'] = flow_statics[key]['PX']
            flow_statics[key]['IOPR_B'] = flow_statics[key]['TBT']

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
        dst = key[1]
        if dst not in dic:
            dic[dst] = 1
        else:
            dic[dst] += 1
    for key in flow_statics:
        flow_statics[key]['src_dst_ratio'] = dic[key[1]]
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
