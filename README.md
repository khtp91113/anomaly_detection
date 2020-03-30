* Install nvidia driver in Host

* Install nvidia-docker in Host(run nvidia device on docker):
    * Ref: https://github.com/NVIDIA/nvidia-docker
    * Ref: https://github.com/NVIDIA/nvidia-docker/wiki/Installation-(version-2.0)

* Run docker: (port mapping: host port 10000 -> docker port 10000)
    * sudo docker load -i ddos_detect.tar
    * sudo docker run --runtime=nvidia -p 0.0.0.0:10000:10000 -p 0.0.0.0:10000:10000/udp --name c1 -itd ddos_detect ddos_detect `<broker ipv4> <broker port>`

* If install sourcecode from github
    * apt update
    * apt install git python python-pip net-tools iperf iputils-ping tcpdump netbase python-prctl python-pypcap -y
    * cd /home
    * git clone https://github.com/khtp91113/anomaly_detection.git
    * cd anomaly_detection
    * pip install -r requirements.txt
    * python run.py `<broker ipv4> <broker port>`


* using mqtt to start/stop AI detector
    * Topic: action
    * Payload: start  or  stop
        * start: start service to sniff packets, analyze and report
        * stop: stop service
    * using command "ps -eT" to see whether python threads are running
        * 3 threads with names "AI detector - ..."

* detector will publish anomaly target to broker every 5 seconds
    * Topic: blocklists
    * Payload: anomaly targets(IP, mac) in json format

* Test
    * using udp flood to test
        * sudo python flood_udp.py {dstIP} {dst port} {attack_time}
        * Ref: https://gist.github.com/Ananasr/e05f3286b6ab94ec2c5431e64832c13e
	* example: python flood_udp.py [hostIP] 10000 100
    * using TCP SYN flood to test
        * sudo python SYN-Flood.py
        * Ref: https://github.com/EmreOvunc/Python-SYN-Flood-Attack-Tool
	* example: src IP: 1.1.1.1, dst IP: hostIP, dst port: 10000, packet num: 10000
