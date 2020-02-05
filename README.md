* Install nvidia driver in Host

* Install nvidia-docker in Host(run nvidia device on docker):
    * Ref: https://github.com/NVIDIA/nvidia-docker
    * Ref: https://github.com/NVIDIA/nvidia-docker/wiki/Installation-(version-2.0)

* Run docker: (port mapping: host port 9999, 10000 -> docker port 9999, 10000)
    * sudo docker load -i ddos_detect.tar
    * sudo docker run --runtime=nvidia -p 9999:9999 -p 10000:10000/tcp -p 10000:10000/udp --name c1 -itd ddos_detect `<broker ipv4> <broker port>`

* If install sourcecode from github
    * apt update
    * apt install git python python-pip net-tools iperf iputils-ping tcpdump netbase python-prctl -y
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
    * Payload: anomaly targets in json format

* Test
    * using iperf to test, open iperf server at port 10000
        * sudo docker exec -it {container_id} iperf -s -p 10000 -u
    * using another host attack current host with port 10000
        * iperf -c {host-ip} -p 10000 -t {attack-time} -u -b 1G

    * using syn_attack.py to send TCP SYN flood
        * sudo python syn_attack.py {src_IP} {src_port} {dst_IP} {dst_port}
