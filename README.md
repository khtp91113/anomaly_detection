* Install nvidia driver in Host

* Install nvidia-docker in Host(run nvidia device on docker):
    * Ref: https://github.com/NVIDIA/nvidia-docker
    * Ref: https://github.com/NVIDIA/nvidia-docker/wiki/Installation-(version-2.0)

* Run docker: (port mapping: host port 9999, 10000 -> docker port 9999, 10000)
    * sudo docker load -i ddos_detect.tar
    * sudo docker run --runtime=nvidia -p 9999:9999 -p 10000:10000/tcp -p 10000:10000/udp --name c1 -itd ddos_detect <container ifname> <container ipv4>

* If install sourcecode from github
    * apt update
    * apt install git python python-pip net-tools iperf iputils-ping tcpdump netbase python-prctl -y
    * cd /home
    * git clone https://github.com/khtp91113/anomaly_detection.git
    * cd anomaly_detection
    * pip install -r requirements.txt
    * python run.py {mirror-interface} {management-ipaddr}
    * ex: python run.py eth0 172.17.0.2


* using POST method to start/stop AI detector
    * url: {host-ip}:9999/task?action={start/stop}
        * start: start service to sniff packets, analyze and report
        * stop: stop service
    * using command "ps -eT" to see whether python threads are running
        * 3 threads with names "AI detector - ..."

* detector will POST anomaly target to server(server.py) every 5 seconds
    * build server: python server.py {server-IP}
    * using GET method to server to get blacklist
    * url: {server-IP}:8181/restconf/config/estinet:estinet/ai_detector_blacklists

* Test
    * using iperf to test, open iperf server at port 10000
        * sudo docker exec -it {container_id} iperf -s -p 10000 -u
    * using another host attack current host with port 10000
        * iperf -c {host-ip} -p 10000 -t {attack-time} -u -b 1G

    * using syn_attack.py to send TCP SYN flood
        * sudo python syn_attack.py {src_IP} {src_port} {dst_IP} {dst_port}
