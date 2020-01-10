* Install nvidia driver in Host

* Install nvidia-docker in Host(run nvidia device on docker):
    * Ref: https://github.com/NVIDIA/nvidia-docker
    * Ref: https://github.com/NVIDIA/nvidia-docker/wiki/Installation-(version-2.0)

* Run docker: (port mapping: host port 9999 -> docker port 9999)
    * sudo docker load -i ddos_detect.tar
    * sudo docker run --runtime=nvidia -p 9999:9999 --name c1 -itd ddos_detect <docker ifname> <docker ipv4>

* If install sourcecode from github
    * apt update
    * apt install git python python-pip net-tools iperf iputils-ping tcpdump netbase -y
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

* using GET method to get warning host
    * url: {host-ip}:9999/warning
