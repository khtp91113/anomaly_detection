* Install nvidia-docker in Host(run nvidia device on docker):
    * Ref: https://github.com/NVIDIA/nvidia-docker/wiki/Installation-(version-2.0)
* Install Cuda & Cudnn in Host

* Run docker:
    * cat detector.tar | sudo docker import - tensorflow/tensorflow:1.14.0-gpu
    * sudo docker run --runtime=nvidia -p 9999:9999 --name c1 -itd tensorflow/tensorflow:1.14.0-gpu bash

* If install sourcecode from github
    * apt update
    * apt install git python python-pip net-tools iperf iputils-ping tcpdump
    * cd /home
    * git clone https://github.com/khtp91113/anomaly_detection.git
    * cd anomaly_detection
    * pip install -r requirements.txt

* Usage:
    * cd /home/anomaly_detection
    * python run.py {mirror-interface} {management-ipaddr}
    * ex: python run.py eth0 172.17.0.2

* using POST method to start/stop AI detector

url: {host-ip}:9999/task={start/stop}

* using GET method to get warning host

url: {host-ip}:9999/warning
