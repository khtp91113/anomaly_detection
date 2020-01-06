Install required python package:
    sudo pip install -r requirements.txt

Usage: python run.py {mirror-interface} {management-ipaddr}

using POST method to start/stop AI detector
url: {ip}:9999/task={start/stop}

using GET method to get warning host
url: {ip}:9999/warning
