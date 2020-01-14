from flask import *
import requests
import json

blacklist = {'ai_detector_blacklists':{}}

app = Flask(__name__)
@app.route('/restconf/config/estinet:estinet/ai_detector_blacklists', methods=['POST'])
def task_post():
    blacklist['ai_detector_blacklists'] = request.json
    return 'add blacklist success'

@app.route('/restconf/config/estinet:estinet/ai_detector_blacklists', methods=['GET'])
def task_get():
    return Response(json.dumps(blacklist, indent=4), mimetype='application/json')

def main():
    if len(sys.argv) != 2:
        print 'python server.py {IP}'
        return
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
    app.run(host=sys.argv[1], port=8181)

if __name__ == '__main__':
    main()
