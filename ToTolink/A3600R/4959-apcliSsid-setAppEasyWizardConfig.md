# [CVE-2026-1686](https://www.cve.org/CVERecord?id=CVE-2026-1686)

# TARGET

TOTOLink A3600R Router

# BUG TYPE

Buffer Overflow

# Abstract

The TOTOlink A3600R router, firmware version V5.9c.4959, contains a buffer overflow vulnerability in the `setAppEasyWizardConfig` interface of `/lib/cste_modules/app.so`. The vulnerability occurs because the `apcliSsid` parameter is not properly validated for length, allowing remote attackers to trigger a buffer overflow, potentially leading to arbitrary code execution or denial of service.

# Details

**Environment:**

* Device: TOTOlink 3600R
* Firmware version:  V5.9c.4959
* Manufacturer: [https://www.totolink.net/](https://www.totolink.net/)

**Vulnerability Analysis:**

A stack-based buffer overflow vulnerability exists in the `setAppEasyWizardConfig` function. The function retrieves the `apcliSsid` parameter from HTTP requests via `websGetVar` and copies it into a fixed-size stack buffer without proper bounds checking.

Specifically, the destination buffer `v36` is defined as `_DWORD v36[8]`, corresponding to a 32-byte stack buffer. Under certain execution conditions, the following unsafe operation is performed:

```
strcpy((char *)v36, v19);  // v19 = apcliSsid
```

Because strcpy does not enforce length validation, an attacker can supply an excessively long apcliSsid value to overflow the v36 buffer. This overflow may overwrite adjacent stack memory, leading to memory corruption, process crashes (denial of service), or potentially arbitrary code execution.

 The repeated use of these unchecked operations further increases the attack surface and elevates the overall risk and exploitability of the vulnerability.

# POC

![setAppEasyWizardConfig-1](4959-apcliSsid-setAppEasyWizardConfig.assets/setAppEasyWizardConfig-1.png)



