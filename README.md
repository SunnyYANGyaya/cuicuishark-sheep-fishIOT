# IOT-vulnerability-report
fish、sheep：

## LINKSYS

| 序号 | Firmware      | Number          | Type | Details              |
| ---- | ------------- | --------------- | ---- | -------------------- |
| 1    | Linksys E5600 | CVE-2025-22997  | XSS  | pf_table_layout      |
| 2    | Linksys E5600 | CVE-2025-22996  | XSS  | spf_table_layout     |
| 3    | Linksys E5600 | CNVD-2024-29916 | CI   | runtime.emailReg     |
| 4    | Linksys E5600 | CNVD-2024-29915 | CI   | runtime.pingTest     |
| 5    | Linksys E5600 | CNVD-2025-05521 | CI   | /API/info/traceRoute |

# D-LINK

| 序号 | Firmware    | Number          | Type | Details  |
| ---- | ----------- | --------------- | ---- | -------- |
| 1    | D-Link 890L | CNVD-2024-32489 | CI   | soap.cgi |

# TENDA

| 序号 | Firmware   | Number                                                       | Type | Details               |
| ---- | ---------- | ------------------------------------------------------------ | ---- | --------------------- |
| 1    | Tenda HG10 | [CVE-2026-1689](https://www.cve.org/CVERecord?id=CVE-2026-1689) | CI   | formLogin             |
| 2    | Tenda HG10 | [CVE-2026-1690](https://www.cve.org/CVERecord?id=CVE-2026-1690) | CI   | formSysCmd            |
| 3    | Tenda AC10 | CNVD-2025-05844                                              | BOF  | fromAdvSetMacMtuWan   |
| 4    | Tenda AC10 | CNVD-2025-05843                                              | BOF  | fromSetRouteStatic    |
| 5    | Tenda HG10 | [CVE-2026-1687](https://www.cve.org/CVERecord?id=CVE-2026-1687) | CI   | formSamba             |
| 6    | Tenda HG10 | CVE-2026-86167                                               | CI   | formgponConf          |
| 7    | Tenda HG10 | CVE-2026-86166                                               | BOF  | formWanRedirect       |
| 8    | Tenda HG10 | CVE-2026-86165                                               | BOF  | formURL               |
| 9    | Tenda HG10 | CVE-2026-85110                                               | CI   | formWlanSetup         |
| 10   | Tenda HG10 | CVE-2026-85109                                               | BOF  | formLogin             |
| 11   | Tenda HG10 | CVE-2026-82542                                               | CI   | formIPv6Routing       |
| 12   | Tenda AC8  | CVE-2026-2203                                                | CI   | fast_setting_wifi_set |
| 13   | Tenda AC8  | CVE-2026-2202                                                | BOF  | WifiGuestSet          |

# TOTOLINK

| 序号 | Firmware         | Number                    | Type | Details                |
| ---- | ---------------- | ------------------------- | ---- | ---------------------- |
| 6    | ToToLink EX1800T | CNVD-2024-23613           | CI   | setRptWizardCfg        |
| 7    | ToToLink EX1800T | CNVD-2024-23614           | CI   | setWiFiApConfig        |
| 8    | ToToLink A3100R  | CNVD-2025-04627           | CI   | GetDomainName          |
| 9    | ToToLink A950RG  | CNVD-2025-04892           | BOF  | setWiFiWpsConfig       |
| 10   | ToTolink A3002r  | CNVD-2025-04789           | BOF  | formWlanMultipleAP     |
| 11   | ToTolink A3002r  | CNVD-2024-25959           | BOF  | formPortFw             |
| 12   | ToTolink A3002r  | CNVD-2024-26661           | BOF  | formIpQoS              |
| 13   | ToTolink A3002r  | CNVD-2025-05346           | BOF  | formIpv6Setup          |
| 14   | ToTolink A3002r  | CNVD-2024-27627           | BOF  | formIpv6Setup          |
| 15   | ToTolink A3002r  | CNVD-2024-26660           | BOF  | formIpv6Setup          |
| 16   | ToTolink A3002r  | CNVD-2025-06418           | BOF  | formIpv6Setup          |
| 17   | ToTolink A3002r  | CNVD-2024-26659           | BOF  | formIpv6Setup          |
| 18   | ToTolink A3002r  | CNVD-2025-04790           | BOF  | formRebootCheck        |
| 19   | ToTolink A3002r  | CNVD-2025-04839           | BOF  | formDhcpv6s            |
| 20   | ToTolink A3002r  | CNVD-2025-04841           | BOF  | formIpv6Setup          |
| 21   | ToTolink A3002r  | CNVD-2024-23037           | BOF  | formFilter             |
| 22   | ToTolink A3002r  | CNVD-2024-26728           | CI   | formWsc                |
| 23   | ToTolink A3002r  | CNVD-2024-26728           | CI   | formWlSiteSurvey       |
| 24   | ToToLink A3700R  | CNVD-2024-24878           | CI   | setOpModeCfg           |
| 25   | ToToLink A3700R  | CNVD-2024-24879           | CI   | setWanCfg              |
| 26   | ToToLink A3700R  | CNVD-2024-24880           | BOF  | setWiFiBasicCfg        |
| 27   | ToToLink A3700R  | CNVD-2024-24881           | BOF  | loginAuth              |
| 28   | ToToLink A700R   | CNVD-2025-06146           | BOF  | formWep                |
| 29   | ToToLink A700R   | CNVD-2025-06147           | BOF  | formTcpipSetup         |
| 30   | ToToLink A700R   | CNVD-2025-06148           | BOF  | formWlAc               |
| 31   | ToToLink A700R   | CNVD-2025-06149           | BOF  | formWlAc               |
| 32   | ToToLink A700R   | CNVD-2025-06150           | BOF  | formWsc                |
| 33   | ToToLink A700R   | CNVD-2025-06151           | BOF  | formWdsEncrypt         |
| 34   | ToToLink A700R   | CNVD-2025-06152           | BOF  | formWlWds              |
| 35   | ToToLink A700R   | CNVD-2025-06153           | BOF  | formWlSiteSurvey       |
| 36   | ToToLink A700R   | CNVD-2025-06154           | BOF  | formNewSchedule        |
| 37   | TOTOlink A3002MU | CNVD-2026-19083(zhangxin) | BOF  | formWdsEncrypt         |
| 38   | totolink A3002MU | CVE-2026-90604            | XSS  |                        |
| 39   | Totolink A3002MU | CVE-2026-93742            | CI   | formWSC                |
| 40   | Totolink A3002MU | CVE-2026-93740            | CI   | formWlEncrypt          |
| 41   | Totolink A3002MU | CVE-2026-93739            | BOF  | formWlAc               |
| 42   | Totolink A3002MU | CVE-2026-93738            | BOF  | formSchedule           |
| 43   | Totolink A3002MU | CVE-2026-90608            | BOF  | formPortFw             |
| 44   | Totolink A3002MU | CVE-2026-90607            | BOF  | formNewSchedule        |
| 45   | Totolink A3002MU | CVE-2026-90606            | BOF  | formIpv6Setup          |
| 46   | Totolink A3002MU | CVE-2026-90605            | BOF  | formFilter             |
| 47   | Totolink A702r   | CNVD-2026-06047           | BOF  | formOneKeyAccessButton |
| 48   | Totolink A702r   | CNVD-2026-12207           | BOF  | formOneKeyAccess       |
| 49   | Totolink A702r   | CNVD-2026-12184           | BOF  | formParentControl      |
| 50   | Totolink A702r   | CNVD-2026-11545           | BOF  | formIpv6Setup          |
| 51   | Totolink A720r   | CNVD-2026-06064           | BOF  | setWizardCfg           |
| 52   | Totolink A950RG  | CNVD-2026-04565           | BOF  | setRadvdCfg            |
| 53   | Totolink A950RG  | CNVD-2025-14466           | BOF  | setUrlfliterrules      |
| 54   | Totolink A950RG  | CNVD-2025-10122           | CI   | setWebWlanIdx          |
| 55   | Totolink A950RG  | CNVD-2025-11782           | CI   | setLanfuageCfg         |
| 56   | Totolink A3002R  | CNVD-2025-04789           | BOF  | formWlanMultipleAP     |
| 57   | Totolink A3600R  | CNVD-2026-14335           | BOF  | set_DhcpSParam         |
| 58   | Totolink A950RG  | CNVD-2025-07480           | BOF  | formDhcpv6s            |

