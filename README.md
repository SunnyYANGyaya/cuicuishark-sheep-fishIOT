# IOT-vulnerability-report
fish、sheep：

| 序号 | Firmware         | Number          | Type | Details             |
| ---- | ---------------- | --------------- | ---- | ------------------- |
| 1    | Linksys E5600    | CVE-2025-22997  | XSS  | pf_table_layout     |
| 2    | Linksys E5600    | CVE-2025-22996  | XSS  | spf_table_layout    |
| 3    | Linksys E5600    | CNVD-2024-29916 | CI   | runtime.emailReg    |
| 4    | Linksys E5600    | CNVD-2024-29915 | CI   | runtime.pingTest    |
| 5    | D-Link 890L      | CNVD-2024-32489 | CI   | soap.cgi            |
| 6    | ToToLink EX1800T | CNVD-2024-23613 | CI   | setRptWizardCfg     |
| 7    | ToToLink EX1800T | CNVD-2024-23614 | CI   | setWiFiApConfig     |
| 8    | ToToLink A3100R  | CNVD-2025-04627 | CI   | GetDomainName       |
| 9    | ToToLink A950RG  | CNVD-2025-04892 | BOF  | setWiFiWpsConfig    |
| 10   | ToTolink A3002r  | CNVD-2025-04789 | BOF  | formWlanMultipleAP  |
| 11   | ToTolink A3002r  | CNVD-2024-25959 | BOF  | formPortFw          |
| 12   | ToTolink A3002r  | CNVD-2024-26661 | BOF  | formIpQoS           |
| 13   | ToTolink A3002r  | CNVD-2025-05346 | BOF  | formIpv6Setup       |
| 14   | ToTolink A3002r  | CNVD-2024-27627 | BOF  | formIpv6Setup       |
| 15   | ToTolink A3002r  | CNVD-2024-26660 | BOF  | formIpv6Setup       |
| 16   | ToTolink A3002r  | CNVD-2025-06418 | BOF  | formIpv6Setup       |
| 17   | ToTolink A3002r  | CNVD-2024-26659 | BOF  | formIpv6Setup       |
| 18   | ToTolink A3002r  | CNVD-2025-04790 | BOF  | formRebootCheck     |
| 19   | ToTolink A3002r  | CNVD-2025-04839 | BOF  | formDhcpv6s         |
| 20   | ToTolink A3002r  | CNVD-2025-04841 | BOF  | formIpv6Setup       |
| 21   | ToTolink A3002r  | CNVD-2024-23037 | BOF  | formFilter          |
| 22   | ToTolink A3002r  | CNVD-2024-26728 | CI   | formWsc             |
| 23   | ToTolink A3002r  | CNVD-2024-26728 | CI   | formWlSiteSurvey    |
| 24   | ToToLink A3700R  | CNVD-2024-24878 | CI   | setOpModeCfg        |
| 25   | ToToLink A3700R  | CNVD-2024-24879 | CI   | setWanCfg           |
| 26   | ToToLink A3700R  | CNVD-2024-24880 | BOF  | setWiFiBasicCfg     |
| 27   | ToToLink A3700R  | CNVD-2024-24881 | BOF  | loginAuth           |
| 28   | ToToLink A700R   | CNVD-2025-06146 | BOF  | formWep             |
| 29   | ToToLink A700R   | CNVD-2025-06147 | BOF  | formTcpipSetup      |
| 30   | ToToLink A700R   | CNVD-2025-06148 | BOF  | formWlAc            |
| 31   | ToToLink A700R   | CNVD-2025-06149 | BOF  | formWlAc            |
| 32   | ToToLink A700R   | CNVD-2025-06150 | BOF  | formWsc             |
| 33   | ToToLink A700R   | CNVD-2025-06151 | BOF  | formWdsEncrypt      |
| 34   | ToToLink A700R   | CNVD-2025-06152 | BOF  | formWlWds           |
| 35   | ToToLink A700R   | CNVD-2025-06153 | BOF  | formWlSiteSurvey    |
| 36   | ToToLink A700R   | CNVD-2025-06154 | BOF  | formNewSchedule     |
| 37   | Tenda AC10       | CNVD-2025-05843 | BOF  | fromSetRouteStatic  |
| 38   | Tenda AC10       | CNVD-2025-05844 | BOF  | fromAdvSetMacMtuWan |