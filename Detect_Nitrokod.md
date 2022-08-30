# Nitrokod IOCs

## Detects DNS Requests and File Creation containing the String "Nitrokod"

 - Source: https://www.bleepingcomputer.com/news/security/windows-malware-delays-coinminer-install-by-a-month-to-evade-detection/
 - Source: https://research.checkpoint.com/2022/check-point-research-detects-crypto-miner-malware-disguised-as-google-translate-desktop-and-other-legitimate-applications/

```STARQuery
DnsRequest In Contains Anycase ("nitrokod.com","intelserviceupdate.com","nvidiacenter.com") OR TgtFilePath Contains Anycase "nitrokod"
```
