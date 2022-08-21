# Potentially malicious Activites on Webservers

## Detects IIS Module Registration

 - Detects native IIS Module Installation and Uninstall for Backdooring
 - The "list" Parameter of the appcmd.exe was intentionally excluded but can be integrated to even find instances of reconaissance
 - Source: https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/

```STARQuery
EventType = "Process Creation" AND TgtProcName Contains Anycase "appcmd.exe" AND TgtProcCmdLine Contains Anycase "install"
```