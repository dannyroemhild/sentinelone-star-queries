# Potentially malicious Process Executions

## Detects Follina CVE-2022-30190

 - This Query comes from the original Sentinelone Blog post
 - Source: https://www.sentinelone.com/blog/staying-ahead-of-cve-2022-30190-follina/

```STARQuery
EndpointOS = "windows" AND EventType = "Process Creation" AND TgtProcName Contains Anycase "msdt.exe" AND TgtProcCmdLine Contains Anycase "PCWDiagnostic" AND ( TgtProcCmdLine Contains Anycase "IT_BrowseForFile" OR TgtProcCmdLine Contains Anycase "IT_RebrowseForFile" )
```

## Detects Dogwalk CVE-2022-34713

 - This Query monitors the Execution and Command Line of the msdt.exe if it contains cab oder diagcab
 - Source: https://www.securonix.com/blog/detecting-microsoft-msdt-dogwalk/

```STARQuery
EndpointOS = "windows" AND EventType = "Process Creation" AND TgtProcName Contains Anycase "msdt.exe" AND ( TgtProcCmdLine Contains Anycase "cab" OR TgtProcCmdLine Contains Anycase "diagcab" )
```