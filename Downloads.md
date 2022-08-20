# Potentially malicious Downloads

## Detects downloads via MPCMDRun.exe or VMwareXferlogs.exe initiated by Powershell

 - Detects Downloads via MPCMDRun oder VMxferlog initiated by Powershell - used by BlackBasta Ransomware
 - Source: https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/
 - Source: https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/

`query: EndpointOS = "windows" AND EventType = "Process Creation" AND TgtProcName Contains Anycase "powershell.exe" AND (TgtProcCmdLine Contains Anycase "MpCmdRun.exe" OR TgtProcCmdLine Contains Anycase "mpclient.dll" OR TgtProcCmdLine Contains Anycase "VMwareXferlogs.exe") AND TgtProcCmdLine Contains Anycase "Invoke-WebRequest"