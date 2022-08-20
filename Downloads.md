# Potentially malicious Downloads

## Detects downloads via MPCMDRun.exe or VMwareXferlogs.exe initiated by Powershell
' query: EndpointOS = "windows" AND EventType = "Process Creation" AND TgtProcName Contains Anycase "powershell.exe" AND (TgtProcCmdLine Contains Anycase "MpCmdRun.exe" OR TgtProcCmdLine Contains Anycase "mpclient.dll" OR TgtProcCmdLine Contains Anycase "VMwareXferlogs.exe") AND TgtProcCmdLine Contains Anycase "Invoke-WebRequest"