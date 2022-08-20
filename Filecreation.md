# Potentially malicious Filecreations

## Detects ISO and LNK File Creations Operations in AppData\Local\Temp or Downloads Folder

 - Detects ISO and LNK Filecreation in AppData\Local\Temp and Downloads, Paths shall not include "Recent" and "Downloads.lnk" because of too many "false positives"
 - Source: https://twitter.com/rfackroyd/status/1559920328087932937?s=20&t=0Df72RRfw-Zqo2WKztoG7g

' query: TgtFileExtension In AnyCase ("iso","lnk") AND (TgtFilePath In Contains ("\AppData\Local\Temp","\Downloads") AND (TgtFilePath Does Not Contain "Downloads.lnk" AND TgtFilePath Does Not Contain "Recent"))
