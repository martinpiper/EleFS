EleFS
=====

A long time ago, for a computer far far away, there was a blob file based file system called EleFS for the Acorn Archimedes.

This uses Dokan 1.3.1.1000 https://github.com/dokan-dev/dokany/releases/tag/v1.3.1.1000

Install: DokanSetup_redist.exe
	https://github.com/dokan-dev/dokany/releases/download/v1.3.1.1000/DokanSetup_redist.exe
	Note the default (click "Options") will install the Dokan development files at: C:\Program Files\Dokan\Dokan Library-1.3.1
		This path is added to the project for includes, it will need to be updated if it is different for your installation



Example command lines:

* /p cryptoPassword /f C:\temp\container.EleFs /l M:\ /s /d /m
* /f C:\temp\container.EleFs /l M:\ /s /d /m
* /f C:\temp\container.EleFs /l M:\ /s /m
