mkdir C:\temp\dokanempty

rmdir /s /q m:\temp
rem robocopy c:\ReplicaNet\ReplicaNetPublic\Includes m:\temp\ /s
robocopy c:\ReplicaNet\ReplicaNetPublic\Includes\RNLobby m:\temp\ /s

rem "C:\Program Files\Git\usr\bin\diff.exe" -r -q c:\ReplicaNet\ReplicaNetPublic\Includes m:\temp\
"C:\Program Files\Git\usr\bin\diff.exe" -r -q c:\ReplicaNet\ReplicaNetPublic\Includes\RNLobby m:\temp\
