mkdir C:\temp\dokanempty

rmdir /s /q m:\temp
robocopy c:\ReplicaNet\ReplicaNetPublic\Includes m:\temp\ /s

"C:\Program Files\Git\usr\bin\diff.exe" -r -q c:\ReplicaNet\ReplicaNetPublic\Includes m:\temp\

echo Rename the files
rename m:\temp\RNLobby RNLobby2
rename m:\temp\RNLog RNLog2
rename m:\temp\RNLobby2\Inc\_SrvCommon.cpp _SrvCommonNew.cpp
rename m:\temp\RNLog2\Inc\Log.h LogNew.h

echo Then restore the files
rename m:\temp\RNLobby2\Inc\_SrvCommonNew.cpp _SrvCommon.cpp
rename m:\temp\RNLog2\Inc\LogNew.h Log.h

rename m:\temp\RNLobby2 RNLobby
rename m:\temp\RNLog2 RNLog

echo Then check the data again
"C:\Program Files\Git\usr\bin\diff.exe" -r -q c:\ReplicaNet\ReplicaNetPublic\Includes m:\temp\
