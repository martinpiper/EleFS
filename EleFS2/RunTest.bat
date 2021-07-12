mkdir C:\temp\dokanempty

rmdir /s /q m:\temp
robocopy c:\ReplicaNet\ReplicaNetPublic\Includes m:\temp\ /s

"C:\Program Files\Git\usr\bin\diff.exe" -r -q c:\ReplicaNet\ReplicaNetPublic\Includes m:\temp\
