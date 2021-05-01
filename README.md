# MiniDumpSnapshot


Usage:``` MiniDumpSnapShot.exe```

Upon successfull execution you can find the lsass.dmp file in C:\Windows\tasks

This program uses PSSCaptureSnapShot API to take the snapshot of the lsass process.

MiniDumpWriteDump will further use the handle returned by PSSCaptureSnapShot instead of LSASS process.

## Credits
This was inspired by awesome work done in SharpSploit by @cobbr - https://github.com/cobbr/SharpSploit

There is also an BOF created for the same by @pwn1sher - https://github.com/pwn1sher/CS-BOFs



