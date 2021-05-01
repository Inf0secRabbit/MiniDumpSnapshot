# MiniDumpSnapshot

Usage: MiniDumpSnapShot.exe

Upon Successfull execution you can find the lsass.dmp file in C:\Windows\tasks

This program uses PSSCaptureSnapShot API to take the snapshot of the lsass process.

MiniDumpWriteDump will further use the handle returned by PSSCaptureSnapShot instead of LSASS process.

The was inspired by awesome work done by 
