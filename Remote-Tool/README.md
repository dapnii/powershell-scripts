**Remote Tool**

Command line tool that utilizes PowerShell remoting to run remotely variety of commands on end user's machine with the use of domain admin account (you can also use LAPS if you add remote device you're trying to connect to trusted hosts on your machine,
here is how you can do that https://stackoverflow.com/questions/21548566/how-to-add-more-than-one-machine-to-the-trusted-hosts-list-using-winrm) 

You can do below things from remote device:

1) Check network configuration (ipconfig)
2) Ping Google DNS
3) Download a test file to null path and calculate the time it took to complete
4) Check local admin accounts
5) Run group policy update for all users and machine (done by creating and running scheduled task)
6) Check the list of installed software
7) Restart Intune service
8) Clear system cache files (from %temp%, temp, prefetch)
9) Clear Firefox cache (both esr and release)
10) Clear Google Chrome cache
11) Clear Teams cache
12) Enable One Drive in registry
13) Enable high performance power plan (also restores it if not available)
14) Adjust visual system settings for the best performance


In order to run the script you'd need to download the Remote Tool.exe file (it's just converted to .exe Remote Tool.ps1 file using ps2exe module) and run it.
If you encounter any problems that it does not run, make sure that you don't have execution policy set to Restricted.

Once script is ran you must enter 
1) username of admin account you wish to use to connect to remote device
2) password
3) hostname of this machine

![image](https://github.com/dapnii/Remote-Tool/assets/116521500/64156c90-9e43-464d-a9c7-9df785895ffc)
