# Open-Windows-Exec-Check
Takes known Windows credentials to determine which services on which hosts can be used for RCE. 
Current Checks: 
* RDP
* SMBExec
* PSExec
* Task Schedule (atexec)
* DCOMexe
* WMIexec


Check which Windows have been opened in your neighbourhood (network).


## Description

Are you a lazy pentester who doesn't have to be quiet and won't get blocked/stopped? Have some creds, and want to identify all the Windows systems your creds grant you access to? This is the tool for you.  Uses modified versions of impackets RDP_Check, SMBExec, PSExec, ATExec, DCOMExec, WMIExec to perform RCE checks.

Is capable perform all checks, or subset of checks against multiple hosts with multiple credential pairs. Also supports LM:NT pass-the-hash where credentials are unknown. Outputs a PrettyTable that is easy to read that is sorted by host and username.

There are *no* lockout avoidances, ensure the credentials you provide are accurate or you may end up locking out alot of users.

The timeouts have been modified in each Impacket module (where possible) to be 25 seconds. There may still be some issues that are not handled properly and cause the tool to hang. If you encounter an issue such as the script exiting before finishing or hanging please the error message(s) and potential reasons why the error occured would be great (try and take a pcap of the crash/hanging).

## Requirements
* Impacket
* PrettyTable


## Examples

Single host, single credential, all checks

`python3 openwinexec.py -t 172.66.10.5 -u username -p P@ssw0rd`


Multiple host, multiple creds, all checks

`python3 openwinexec.py -T ips.txt -C credpairs.txt`

Single host, multiple creds, only rdp, smb and psexec checks.

`python3 openwinexec.py -t 172.66.10.5 -C credpairs.txt -rdp -smb -ps`

Single host, hash example.

`python3 openwinexec.py -t 172.66.10.5 -u username -hash LMHASH:NTHASH`

Single host, multiple hash pairs

`python3 openwinexec.py -t 172.66.10.5 -u username -hashes hashpairs.txt`


Example credential pair file:

```
username1:P@ssw0rd
username2:Passw0rd1!
username3:Welcome1
```

Example hash credential pair file:

```
username1:LMHASH:NTHASH
username2:LMHASH:NTHASH
username3:LMHASH:NTHASH
```

Example host file:

```
172.66.10.10
172.66.10.5
172.66.10.3
```



## TO DO

* Changed timeout for all modules (except for ATExec) to 25 seconds. If there is enough interest I may explore adding timeout as an argument
* RDP "SSL routines, wrong ssl version" - This happens on older systems and might wrongly indicate RDP is not usable on a host. If this error occurs try RDP on some of the hosts.

To Do:
* Planned
** Fix RDP wrong SSL Version
** Error logging and color? - Only real test left.
** Kerberos not testing (need make change to test lab)
* Potential Feature enhancements:
** Different spray methods? E.G stealth mode that randomizes the IP and does it slowly.
** Add more arguments? Might be: RemComSVC alernative executable file, SMBexec server mode, SMB port 139 or 445
** Debugging/verbosity options?


