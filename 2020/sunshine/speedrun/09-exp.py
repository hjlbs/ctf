from pwn import *

p = remote('chal.2020.sunshinectf.org', 30009)
#p = process('./chall_09')

e = ELF('./chall_09')

key = b'\x79\x17\x46\x55\x10\x53\x5f\x5d\x55\x10\x58\x55\x42\x55\x10\x44\x5f\x3a'

nk = ''

for x in key:
    nk += chr(x ^ 0x30)

p.send(nk + '\n')

input('...')

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30009: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_09'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
...
[*] Switching to interactive mode
$ ls
chall_09
flag.txt
$ cat flag.txt
sun{coming-home-4202dcd54b230a00}
'''
