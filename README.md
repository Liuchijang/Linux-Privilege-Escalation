# Linux-Privilege-Escalation
This document contains a list of privilege escalation techniques in Linux and how to harden the system to prevent them.

[Technicques](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) 

## Arbitrary File Write to Root

## Cisco - vmanage

## Containerd (ctr) Privilege Escalation

## D-Bus Enumeration & Command Injection Privilege Escalation

## Docker Security


## Escaping from Jails


## euid, ruid, suid

SUID or GUID, when set, allows the process to execute under the specified user or group.
List all binary with suid/guid:
```cmd
find / -perm -4000 -exec ls -ld {} \; 2>/dev/null
find / -perm -u=s -exec ls -ld {} \; 2>/dev/null
find / -perm -2000 -exec ls -ld {} \; 2>/dev/null
find / -perm -g=s -exec ls -ld {} \; 2>/dev/null
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

## Interesting Groups - Linux Privesc


## Logstash


## ld.so privesc exploit example


## Linux Active Directory


## Linux Capabilities


## NFS no_root_squash/no_all_squash misconfiguration PE


## Node inspector/CEF debug abuse


## Payloads to execute


## RunC Privilege Escalation


## SELinux


## Socket Command Injection


## Splunk LPE and Persistence


## SSH Forward Agent exploitation

## Wildcards Spare tricks

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
