__Linux Server Hardener__ is a bash script that automates few of the tasks that you need to perform on a new Linux server to give it basic amount security.

I wanted to change my VPS(Virtual Private Server) provider and was testing out many providers and many Linux flavours on those VPS. But before doing anything those servers needed to be given basic amount security and this involved a set of repetitive commands on terminal. Depending on network speed and number of mis-types, these took between 30-90 minutes to perform. 

This script is meant to save that time.

# Getting Started

## Prerequisites

* One of the following Linux flavours
  - Debian 8.x
  - Debian 9.x
  - Ubuntu 14.x
  - Ubuntu 16.x
  - Ubuntu 18.x
* *curl* or *wget* should be installed
* *__root__* access to the server

## Usage

The script is intended to be executed immediately after you have access to a **new** Linux server (most likely a VPS) as *__root__*.

```bash
# bash https://raw.githubusercontent.com/pratiktri/init-li-harden/master/init-linux-harden.sh --help

# bash https://raw.githubusercontent.com/pratiktri/init-li-harden/master/init-linux-harden.sh --username someusername --resetrootpwd --defaultsourcelist

# bash https://raw.githubusercontent.com/pratiktri/init-li-harden/master/init-linux-harden.sh --quiet
```

# What does it do exactly?
Script performed the following operations:-

1. Create non-root user and give it "sudo" privilege.
2. Generate passphrage protected *ed25519* SSH Keys (Private & Public).
3. Secure "authorized_keys" file.
4. [Optionally] Resets the url from which apt gets software from. Resets them to the flavour provided urls.
5. Updates + Upgrades + Installs required softwares (sudo curl screen ufw fail2ban)
6. Configures UFW
7. Configures Fail2Ban
8. Alters SSH options(/etc/ssh/sshd_config) to do the following:-
   * Disable SSH login for **__root__** (PermitRootLogin no)
   * Disable SSH login through password for all users (PasswordAuthentication no) 
   * Updates path for *authoried_keys* file
9. *[Optionally] Resets root password*
10. On successfully completing above operations, display the following on screen:-
    * Username
    * User Password
    * SSH Private Key's path on the server
    * SSH Public Key's path on the server
    * SSH Private Key's passphrase
    * (If so opted) New root password
    * SSH Private Key
    * SSH Public Key

## Details of each operation
### 1. Create non-root user and give it "sudo" privilege
You can specify your own username with "--username" flag.

When accepting username through "--username", __*script actively rejects special characters in the name*__ because bash does not act well with special characters. The values accepted by the script [a-zA-Z0-9_-] i.e., alphanumeric and following 2 special characters _ and -

If "--username" is not provided, __*script will randomly generate an username for you*__. Script generated usernames are 9 character long and are alphanumeric (i.e., numbers & English characters).

Password for the user is always randomly generated. Passwords are 15 character long and are alphanumeric as well.

### 2. Generate passphrage protected *ed25519* SSH Keys (Private & Public)
Since password authentications are bad security practice, script will generate a SSH Key and use that for user authentication.

All SSH keys are not made the same and we use OpenSSH keyformat and ed25519 algorithm to generate ours. You can read the reason for that [here](https://security.stackexchange.com/questions/143442/what-are-ssh-keygen-best-practices#answer-144044) and [here](https://stribika.github.io/2015/01/04/secure-secure-shell.html). For additional security SSH Private keys are secured by a passphrase. This passphrase is randomly generated. Passphrase are 15 character long and are alphanumeric. Algorithm used for user's password and SSH Private Key's passphrase are the same.

Generated keys are placed in ".ssh" sub-directory of the user's (created in step 1 above) home-directory, i.e., /home/*__username__*/.ssh/

SSH Public Key is then *appended* to /home/*__username__*/.ssh/authorized_keys file.

### 3. Secure "authorized_keys" file
"authorized_keys" file present in user's .ssh sub-directory contains the Public Key values. These Public Key values are used to authenticate user logins. Since, this is an important file we need to secure it tight. 

Following are the file access restrictions that the script applies:-
* Make *root* user the owner of /home/*__username__*/.ssh/ directory and all files inside it.
* Give *root* group access to /home/*__username__*/.ssh/ directory and all files inside it.
* Make the /home/*__username__*/.ssh/ directory and all files inside it visible only to the *root* user.
* Remove the editing rights on /home/*__username__*/.ssh/authorized_keys file from every user - including *root*.
* Make the /home/*__username__*/.ssh/authorized_keys file immutable.

### 4. [Optionally] Resets the url from which apt gets software from. Resets them to the flavour provided urls

Most VPS provider change the location from which operating system downloads software from (i.e. *apt* repository); usually to CDNs that are maintained by them. While, this greatly reduces the time it takes to install a new application, it does come with its security implications (what if they insert tracker in application?). 

However, one can also argue that if the OS (i.e. Linux) itself is installed by the providers, then OS itself is a more likely place where they might want to insert something dirty.

Depending on which argument you find valid, __you can use this option in the script to ensure the default OS provided CDNs are used__. This is done by updating the [/etc/apt/sources.list](https://linoxide.com/debian/configure-sources-list-debian-9/) file.

If the script is started with --defaultsourcelist option, then for Debian http://deb.debian.org/debian is used and for Ubuntu http://archive.ubuntu.com/ubuntu/ is used.

This is disabled by default.

### 5. Updates + Upgrades + Installs required softwares (sudo  screen ufw fail2ban)
Pretty self explanatory. 
### 6. Configures UFW
[UFW(**U**ncomplicated **F**ire**W**all)](https://www.digitalocean.com/community/tutorials/how-to-setup-a-firewall-with-ufw-on-an-ubuntu-and-debian-cloud-server) makes it easy to manage what kind of internet traffic enters or leaves the server. Without this program you would have to deal with Linux's iptables (which I can not understand at all).

This script sets up UFW so that only __ssh__(required for user login), __http__(required for any web application) & __https__(also required for any web application) __traffic are allowed in and out__ of the server. All other traffic are blocked.
### 7. Configures Fail2Ban
While UFW restrict access to ports, the ports that are required (and are allowed by UFW in above step) for our purpose can be exploited by nefarious actors.

Fail2ban watches traffic coming through the allowed ports to determine if it is indeed a legitimate one. This determination is usually done by analyzing various *log files* being generated by Linux and other applications running on the server. If anything suspicious is found then after a certain number of illegitimate attempts the intruder(IP) is banned. Ban is then lifted after a desired amount of time.

This script sets up Fail2ban as following:-
* default ban time is 5 hours, 
* Whitelists your server's IP from detection (uses https://ipinfo.io/ip to determine the IP),
* sets (backend = polling). *polling* is an algoritm used to check if the *log files* are updated. This algorithm does not required any additional software and if no additional software are installed then is faster option to choose.
* Explicitly enables protection for *ssh* with (maxretry = 3) & (bantime = 2592000)
  
### 8. Alters SSH options
This step contines from step 3 to harden our ssh login. Here, we do edit */etc/ssh/sshd_config* file to achieve the following:-
* Disable root login (**PermitRootLogin no**). No one needs to work on root. The new user created already has *root* privileges anyways.
* Disable password login (**PasswordAuthentication no**). This ensures we can ONLY login though SSH Keys.
* Specify where to find authorized public keys which are granted login (\\.ssh\authorized_keys %h\\.ssh\authorized_keys)
### 9. [Optionally] Resets root password
Since, VPS providers sends you the password of your VPS's root user in email in plain text. So, password needs to be changed immediately. Note that **since we have disabled *root* login AND password login in the above step, changing *root* password might be an overkill**. But, still...

Also most VPS providers these days, allow you to provide SSH Public Key in their website. If you have done that you can skip this step. **It is disabled by default anyways**.

To change your root password provide option --resetrootpw. *root* password then be randomly generated. Passwords are 15 character long and are alphanumeric.

### 10. On successfully completing above operations
All the generated username, passwords, SSH Key location & SSH Keys themselves are displayed on the screen.

This might not be desired, on future version you might find option to NOT show the details and find them from the log file.

The logfile is located in /tmp/ directory - thus will be removed server reboots. All the details shown on the screen and a lot more can be found in the log. Exact logfile location will be shown on the screen as well.