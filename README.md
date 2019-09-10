# Linux Server Hardener

Bash script that automates server security hardening on a new Linux server.

I wanted to change my VPS(Virtual Private Server) provider and was testing out many providers and many Linux flavours on those VPSes. But before doing anything those servers needed to be given basic amount security and this involved a set of repetitive commands on terminal. Depending on network speed and number of mis-types, these took between 30-90 minutes to perform.
This script is meant to save that time.

This script is intended to be executed _**immediately**_ after you have access to a _**new**_ Linux server (most likely a VPS) as _**root**_.

## Status

Stable. Production ready.

## ***WARNING***

This script can potentially make your server inaccessible.

**If your network connection gets reset during this operation; you won't be able to log back in to the server**.

### Trust on VPS

This script generates username, password (for the user AND _root_), SSH Key, SSH Key Passphrase **on the server**. Infact, we store both the SSH Keys (Public & Private) on the server after the operation completes. Your VPS _can_ see all of these.

So, if you think your server/VPS provider might snoop on you - all these security won't really matter. The security this script provides is from actors other than your server(VPS) and you.

## Usage

### Prerequisites

-   One of the following Linux flavours
    -   Debian 8.x
    -   Debian 9.x
    -   Debian 10.x
    -   Ubuntu 16.x
    -   Ubuntu 18.x
-   _wget_ should be installed (comes preinstalled on the above OS)
-   _root_ access to the server

### Examples

```console
root@host:~# wget -q https://raw.githubusercontent.com/pratiktri/server_init_harden/master/init-linux-harden.sh -O init-linux-harden.sh && bash ./init-linux-harden.sh -d -q -hide

root@host:~# wget -q https://raw.githubusercontent.com/pratiktri/server_init_harden/master/init-linux-harden.sh -O init-linux-harden.sh && bash ./init-linux-harden.sh --defaultsourcelist --quiet --hide-credentials
```

> There are inherent risks involved with running scripts directly (without reviewing it first) from web - as done above. Everyone does it anyways, but you have been warned.

### Available Options

Run the script with below option (--help or -h) to see all available options:-

```console
root@host:~# init-linux-harden.sh --help

Usage: sudo bash $0 [-u|--username username] [-r|--resetrootpwd] [--defaultsourcelist]
  -u,     --username              Username for your server (If omitted script will choose an username for you)
  -r,     --resetrootpwd          Reset current root password
  -hide,  --hide-credentials      Credentials will hidden from screen and can ONLY be found in the logfile
                                  eg: tail -n 20 logfile
  -d,     --defaultsourcelist     Updates /etc/apt/sources.list to download software from debian.org
  -ou,    --only-user             Only creates the user and its SSH authorizations
                                  NOTE: -r, -d would be ignored

Example: bash ./linux_init_harden.sh --username myuseraccount --resetrootpwd

Below restrictions apply to usernames -
   - [a-zA-Z0-9] [-] [_] are allowed
   - NO special characters.
   - NO spaces.
```

### Script completed successfully - Now what?

-   Copy the following details from screen or logfile:-

    1. User password
    2. SSH Public Key
    3. SSH Private Key
    4. SSH Passphrase
    5. New _root_ password (if you chose to change it with `-r`)

-   From a terminal login using the following command:-

```console
    $ ssh -i [full-path-of-ssh-private-key-file] [username]@[server-ip]
    Enter passphrase for key '[full-path-of-ssh-private-key-file]':
```

At the above prompt type in the SSH Passphrase.

```console
    $ sudo apt-get upgrade
    [sudo] password for [username]:
```

Provide user-password at this prompt.

-   If the above 2 commands ran successfully - everything went great for us.
-   If not - check the log file for errors.

## What does the script do ?

Script performs the following operations:-

1. [Create non-root user and give it "sudo" privilege](.#1-create-non-root-user-and-give-it-sudo-privilege "Goto details of the step")
2. [Generate passphrage protected _ed25519_ SSH Key](.#2-generate-passphrage-protected-ed25519-ssh-keys "Goto details of the step")
3. [Secure "authorized_keys" file](.#3-secure-authorized_keys-file "Goto details of the step")
4. [[Optionally] Reset the url for apt repo from VPS provided CDN to OS provided ones](.#4-optionally-reset-the-url--for-apt-repo-from-vps-provided-cdn-to-os-provided-ones "Goto details of the step")
5. [Update + Upgrade + Install softwares (sudo curl screen ufw fail2ban)](.#5-updates--upgrades--installs-required-softwares-sudo--screen-ufw-fail2ban "Goto details of the step")
6. [Change DNS Server](.#6change-dns-server "Goto details of the step")
7. [Configure UFW](.#7-configure-ufw "Goto details of the step")
8. [Configure Fail2Ban](.#8-configure-fail2ban "Goto details of the step")
9. [Schedule cron for daily system update](.#9-schedule-cron-for-daily-system-update "Goto details of the step")
10. [[Optionally] Reset _root_ password](.#10-optionally-reset-root-password "Goto details of the step")
11. [Alter SSH options(/etc/ssh/sshd_config) to do the following:-](.#11-alter-ssh-options "Goto details of the step")

-   Disable SSH login for _root_
-   Disable SSH login through password for all users
-   Updates path for _authoried_keys_ file

```
PermitRootLogin no
PasswordAuthentication no
```

12. [On successfully completing above operations, display the following on screen:-](..#11-display-summary "Goto details of the step")
    -   Username
    -   User Password
    -   SSH Private Key's path on the server
    -   SSH Public Key's path on the server
    -   SSH Private Key's passphrase
    -   (If so opted) New _root_ password
    -   SSH Private Key
    -   SSH Public Key

Step 2 & Step 5 are most time consuming operations.

If you are stuck on Step 5 for more than 10 minutes, something went wrong in Step 4. Stop (ctrl + c) the script and check log file to see what went wrong.

Step 11 is the most dangerous operation.

## Error Handling

Since the script has the potential to make you loose access to your server, it takes a number of steps to recover from an error.

### Back up files

Script creates a back of every file that it changes.

Back up files are stored in the same directory as the original file.

Back up file name = (Original File Name) + "." + (Script start timestamp in '%d*%m*%Y-%H*%M*%S' format) + "\_bak"

So, if the original file name was _sshd_config_ and the script was started at 25th January 2019 09:15:25, then the backup files name would be _sshd_config.25_01_2019-09_15_25_bak_

### Recovery

Script _tries_ to recover from an error if it can determine that an error has occured. What it does to recover varies and it depends on which step the error has occured (read details of each step).

**Step 11 (Alter /etc/ssh/sshd_config) is where most danger resides. If this step fails AND script can not successfully recovery - then you'll most likely loose all access to your system**.

## Screenshots

### Operation successful and credentials displayed on screen

![Success With Credentials on Screen - the command](/screencaptures/success1.jpg?raw=true "Command")

![Success With Credentials on Screen - Prompt to procceed](/screencaptures/success2.jpg?raw=true "Prompt to Procceed")

![Success With Credentials on Screen - Execution in Process](/screencaptures/success3.jpg?raw=true "Execution in Process")

![Success With Credentials on Screen - Execution Succeeded 1](/screencaptures/success4.jpg?raw=true "Execution Succeeded 1")

![Success With Credentials on Screen - Execution Succeeded 2](/screencaptures/success5.jpg?raw=true "Execution Succeeded 2")

---

### Operation successful and credentials hidden from screen

![Success With Credentials Hidden - Execution Succeeded 3](/screencaptures/success6.jpg?raw=true "Execution Succeeded 3")

---

### Operation failed and reverted

![Failure and revert](/screencaptures/failure.jpg?raw=true "Failed and Reverted")

---

## Details of each operation

### 1. Create non-root user and give it "sudo" privilege

You can specify your own username with `--username` or `-u` flag.

If the username provided already exists, then the script will terminate without doing any operation.

When accepting username through `--username`, **_script actively rejects special characters in the name_** because bash does not act well with special characters. The values accepted by the script [a-zA-Z0-9_-] i.e., alphanumeric and [_] and [-]

If `--username` is not provided, **_script will randomly generate an username for you_**. Script generated usernames are 8 characters long and are alphanumeric (i.e., numbers & English characters). First 6 characters are random English lower-case alphabets and last 2 characters are random numbers.

Password for the user is **always** auto generated. Passwords are 20 character long, containing a mixture of special-symbols, English upper & lower case characters and numbers.

#### Error Handling

> **Failure Impact** - Minimal. An additional user on system.
>
> **Restoration** - Script tries to delete the user it created, along with user's home directory
>
> **Impact of Restoration Failure** - If the user will linger around in the system. You might have to manually delete the user and its home directory.
>
> **After Error** - Script will be terminated.

### 2. Generate passphrage protected _ed25519_ SSH Keys

Since password authentications are bad security practice, script will generate a SSH Key and use that for user authentication.

You need the following 3 to be able to access the server after the script is done:-

-   Public Key
-   Private Key
-   Passphrase for the Key

These 3 will be diplayed on screen at the end of the script (unless, you have opted to have it hidden with `-hide` option). Copy them and **keep them safe. Without these you won't be able to access the server.**

We use OpenSSH keyformat and ed25519 algorithm to generate ours. You can read the reason for that [here](https://security.stackexchange.com/a/144044) and [here](https://stribika.github.io/2015/01/04/secure-secure-shell.html). For additional security the key is secured by a passphrase. This passphrase is auto generated. Passphrase are 20 character long, containing a mixture of special-symbols, English upper & lower characters and numbers.

Generated keys are placed in ".ssh" sub-directory of the user's (created in step 1 above) home-directory, i.e., /home/_**[username]**_/.ssh/

SSH Public Key is then _appended_ to /home/_**[username]**_/.ssh/authorized_keys file.

#### Error Handling

> **Failure Impact** - Minimal. An additional user on system.
>
> **Restoration** - Script tries to delete the user along with user's home directory.
>
> **Impact of Restoration Failure** - If restoration of step 2 failed - most probably restoration on step 1 failed as well. At any case - just delete the user's home directory.
>
> **After Error** - Script will be terminated.

### 3. Secure "authorized_keys" file

"authorized_keys" file present in user's ".ssh" sub-directory contains the Public Key values. These Public Key values are used by Linux to authenticate user logins. Since, this is an important file we need to secure it tight.

Following are the file access restrictions that the script applies:-

-   Make _root_ user the _owner_ of /home/_**[username]**_/.ssh/ directory and all files inside it.
-   Give _root_ group access to /home/_**[username]**_/.ssh/ directory and all files inside it.
-   Make the /home/_**[username]**_/.ssh/ directory and all files inside it visible only to the _root_ user.
-   Remove the editing rights on /home/_**[username]**_/.ssh/authorized*keys file from every user - including \_root*.
-   Make the /home/_**[username]**_/.ssh/authorized_keys file immutable. i.e. - even _root_ user needs to do extra work to change it.

#### Error Handling

> **Failure Impact** - Minimal. An additional user on system.
>
> **Restoration** - Reset the attributes of "authorized_keys" file. Then deletes the user and its home directory.
>
> **Impact of Restoration Failure** - User and its home directory would persist. Delete them manually. Some of the files have their attributes modified to make them immutable (i.e. `chattr +i` ), so while deleting user's home directory manually, remember to remove this attribute (i.e. `chattr -i` ).
>
> **After Error** - Script will be terminated.

### 4. [Optionally] Reset the url for apt repo from VPS provided CDN to OS provided ones

Most VPS provider change the location from which operating system downloads software from (i.e. _apt_ repository); usually to CDNs that are maintained by them. While, this greatly improves time taken to install applications, it does come with its security implications (what if they insert tracker/sniffer in an application?).

However, one can also argue that if the OS (i.e. Linux) itself is installed by the providers, then OS is a more likely place where they might want to insert something dirty.

Depending on which argument you find valid, **you can use this option in the script to ensure the default OS-provided CDNs are used**. This is done by updating the [/etc/apt/sources.list](https://linoxide.com/debian/configure-sources-list-debian-9/) file.

If the script is started with `--defaultsourcelist` option, then for Debian http://deb.debian.org/debian is used and for Ubuntu http://archive.ubuntu.com/ubuntu/ is used.

This is disabled by default.

#### Error Handling

> **Failure Impact** - In the worst case, you will not be able to update or install applications through _apt_. In the best case, Service provider's CDN will continue to be used for _apt_ to install & update applications. In either case, script will continue to next step after restoration.
>
> **Restoration** - Before execution, a back up of _sources.list_ file was made. During restoration, this back up file is copied (over-written) to _sources.list_.
>
> **Impact of Restoration Failure** - You may not be able to install or update the system. Manually check if any \*\_bkp file exists in /etc/apt/ directory. If multiple file exist - use the most recent file and rename it to /etc/apt/sources.list
>
> **After Error** - Script continues to next step after restoration.
>

__Note__ - When script fails on this step - it won't attempt restoring earlier steps.

### 5. Updates + Upgrades + Installs required softwares (sudo screen ufw fail2ban)

Pretty self-explanatory.

#### Error Handling

> **Failure Impact** - Both UFW and Fail2ban CANNOT be configured. So, major part of server hardening will not be successful.
>
> **Restoration** - Nothing to restore. However, do check the log file to see that went wrong.
>
> **Impact of Restoration Failure** - None.
>
> **After Error** - Script continues to next step.

**Note** - When script fails on this step - it won't attempt restoring earlier steps. Also, as it is evident from above, script does NOT uninstall already installed programs even when error occors in this step or any other step. Because, you might have installed those programs before running the script or those programs might have been preloaded by the OS itself - too many variables to consider.

### 6. Change DNS Server

Instead of using server/VPS provided DNS servers, we use [OpenNIC]("https://servers.opennic.org/") provided ones. OpenNIC is a volunteer-operated DNS (Domain Name System) provider that aims to be an alternative to the standard DNS. This is more for privacy reasons than security. I personally trust volunteer run DNS providers (like OpenNIC) than those run by big organizations (like Google or Cloudflare). If you would rather use [Cloudflare's 1.1.1.1]("https://www.cloudflare.com/learning/dns/what-is-1.1.1.1/") DNS use `--CloudflareDNS` or `-cf` option to do so.

Following are the DNS IP we use:-

#### OpenNIC

The servers we use are anycast - so would be faster for everyone. Also we chose servers that do not keep logs. It is fast enough but [not as fast as Google DNS or Cloudflare 1.1.1.1]("https://www.networkworld.com/article/3194890/comparing-the-performance-of-popular-public-dns-providers.html").

##### IPv4

185.121.177.177</br>
169.239.202.202

##### IPv6

2a05:dfc7:5::53</br>
2a05:dfc7:5::53

#### Cloudflare

Reason I go for Cloudflare and NOT Google is due to the later's sketchy privacy history and they [crazy fast DNS resolution]("https://medium.com/@nykolas.z/dns-resolvers-performance-compared-cloudflare-x-google-x-quad9-x-opendns-149e803734e5#39a3") provided by Cloudflare.

#### Error Handling

> **Failure Impact** - Less secure server. You will keep using the VPS/server provided DNS servers.
>
> **Restoration** - Revert the /etc/resolv.conf file
>
> **Impact of Restoration Failure** - Server may not be able to connect to any host.
>
> **After Error** - Script continues to next step.

**Note** - When script fails on this step - it won't attempt restoring earlier steps.

### 7. Configure UFW

[UFW(**U**ncomplicated **F**ire**W**all)](https://www.digitalocean.com/community/tutorials/how-to-setup-a-firewall-with-ufw-on-an-ubuntu-and-debian-cloud-server) makes it easy to manage what kind of internet traffic enters or leaves the server. Without this program you would have to deal with Linux's iptables.

This script sets up UFW so that only **ssh**(required for user login), **http**(required for web applications) & **https**(also required for web applications) **traffic are allowed in and out** of the server. All other traffic are blocked.

#### Error Handling

> **Failure Impact** - Less secure server.
>
> **Restoration** - Disable UFW
>
> **Impact of Restoration Failure** - Most probably UFW was not installed properly. Check log file for details.
>
> **After Error** - Continue to next step after restoration.
>
> **Note** - When script fails on this step - it won't attempt restoring earlier steps.

### 8. Configure Fail2Ban

While UFW restricts access to ports, the ports that are required (and are allowed by UFW in above step) can/will be exploited by hackers.

Fail2ban watches traffic coming through the allowed ports to determine if it indeed is legitimate. This is usually done by analyzing various _log files_ being generated by Linux and other applications running on the server. If anything suspicious is found then after a certain number of illegitimate attempts the intruder(IP) is banned. Ban is then lifted after a desired amount of time.

This script sets up Fail2ban as following:-

-   default _ban time_ is 5 hours (2592000 seconds),
-   Whitelists your server's IP (uses https://ipinfo.io/ip to determine your server's IP),
-   Sets `backend = polling`. _polling_ is an algoritm used to notify fail2ban when the log files are updated. _polling_ algorithm does not require any additional software and is faster option to choose for our configuration.
-   Explicitly enables protection for _ssh_ with `maxretry = 3` & `bantime = 2592000`

#### Error Handling

> **Failure Impact** - Less secure server.
>
> **Restoration** - If back up of /etc/fail2ban/jail.local file found, then that is restored; else back up of /etc/fail2ban/jail.conf is restored. Also, back up of /etc/fail2ban/jail.d/defaults-debian.conf file restored if available.
>
> **Impact of Restoration Failure** - Potential corruption of Fail2ban configuration. Check log file for details.
>
> **After Error** - Continue to next step after restoration.

**Note** - When script fails on this step - it won't attempt restoring earlier steps.

### 9. Schedule cron for daily system update

While it is a bad idea to schedule automatic installation of updates ([read more here](https://debian-administration.org/article/162/A_short_introduction_to_cron-apt)), sizable amount of server administration time can be saved by _downloading_ updates automatically.

In this step we schedule a daily crontab (/etc/cron.daily/linux_init_harden_apt_update.sh) to download updates. You would want to manually do the installation running the below command.

```console
user@host:~$ sudo apt-get dist-upgrade
```

#### Error Handling

> **Failure Impact** - Minimal. No auto download of software updates
>
> **Restoration** - Remove the script file (/etc/cron.daily/linux_init_harden_apt_update.sh).
>
> **Impact of Restoration Failure** - The cron job might execute once a day and _fail_. You might have to delete the file (/etc/cron.daily/linux_init_harden_apt_update.sh) manually.
>
> **After Error** - Continue to next step.
>
> **Note** - When script fails on this step - it won't attempt restoring earlier steps.

### 10. [Optionally] Reset root password

Some VPS providers send you the password of your VPS's _root_ user in email - in plain text. If so, that password needs to be changed immediately. **But, we will disable _root_ login AND password login in the next step, so changing _root_ password might be a slight overkill**. But, still...

Also, most VPS providers nowadays allow you to provide SSH Public Key on their website. If you have done that you can skip this step. **This option is disabled by default**.

To change your _root_ password provide option `-r` or `--resetrootpw`. _root_ password will be auto generated. Passwords are 20 character long, containing a mixture of special-symbols, English upper & lower characters and numbers.

#### Error Handling

> **Failure Impact** - None. Existing password will be valid.
>
> **Restoration** - Nothing to restore.
>
> **Impact of Restoration Failure** - None.
>
> **After Error** - Continue to next step.

**Note** - When script fails on this step - it won't attempt restoring earlier steps.

### 11. Alter SSH options

This step contines from step 3 to harden our ssh login. Here, we edit _/etc/ssh/sshd_config_ file to achieve the following:-

-   Disable _root_ login (PermitRootLogin no). No one needs to work on _root_. The new user created already has _root_ privileges anyways.
-   Disable password login (`PasswordAuthentication no`). This ensures we can login ONLY though SSH Keys.
-   Specify where to find authorized public keys which are granted login (\\.ssh\authorized_keys %h\\.ssh\authorized_keys)

#### Error Handling

> **Failure Impact** - Potentially **CATASTROPHIC**.
>
> **Restoration** - Delete user and its home directory; Disable UFW: If back up of /etc/fail2ban/jail.local file found, then that is restored; else back up of /etc/fail2ban/jail.conf is restored. Also, back up of /etc/fail2ban/jail.d/defaults-debian.conf file restored if available. Restore the /etc/ssh/sshd_config file from backup file created before the operation.
>
> **Impact of Restoration Failure** - Fatal. DO NOT logout of the session. If you do then, you may not be able to log back in. Check the log file to see what went wrong. Issue the following command and see what is the out put.
>
> ```console
> root@host:~# service sshd restart
> ```
>
> Search the error message on internet for solution.
>
> **After Error** - Script will be terminated.

### 12. Display Summary

All the generated username, passwords, SSH Key location & SSH Keys themselves are displayed on the screen.

This might not be desired (nosy neighbours). To NOT show the details on screen and find them from the log file use `-hide` option.

NOTE - while we login through SSH Keys, you will still be asked for your password (after logging in) while installing softwares and for other administrative operations. So, you NEED ALL of the information displayed on the screen.

The logfile is located in /tmp/ - hence will be removed when server reboots. All the details shown on the screen and a lot more can be found in the log. Exact logfile location will be shown on the screen.

## FAQ

Q - Is the script idempotent?

Ans - No.

> **Idempotency**
>
> An operation is _idempotent_ if the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

Q - Why is it not idempotent?

Ans - We take backup of configuration files, which stay on your server after operations. After taking back up of the file - **script sometimes comments out older configuration**. This is specifically true for [Step 4](..#4-optionally-reset-the-url--for-apt-repo-from-vps-provided-cdn-to-os-provided-ones "Goto details of the step") where we comment out older configurations and append new ones to the end of the file. Also, for the SSH configuration file (/etc/ssh/sshd_conf) where we comment out the line of configuration and add the new configuration below the commented out line. So, if we re-run the script multiple times, those changes would compound. Details of all such operatons are listed below:-

1.  Multiple backup files of _sources.list_ in _/etc/apt/_ directory. eg - _sources.list.13_02_2019-01_21_07_bak_ for each execution.
2.  Many commented out lines on _/etc/apt/sources.list_ file.
3.  Multiple backup files of (.list) files under _/etc/apt/sources.d/_ directory.
4.  Many commented out lines on ALL (.list) files under _/etc/apt/sources.d/_ directory.
5.  Some softwares would be installed or updated _sudo_, _curl_, _screen_, _ufw_, _fail2ban_.
6.  _One_ backup of _/etc/fail2ban/jail.conf_ file.
7.  Multiple backups of _/etc/fail2ban/jail.local_ file
8.  Multiple backups of _/etc/fail2ban/jail.d/defaults-debian.conf_ file
9.  Multiple backups of _sshd_config_ file in _/etc/sshd/_ directory

Q - What would happen if I rerun the script multiple times?

Ans -

-   A new user would be created per execution
-   All changes you have made to **_/etc/apt/\*/\*.list_** files will be **overwritten**.
-   Changes to **_/etc/fail2ban/jail.conf_** file would not be read by fail2ban.
-   Following configuration changes to **_/etc/fail2ban/jail.local_** file (under [DEFAULT] section) will be **overwitten**:-
    1. bantime
    2. backend
    3. ignoreip
-   All changes to **_/etc/fail2ban/jail.d/defaults-debian.conf_** will be **overwritten**.
-   Following changes to **_/etc/sshd/sshd_config_** file would be overwritten
    1. PermitRootLogin
    2. PasswordAuthentication
    3. AuthorizedKeysFile

Q - What are the files that the script creates or edits?

Ans - Following is the list (in order of execution):-

1. New - _/home/[new-username]/.ssh/[new-username].pem_
2. New - _/home/[new-username]/.ssh/[new-username].pem.pub_
3. New - _/home/[new-username]/.ssh/authorized_keys_
4. New - _/etc/apt/sources.list.[execution-timestamp]\_bkp_
5. Edit - _/etc/apt/sources.list_
6. New - _/etc/apt/sources.d/[anydotlistfile.list].[execution-timestamp]\_bkp_
7. Edit - _/etc/apt/sources.d/[anydotlistfile.list]_
8. New - If it does not exist - _/etc/fail2ban/jail.local_
9. New - /etc/fail2ban/jail.conf.[execution-timestamp]\_bkp
10. New - If _/etc/fail2ban/jail.local_ exists - _/etc/fail2ban/jail.local.[execution-timestamp]\_bkp_
11. Edit - _/etc/fail2ban/jail.local_
12. New - _/etc/fail2ban/jail.d/defaults-debian.conf[execution-timestamp]\_bkp_
13. Edit - _/etc/fail2ban/jail.d/defaults-debian.conf_
14. New - If does not exist - _/etc/cron.daily/linux_init_harden_apt_update.sh_
15. New - _/etc/ssh/sshd_config.[execution-timestamp]\_bkp_
16. Edit - _/etc/ssh/sshd_config_

Q - Why comment out entire files in /etc/apt/ instead of just deleting them and creating new ones with required configurations?

Ans - If there was error creating backup files, you would have no way to restore sources from. We can put more if-else to check if backup creation failed - but that would make the code unreadable. This is a lengthy script; readability is paramount.

Q - Can I execute it as a non-root user?

Ans -

If your user belongs to "sudo" group then => Yes

Run the script with "sudo" privileges:-

```console
root@host:~$ wget -q https://raw.githubusercontent.com/pratiktri/server_init_harden/master/init-linux-harden.sh -O init-linux-harden.sh && sudo bash ./init-linux-harden.sh --username someusername --resetrootpwd --defaultsourcelist --quiet --hide-credentials

root@host:~$ wget -q https://raw.githubusercontent.com/pratiktri/server_init_harden/master/init-linux-harden.sh -O init-linux-harden.sh && sudo bash ./init-linux-harden.sh -u someusername -r -d -q -hide
```

## Todo

### Bug fixes

-   [ ] fail2ban on Ubuntu 14.04 => need apply default-debian.conf to jail.local itself.
-   [ ] Exception handle - when curl https://ipinfo.io/ip fails

### Roadmap

-   [x] Update README - Assumptions - TOFU, Trust on VPS provider vis-a-vis creating SSH keys on the server
-   [x] New - Add commented license to script itself
-   [ ] New - Add github URL on usage()
-   [ ] New - Enable LUKS (is it even worth it???)
-   [ ] New - Only checks before starting the script should be root-check and "apt" check. Don't want to change
-   [ ] Update - Remove Ubuntu 14.x support - way too old - No systemd - probably has many security holes.
-   [ ] New - add logs to syslog as well (all or only error?)

## License

Copyright 2019 Pratik Kumar Tripathy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
