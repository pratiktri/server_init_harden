# Linux Server Hardener

A robust POSIX-compliant shell script that automates security hardening for Linux systems through SSH hardening, intrusion detection, firewall configuration, and granular access controls. This production-grade solution ensures consistent security baselines while maintaining compatibility across major Linux distributions.

## **WARNING**

This script can potentially make your server inaccessible if not used properly. Make sure you:

-   Have a backup access method
-   Review the script before running
-   Keep the terminal session open until completion
-   Save all credentials shown/logged during execution

### IMPORTANT: SSH Key Management

After running the script, you MUST:

1. **Save the SSH Private Key**

    - Copy the entire private key content (starts with `-----BEGIN OPENSSH PRIVATE KEY-----`)
    - Store it securely on your local machine as `id_ed25519` or similar
    - Keep it strictly private and NEVER share it with anyone
    - Without this key, you cannot access your server

2. **Save the Key Passphrase**

    - Store the generated passphrase securely
    - Required every time you use the private key
    - Keep it secret like a password
    - Cannot be recovered if lost

3. **Public Key (Optional Save)**
    - The part ending in `.pub` (starts with `ssh-ed25519`)
    - Already configured on the server
    - Can be shared safely with others
    - Used for adding access to other servers

Without the private key and passphrase, you will permanently lose access to your server!

## Status

Tested and working on:

-   Debian 11, 12
-   Ubuntu 22.04, 24.04, 24.10

## What's New in v2.0 🚀

### Improved Logging 🎯

-   **Sensitive Data Control**: New `-s` flag to control credential display
-   Separate console/file logging levels
-   Better organized log file structure
-   More detailed operation logging

### Documentation 📚

-   **Better Examples**: More usage examples and scenarios
-   **Clear Warnings**: Improved warning messages and precautions

### OS Support 🐧

-   Removed unnecessary OS Restrictions

-   Tested on the following distributions:
    -   Ubuntu 22.04, 24.04, 24.10
    -   Debian 11, 12
    -   Fedora 40, 41 (in testing)
    -   FreeBSD (in future)

### Test with Docker 🐳

-   **Test Commands**: Added various test scenarios
-   **Multi-distro**: Support for testing across distributions
-   **Quick Testing**: Faster feedback loop for testing changes

## Usage

### Requirements

-   Root/sudo privileges
-   One of the supported Linux distributions:
    -   Debian 11/12
    -   Ubuntu 20.04/22.04/24.04
    -   Fedora 40/41

### Options

-   `-u USERNAME`: Create a new sudo user
-   `-r`: Reset root password to secure random value
-   `-s`: Show sensitive information in console output
-   `-h`: Display help message

```bash
# Basic hardening (SSH, Fail2ban, UFW, create & secure SSH key for logged in user)
# Default behavior - no user creation, no root reset, no show credentials info
# Use it when VPS already disabled root password and created new user during setup (e.g. NetCup)
./init-linux-harden.sh

# Create new sudo user during hardening
# Use it when VPS already disabled root password, but no new user created
./init-linux-harden.sh -u jay

# Create new user and reset root password
./init-linux-harden.sh -u jay -r

# Show all credentials in console output (less secure)
./init-linux-harden.sh -u jay -s
```

### Post Installation

-   Check if the services are working properly

```bash
sudo ufw status

sudo fail2ban-client status
```

## Features

The script performs comprehensive security hardening:

### SSH Hardening

-   Uses Ed25519 SSH keys (stronger than RSA)
-   Disables root login
-   Disables password authentication
-   Enforces public key authentication
-   Creates backup of original config
-   Secures authorized_keys file with proper permissions

### Fail2ban Protection

-   Protects against brute force attempts
-   Configures SSH jail (1 day ban time)
-   Configures recidive jail (30 days for repeat offenders)
-   Configures nginx-http-auth jail
-   Auto-excludes server's public IP
-   TIP: Unban using `fail2ban-client set sshd unbanip <IP>`

### UFW Firewall

-   Enables and configures UFW
-   Allows SSH (22), HTTP (80), HTTPS (443)
-   Blocks all other incoming traffic
-   Allows all outgoing traffic
-   TIP: Add new rules with `ufw allow <service>`

### User Management

-   Option to reset root password
-   Creates new sudo user (optional)
-   Generates secure random password
-   Creates Ed25519 SSH key pair with 1000 KDF rounds
-   Configures authorized_keys securely
-   TIP: Copy the user credentials from the log file after the script completes

### Backup and Recovery

-   Creates backups of all modified configuration files
-   Automatic recovery if operations fail
-   Restarts affected services as needed
-   Detailed logging for troubleshooting

### Logging

-   All operations logged to `./${SCRIPT_NAME}_TIMESTAMP.log`
-   Sensitive information only logged to file by default
-   Optional console display with `-s` flag
-   Execution time tracking
-   Separate console/file logging levels

## To-do

-   [ ] Test on Fedora 40, 41 on VPS and not on Docker (it fails on Docker right now)
-   [ ] Test on FreeBSD

## License

Copyright © 2025, Pratik Kumar Tripathy. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
