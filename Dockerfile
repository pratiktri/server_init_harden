# Fail2ban failed
# FROM debian:12-slim

# UFW failed
# FROM debian:11-slim

# All good
FROM ubuntu:24.10

# All good
# FROM ubuntu:24.04

# All good
# FROM ubuntu:22.04

# Fail2ban failed
# FROM ubuntu:20.04

# User creation failed, Fail2ban failed
# FROM fedora:41

# User creation failed, Fail2ban failed
# FROM fedora:40
# RUN dnf update -y && dnf install -y sudo openssh-server && dnf clean all && systemctl enable sshd

RUN apt-get update && apt-get install -y sudo openssh-server && rm -rf /var/lib/apt/lists/* && service ssh start

WORKDIR /script
COPY init-linux-harden.sh .
RUN chmod +x init-linux-harden.sh

# Default command to run the script
CMD ["./init-linux-harden.sh", "-u", "test"]
