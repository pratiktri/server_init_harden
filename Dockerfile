FROM debian:12-slim
# FROM debian:11-slim
# FROM ubuntu:24.10
# FROM ubuntu:24.04
# FROM ubuntu:22.04
# FROM ubuntu:20.04
# FROM fedora:41
# FROM fedora:40

# RUN dnf update -y && dnf install -y sudo openssh-server && dnf clean all && systemctl enable sshd

RUN apt-get update && apt-get install -y sudo openssh-server && rm -rf /var/lib/apt/lists/* && service ssh start

WORKDIR /script
COPY init-linux-harden.sh .
RUN chmod +x init-linux-harden.sh

# Test commands - uncomment one at a time to test different scenarios
# Basic hardening (no user creation)
CMD ["./init-linux-harden.sh"]

# Create new user
#CMD ["./init-linux-harden.sh", "-u", "testuser"]

# Create user and reset root password
#CMD ["./init-linux-harden.sh", "-u", "testuser", "-r"]

# Show credentials in console
#CMD ["./init-linux-harden.sh", "-u", "testuser", "-s"]

# Show credentials and reset root password
#CMD ["./init-linux-harden.sh", "-u", "testuser", "-r", "-s"]

# Show help
#CMD ["./init-linux-harden.sh", "-h"]
