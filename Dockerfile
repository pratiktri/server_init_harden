# Use Debian Slim as base image
FROM debian:stable-slim

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    sudo \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /script

# Copy the initialization script
COPY init-linux-harden.sh /script/

# Make the script executable
RUN chmod +x /script/init-linux-harden.sh

# Set entrypoint to run the script
ENTRYPOINT ["/bin/sh", "-c"]

# Default command to run the script
CMD ["/script/init-linux-harden.sh"]
