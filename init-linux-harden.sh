#!/bin/sh

# TODO: Setup docker for testing across OSes
# TODO: Make it posix as POSIX compliant as possible - freebsd feasible???
# TODO: Things from https://github.com/imthenachoman/How-To-Secure-A-Linux-Server

SCRIPT_NAME=linux_init_harden
SCRIPT_VERSION=2.0
LOGFILE_NAME="${SCRIPT_NAME}_$(date '+%Y-%m-%d_%H-%M-%S').log"

# Global variables for username and password
USERNAME=""
USER_PASSWORD=""

# Parse command line arguments
parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
        -u | --username)
            # Validate username format
            if [ -n "$2" ] && echo "$2" | grep -qE '^[a-zA-Z][a-zA-Z0-9_-]*$'; then
                USERNAME="$2"
                shift 2
            else
                console_log "Error" "Invalid username format. Must start with a letter and contain only alphanumeric characters, _, or -"
                exit 1
            fi
            ;;
        *)
            shift
            ;;
        esac
    done
}

create_user() {
    # If no username provided, generate a random one
    if [ -z "$USERNAME" ]; then
        # Generate a random username starting with a letter
       
        USERNAME="$(</dev/urandom tr -cd '[:lower:]' | head -c 6)""$(</dev/urandom tr -cd '0-9' | head -c 2)"
        console_log "Info" "Generated username: $USERNAME"
    fi

    # Check if username already exists
    if id "$USERNAME" >/dev/null 2>&1; then
        console_log "Error" "User $USERNAME already exists"
        return 1
    fi

    # Generate a 15-character random password
    USER_PASSWORD=$(head -c 12 /dev/urandom | base64 | tr -dc "[:alnum:]" | head -c 15)

    # Create user with the generated password
    console_log "Info" "Creating user $USERNAME"
    if (echo "$USERNAME:$USER_PASSWORD" | chpasswd) &&
        adduser "$USERNAME" --gecos ",,," --disabled-password &&
        usermod -aG sudo "$USERNAME"; then

        # Log user creation details
        file_log "User created: $USERNAME"
        file_log "User password: $USER_PASSWORD"
        console_log "Success" "User $USERNAME created successfully"

        return 0
    else
        console_log "Error" "Failed to create user $USERNAME"
        # Attempt to cleanup if user creation fails
        revert_create_user
        return 1
    fi
}

revert_create_user() {
    # Check if the user exists before attempting to remove
    if id "$USERNAME" >/dev/null 2>&1; then
        console_log "Info" "Attempting to remove user $USERNAME"

        # Remove user and its home directory
        if userdel -r "$USERNAME" >/dev/null 2>&1; then
            console_log "Success" "User $USERNAME and home directory removed successfully"
            file_log "User $USERNAME and home directory removed successfully"
            return 0
        else
            console_log "Error" "Failed to remove user $USERNAME"
            file_log "Failed to remove user $USERNAME"
            return 1
        fi
    else
        console_log "Info" "No user $USERNAME found to remove"
        file_log "No user $USERNAME found to remove"
        return 0
    fi
}

console_log() {
    # $1: Log level
    # $2: Log message
    case "$1" in
    Success) printf "[ \033[0;32m OK \033[0m ] %s\n" "$2" ;;
    Error) printf "[ \033[0;31mFAIL\033[0m ] %s\n" "$2" ;;
    Info) printf "[ \033[0;34mINFO\033[0m ] %s\n" "$2" ;;
    *) printf "[     ] %s\n" "$2" ;;
    esac
}

file_log() {
    # $1: Log message
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Write to logfile with timestamp and log level
    printf "%s: %s\n" "$timestamp" "$1" >>"$LOGFILE_NAME"
}

create_logfile() {
    touch "$LOGFILE_NAME"
}

main() {
    create_logfile
    parse_args "$@"

    console_log "Info" "Starting user creation process"

    if create_user; then
        console_log "Success" "User creation completed"
        file_log "User creation process completed successfully"
    else
        console_log "Error" "User creation failed"
        file_log "User creation process failed"
        exit 1
    fi

    console_log "Success" "Installation success"
    console_log "Error" "Could not copy stuff"
    console_log "Info" "Took 3 minutes to complete script"

    file_log "Installation success"
    file_log "Could not copy stuff"
    file_log "Took 3 minutes to complete script"
}

main "$@"
