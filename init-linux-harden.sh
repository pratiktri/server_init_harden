#!/etc/bin/env bash

# Accept user name as a script argument
    # If no username provided
        # generate a random username - all lowercase
# Something important fails
    # Revert everything back to how it was
# Redirect every output to a logfile
# Ask the user to NOT logout yet
    # Ask him to report back if he can login using the new user -with the ssh-private key
# If not
    # Remove the SSH-only login and ask the user to login using password
# If he can - great - tell him to talk to the server provider's support to get help regarding SSH-only access
    # Report the things
        # Root password
        # User Password
        # User SSH-Private Key
        # User SSH-Public key
        #   Display the root-user's new password on screen
# What to do if making .bkp file fails?

##############################################################
# Basic checks before starting
##############################################################

# No root - no good
[ "$(id -u)" != "0" ] && {
    echo "Error: You must be root to run this script, please login as root and execute the script again."
    exit 1
}

# Check supported OSes
if [[ $(sed 's/\..*//' /etc/debian_version) -eq 8 ]]; then
    DEB_VER_STR="jessie"
elif [[ $(sed 's/\..*//' /etc/debian_version) -eq 9 ]]; then
    DEB_VER_STR="stretch"
else
    printf "This version of Debian is NOT supported.\\n"
    exit 1
fi


##############################################################
# Display what the script does
##############################################################

# What to do if something fails
    # Catastophic failure
    # Ignorable failure
# Where to find the log file

##############################################################
# Gather info
##############################################################

# Change root user's password
# Choose a user name 
clear
echo "Do you want to change root password ? (y/n)"
echo "(You might want to do this if you received it as an email from your host.)"
    while [[ $RESET_ROOT_PWD != "y" && $RESET_ROOT_PWD != "n" ]]; do
        read -rp "Select an option [1-2]: " RESET_ROOT_PWD
done

# Ask for a user name
echo ""
echo "A new non-root user will be created for you."
read -rp "Please provide a user name - " NORM_USER_NAME

# If the user exists - ask for a different username
while [[ ! "$NORM_USER_NAME" ]] && [[ $(getent passwd "$NORM_USER_NAME" | wc -l) -gt 0 ]]; do
    echo "User name either already exists or you provided an invalid username."
    read -rp "Please provide a user name - " NORM_USER_NAME
done


##############################################################
# Log
##############################################################

CSI='\033['
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"
CVERTICAL="|"
CHORIZONTAL="_"
SCRIPT_NAME=server_harden
SCRIPT_VERSION=0.2
LOGFILE=/tmp/"$SCRIPT_NAME"_v"$SCRIPT_VERSION".log


function horizontal_fill() {
    local char=$1
    declare -i rep=$2
    for ((x = 0; x < "$rep"; x++)); do
        printf %s "$char"
    done
}

function line_fill() {
    horizontal_fill "$1" "$2"
    printf "\\n"
}

function recap (){
    local purpose=$1
    local value=$2

    if [[ $value ]]; then
        value="[${CGREEN}${value}${CEND}]"
    else
        value="${CRED}-FAILED-${CEND}"
    fi

    horizontal_fill "$CVERTICAL" 1
    printf "%20s:%5s%-33s" "$purpose" " " "$(echo -e "$value")"
    line_fill "$CVERTICAL" 1
}

function finally(){
    #local what_failed=$1

    line_fill "$CHORIZONTAL" 60
    recap "New root Password" "$PASS_ROOT"
    recap "User Name" "$NORM_USER_NAME"
    recap "User's Password" "$USER_PASS"
    recap "User's SSH Private Key Location" "$KEY_PASS"
    recap "User's SSH Public Key Location" "$KEY_PASS"
    recap "User's SSH Key Passphrase" "$KEY_PASS"
    line_fill "$CHORIZONTAL" 60
}

function log() {
    local EVENT=$1
    local RESULT=$2

    if [ "$RESULT" = "SUCCESSFUL" ]
    then
        printf "%30s %7s [${CGREEN}${RESULT}${CEND}]\\n" "$EVENT" " "
        echo "$(date '+%Y-%m-%d %H:%M:%S')" - "$EVENT" - "$RESULT" >> "$LOGFILE"
    elif [ "$RESULT" = "FAILED" ] 
    then
        printf "%30s %7s [${CRED}${RESULT}${CEND}]\\n" "$EVENT" " "
        printf "\\n\\nPlease look at %s\\n\\n" "$LOGFILE"
        echo "$(date '+%Y-%m-%d %H:%M:%S')" - "$EVENT" - "$RESULT" >> "$LOGFILE"
    else
        printf "%30s %7s [${CRED}..${CEND}]\\r" "$EVENT" " "
        echo "$(date '+%Y-%m-%d %H:%M:%S')" - "$EVENT" - "begin..." >> "$LOGFILE"
    fi
}


declare SESSION_TYPE=""
# Check if the user connected through SSH
if [[ -n "$SSH_CLIENT" ]] || [[ -n "$SSH_TTY" ]]; then
    SESSION_TYPE=remote/ssh
else
    case $(ps -o comm= -p $PPID) in
        sshd|*/sshd)
            SESSION_TYPE=remote/ssh;
    esac
fi

if [[ $SESSION_TYPE == "remote/ssh" ]]; then
    printf "You are currently connected to an SSH session.\\n"
else
    printf "You are currently connected using password authentication.\\n"
fi


##############################################################
# Change root's password
##############################################################

if [[ $RESET_ROOT_PWD == 'y' ]]; then
    {
        log "Changing root password"
        
        # Generate a 15 character random password
        PASS_ROOT="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1

        # Change root's password
        echo -e "${PASS_ROOT}\\n${PASS_ROOT}" | passwd > /dev/null
    }

    if [[ $? -eq 0 ]]; then
        log "Changing root password" "SUCCESSFUL"
    else
        # Low priority - since we are disabling root login anyways
        log "Changing root password" "FAILED"
    fi
fi


##############################################################
# Create a normal user
##############################################################
{
    log "Creating new user"

    # Generate a 15 character random password
    USER_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1

    # Create the user and assign the above password
    echo -e "${USER_PASS}\\n${USER_PASS}" | adduser "$NORM_USER_NAME" -q --gecos "First Last,RoomNumber,WorkPhone,HomePhone" 2> /dev/null

    # Give root privilages to the above user
    usermod -aG sudo "$NORM_USER_NAME" || exit 1
}

if [[ $? -eq 0 ]]; then
    log "Creating new user" "SUCCESSFUL"
else
    log "Creating new user" "FAILED"
    finally "CNU"
    exit 1;
fi


##############################################################
# Create SSH Key for the new user
##############################################################
{
    log "Creating SSH Key for new user"

    shopt -s nullglob
    KEY_FILES=("$SSH_DIR"/"$NORM_USER_NAME".pem*)

    # Create key file only if it does NOT exist
    if [[ ! ${KEY_FILES[0]} ]]; then
        SSH_DIR=/home/"$NORM_USER_NAME"/.ssh
        mkdir "$SSH_DIR" || exit 1

        # Generate a 15 character random password for key
        KEY_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1

        # Create a OpenSSH-compliant ed25519-type key
        ssh-keygen -a 1000 -o -t ed25519 -N "$KEY_PASS" -C "$NORM_USER_NAME" -f "$SSH_DIR"/"$NORM_USER_NAME".pem -q || exit 1

        KEY_FILES=("$SSH_DIR"/"$NORM_USER_NAME".pem*)
    fi
}
if [[ $? -eq 0 ]]; then
    log "Creating SSH Key for new user" "SUCCESSFUL"
else
    log "Creating SSH Key for new user" "FAILED"
    finally "CSK"
    exit 1;
fi


##############################################################
# Add generated key to authorized_keys file
##############################################################
{
    log "Adding SSH Key to 'authorized_keys' file"

    # Insert the public key into "authoried_keys" file
    cat "${KEY_FILES[1]}" >> "$SSH_DIR"/authorized_keys || exit 1
}
if [[ $? -eq 0 ]]; then
    log "Adding SSH Key to 'authorized_keys' file" "SUCCESSFUL"
else
    log "Adding SSH Key to 'authorized_keys' file" "FAILED"
    finally "ATAF"
    exit 1;
fi


##############################################################
# Secure authorized_keys file
##############################################################
{
    log "Securing 'authorized_keys' file"
    
    # Set appropriate permissions for ".ssh" dir and "authorized_key" file
    chown -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chgrp -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chmod 700 "$SSH_DIR" && \
        chmod 400 "$SSH_DIR"/authorized_keys && \
        chattr +i "$SSH_DIR"/authorized_keys
}
if [[ $? -eq 0 ]]; then
    log "Securing 'authorized_keys' file" "SUCCESSFUL"
else
    log "Securing 'authorized_keys' file" "FAILED"
fi


##############################################################
# Enable SSH-only login
##############################################################

function config_search_regex(){
    local search_key=$1
    declare -i isCommented=$2
    local value=$3

    if [[ "$isCommented" -eq 1 ]] && [[ ! "$value" ]]; then
        # Search Regex for an uncommented (active) field
        echo '(^ *)'"$search_key"'( *).*([[:word:]]+)( *)$'
    elif [[ "$isCommented" -eq 2 ]] && [[ ! "$value" ]]; then
        # Search Regex for a commented out field
        echo '(^ *)#.*'"$search_key"'( *).*([[:word:]]+)( *)$'

    elif [[ "$isCommented" -eq 1 ]] && [[ "$value" ]]; then
        # Search Regex for an active field with specified value
        echo '(^ *)'"$search_key"'( *)('"$value"')( *)$'
    elif [[ "$isCommented" -eq 2 ]] && [[ "$value" ]]; then
        # Search Regex for an commented (inactive) field with specified value
        echo '(^ *)#.*'"$search_key"'( *)('"$value"')( *)$'

    else
        exit 1    
    fi
}

function set_config_key(){
    local file_location=$1
    local key=$2
    local value=$3

    ACTIVE_KEYS_REGEX=$(config_search_regex "$key" "1")
    ACTIVE_CORRECT_KEYS_REGEX=$(config_search_regex "$key" "1" "$value")
    INACTIVE_KEYS_REGEX=$(config_search_regex "$key" "2")

    # If no keys present - insert the correct key to the end of the file
    if [[ $(grep -Pnc "$INACTIVE_KEYS_REGEX" "$file_location") -eq 0 ]] && [[ $(grep -Pnc "$ACTIVE_KEYS_REGEX" "$file_location") -eq 0 ]];
    then
        echo "$key" "$value" >> "$file_location"
    fi

    # If Config file already has active keys
    #  Keep only the LAST correct one and comment out the rest
    if [[ $(grep -Pnc "$ACTIVE_KEYS_REGEX" "$file_location") -gt 0 ]]; 
    then
        # Last correct active entry's line number
        LAST_CORRECT_LINE=$(grep -Pn "$ACTIVE_CORRECT_KEYS_REGEX" "$file_location" | tail -1 | cut -d: -f 1)

        # Loop through each of the active lines
        grep -Pn "$ACTIVE_KEYS_REGEX" "$file_location" | while read -r i; 
        do
            # Get the line number
            LINE_NUMBER=$(echo "$i" | cut -d: -f 1 )

            # If this is the last correct entry - break
            if [[ $LAST_CORRECT_LINE -ne 0 ]] && [[ $LINE_NUMBER == "$LAST_CORRECT_LINE" ]]; then
                break
            fi

            # Comment out the line
            sed -i "$LINE_NUMBER"'s/.*/#&/' "$file_location"
        done
    fi

    # If Config file has inactive keys and NO active keys 
    # Append the appropriate key below the LAST inactive key
    if [[ $(grep -Pnc "$INACTIVE_KEYS_REGEX" "$file_location") -gt 0 ]] && [[ $(grep -Pnc "$ACTIVE_KEYS_REGEX" "$file_location") -eq 0 ]]; 
    then
        # Get the line number of - last inactive key
        LINE_NUMBER=$(grep -Pn "$INACTIVE_KEYS_REGEX" "$file_location" | tail -1 | cut -d: -f 1)

        (( LINE_NUMBER++ ))

        # Insert the correct setting below the last inactive key
        sed -i "$LINE_NUMBER"'i'"$key"' '"$value" "$file_location"
    fi
}

{
    log "Enabling SSH-only login"

    # Backup the sshd_config file
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || exit 1

    # Remove root login
    set_config_key "/etc/ssh/sshd_config" "PermitRootLogin" "no"

    # Disable password login
    set_config_key "/etc/ssh/sshd_config" "PasswordAuthentication" "no"

    # Set SSH Authorization-Keys path
    set_config_key "/etc/ssh/sshd_config" "AuthorizedKeysFile" '%h\/\.ssh\/authorized_keys'

    systemctl restart sshd
}
if [[ $? -eq 0 ]]; then
    log "Enabling SSH-only login" "SUCCESSFUL"
else
    log "Enabling SSH-only login" "FAILED"
    finally "ESOL"
    exit 1;
fi


##############################################################
# Change default source-list
##############################################################

# Low priority - But what to do if it fails???
log "Changing urls in sources.list to defaults"

mv /etc/apt/sources.list /etc/apt/sources.list.bak
sed -i "1,$(wc -l < /etc/apt/sources.list.bak) s/^/#/" /etc/apt/sources.list.bak

# Default sources list for debian
cat <<TAG > /etc/apt/sources.list || exit 1
deb https://deb.debian.org/debian ${DEB_VER_STR} main
deb-src https://deb.debian.org/debian ${DEB_VER_STR} main

## Major bug fix updates produced after the final release of the
## distribution.
deb http://security.debian.org ${DEB_VER_STR}/updates main
deb-src http://security.debian.org ${DEB_VER_STR}/updates main

deb https://deb.debian.org/debian ${DEB_VER_STR}-updates main
deb-src https://deb.debian.org/debian ${DEB_VER_STR}-updates main

deb https://deb.debian.org/debian ${DEB_VER_STR}-backports main
deb-src https://deb.debian.org/debian ${DEB_VER_STR}-backports main
TAG

# Find any additional sources listed by the provider and comment them out
SOURCE_FILES=(/etc/apt/source*/*.list)
if [[ ${#SOURCE_FILES[@]} -gt 0 ]]; then
    for file in "${SOURCE_FILES[@]}";
    do
        mv "$file" "$file".bak
        sed -i "1,$(wc -l < "$file") s/^/#/" "$file" >&2 /dev/null
    done
fi

# Comment out cloud-init generated templates for sources
CLOUD_INIT_FILES=(/etc/cloud/templates*/*.tmpl)
if [[ ${#CLOUD_INIT_FILES[@]} -gt 0 ]]; then
    for file in "${CLOUD_INIT_FILES[@]}";
    do
        mv "$file" "$file".bak
        sed -i "1,$(wc -l < "$file") s/^/#/" "$file" >&2 /dev/null
    done
fi

if [[ $? -eq 0 ]]; then
    log "Changing urls in sources.list to defaults" "FAILED"
else
    log "Changing urls in sources.list to defaults" "FAILED"
fi


##############################################################
# Install required softwares
##############################################################
apt-get update && apt-get upgrade -y && apt-get install -y sudo curl screen


##############################################################
# Recap
##############################################################

finally