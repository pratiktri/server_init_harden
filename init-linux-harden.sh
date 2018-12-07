#!/etc/bin/env bash

# Something important fails
    # Revert everything back to how it was
# Ask the user to NOT logout yet and login as normal user
    # If he can - great 
        # Remove the SSH-only login and ask the user to login using password
        # Report 
            # Root password
            # User Password
            # User SSH-Private Key
            # User SSH-Public key
    # If not
        # Ask him to report back if he can login using the new user -with the ssh-private key
        # - tell him to talk to the server provider's support to get help regarding SSH-only access
# What to do if making .bkp file fails?
    # Add timestamp to all backup files filename.071218_171731_bak
#Test
    # 1 - Deb 9.x
    # 2 - Deb 8.x
    # 3 - Ubuntu 14.x
    # 4 - Ubuntu 16.x
    # 5 - Ubuntu 18.x
    # DigitalOcean
    # OVH
    # Hetzner

SCRIPT_NAME=server_harden
SCRIPT_VERSION=0.2
LOGFILE=/tmp/"$SCRIPT_NAME"_v"$SCRIPT_VERSION".log

##############################################################
# Basic checks before starting
##############################################################

# No root - no good
[ "$(id -u)" != "0" ] && {
    printf "ERROR: You must be root to run this script.\\nPlease login as root and execute the script again."
    exit 1
}

# Check supported OSes
if [[ $(cut -d. -f 1 < /etc/debian_version) -eq 8 ]]; then
    DEB_VER_STR="jessie"
elif [[ $(cut -d. -f 1 < /etc/debian_version) -eq 9 ]]; then
    DEB_VER_STR="stretch"
else
    printf "This script only supports Debian Stretch (9.x) and Debian Jessie (8.x).\\n"
    printf "Your OS is NOT supported.\\n"
    exit 1
fi


##############################################################
# Gather info
##############################################################

# Change root user's password
# Choose a user name 
clear
echo "Do you want to change root password ? (y/n)"
echo "(You might want to do this if you received it as an email from your host.)"
while [[ $RESET_ROOT_PWD != "y" && $RESET_ROOT_PWD != "n" ]]; do
        read -rp "Select an option (y/n): " RESET_ROOT_PWD
        RESET_ROOT_PWD=$(echo "$RESET_ROOT_PWD" | head -c 1)
done

echo "Allow this script to randomly generate a username for you ? (y/n)"
    while [[ $AUTO_GEN_USERNAME != "y" && $AUTO_GEN_USERNAME != "n" ]]; do
        read -rp "Select an option (y/n): " AUTO_GEN_USERNAME
done

if [[ $AUTO_GEN_USERNAME == 'n' ]]; then
    while [[ ! "$NORM_USER_NAME" ]]; do
        printf "Please provide a user name - \\n"
        printf "%2s - [a-zA-Z0-9] [-] [_] are allowed\\n%2s - NO special characters.\\n%2s - NO spaces.\\n:" " " " " " "
        read -r NORM_USER_NAME

        # If the user exists or invalid characters - ask for a different username
        if [[ $(echo "$NORM_USER_NAME" | grep -Pnc '^[a-zA-Z0-9_-]+$') -eq 0 ]] || 
           [[ $(getent passwd "$NORM_USER_NAME" | wc -l) -gt 0 ]]; then
            NORM_USER_NAME=""
            printf "%2s !!! User name already exists or \\n%2s !!! Invalid characters in the User name.\\n" " " " "
            continue
        fi
    done
else
    echo ""
fi


##############################################################
# Log
##############################################################

CSI='\033['
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"
CVERTICAL="|"
CHORIZONTAL="_"

# Reset privilous log file
printf "" > "$LOGFILE"

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
    # Check if $what_failed is one of the catastrophic failures
    #   if - Catastrofic failure - Check if any .bkp file exist and revert them to original
        # Let user know nothing was changed
    #   if - Non-catastrophic failure - Inform user of side effects
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

function file_log(){
    printf "%s - %s\\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOGFILE"
}

function op_log() {
    local EVENT=$1
    local RESULT=$2

    if [ "$RESULT" = "SUCCESSFUL" ]
    then
        printf "\r%30s %7s [${CGREEN}${RESULT}${CEND}]\\n" "$EVENT" " "
        file_log "${EVENT} - ${RESULT}"
    elif [ "$RESULT" = "FAILED" ] 
    then
        printf "\r%30s %7s [${CRED}${RESULT}${CEND}]\\n" "$EVENT" " "
        printf "\\n\\nPlease look at %s\\n\\n" "$LOGFILE"
        file_log "${EVENT} - ${RESULT}"
    else
        printf "%30s %7s [${CRED}..${CEND}]" "$EVENT" " "
        file_log "${EVENT} - begin..."
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
    file_log "Connected through SSH session."
else
    file_log "Connected using password authentication."
fi


##############################################################
# Display what the script does
##############################################################

clear
cat <<INFORM | more
         !!! READ BELOW & PRESS ENTER TO CONTINUE !!!
##################################################################
This script performs the following tasks :-
    1 - Change your root password (unless you have choosen NOT to)
    2 - Create a non-root user (unless provided by you a random 
        username will be created)
    3 - Generate SSH keys on the server and store them at ~/.ssh
    4 - Adds the public key from the above step to 
        ~/.ssh/authorized_keys file
    5 - Restricts access to the SSH ~/.ssh folder
    6 - Restricts login method to SSH-only by editing 
        /etc/ssh/sshd_config file to enable 
    7 - Restores the /etc/apt/sources.list 
        (Most server provider alter these to serve software from 
        their CDNs)
    8 - Installs "sudo" "curl" "screen"
    9 - Display the following at the end
            a) root password (if changed)
            b) user name
            c) user password
            d) SSH Private Key
            e) SSH Public Key

Before editing any file, script creates a back up of that file 
(filename.bak) in the same directory. If script detects any 
catastrophic error, then it restores the original files. Script 
assumes you are running this on a brand new VPS and that DATALOSS 
OR LOSS OF ACCESS TO THE SERVER IS NOT A MAJOR CONCERN. If you do 
however lose access to the server - most VPS provider allow to 
create a new one easily.

A log file can be found at ${LOGFILE}

TO CONTINUE (press any key)...
TO EXIT (ctrl + c)...
INFORM

read -r
clear

##############################################################
# Change root's password
##############################################################

if [[ $RESET_ROOT_PWD == 'y' ]]; then
    {
        op_log "Changing root password"
        
        # Generate a 15 character random password
        PASS_ROOT="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1

        file_log "Generated Root Password - ${PASS_ROOT}"

        # Change root's password
        echo -e "${PASS_ROOT}\\n${PASS_ROOT}" | passwd 
    } 2>> "$LOGFILE" >&2

    if [[ $? -eq 0 ]]; then
        op_log "Changing root password" "SUCCESSFUL"
    else
        # Low priority - since we are disabling root login anyways
        op_log "Changing root password" "FAILED"
    fi
fi


##############################################################
# Create a normal user
##############################################################
{
    op_log "Creating new user"

    if [[ $AUTO_GEN_USERNAME == 'y' ]]; then
        NORM_USER_NAME="$(< /dev/urandom tr -cd 'a-z' | head -c 6)""$(< /dev/urandom tr -cd '0-9' | head -c 2)" || exit 1
        file_log "Generated user name - ${NORM_USER_NAME}"
    fi

    # Generate a 15 character random password
    USER_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1
    file_log "Generated user password - ${USER_PASS}"

    # Create the user and assign the above password
    echo -e "${USER_PASS}\\n${USER_PASS}" | adduser "$NORM_USER_NAME" -q --gecos "First Last,RoomNumber,WorkPhone,HomePhone"

    # Give root privilages to the above user
    usermod -aG sudo "$NORM_USER_NAME" || exit 1
} 2>> "$LOGFILE" >&2

if [[ $? -eq 0 ]]; then
    op_log "Creating new user" "SUCCESSFUL"
else
    op_log "Creating new user" "FAILED"
    finally "CNU"
    exit 1;
fi


##############################################################
# Create SSH Key for the new user
##############################################################
{
    op_log "Creating SSH Key for new user"

    shopt -s nullglob
    KEY_FILES=("$SSH_DIR"/"$NORM_USER_NAME".pem*)

    #TODO - If SSH files already exist - rename them to .timestamp_bkp

    # Create key file only if it does NOT exist
    if [[ ! ${KEY_FILES[0]} ]]; then
        SSH_DIR=/home/"$NORM_USER_NAME"/.ssh
        mkdir "$SSH_DIR" || exit 1

        # Generate a 15 character random password for key
        KEY_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1
        file_log "Generated SSH Key Passphrase - ${KEY_PASS}"

        # Create a OpenSSH-compliant ed25519-type key
        ssh-keygen -a 1000 -o -t ed25519 -N "$KEY_PASS" -C "$NORM_USER_NAME" -f "$SSH_DIR"/"$NORM_USER_NAME".pem -q || exit 1

        # See if the files actually got created
        KEY_FILES=("$SSH_DIR"/"$NORM_USER_NAME".pem*)
        if [[ ${#KEY_FILES[@]} -eq 0 ]]; then
            file_log "Unknown error occured."
            file_log "Could not create SSH key files."
            exit 1
        fi
    fi
} 2>> "$LOGFILE" >&2
if [[ $? -eq 0 ]]; then
    op_log "Creating SSH Key for new user" "SUCCESSFUL"
else
    op_log "Creating SSH Key for new user" "FAILED"
    finally "CSK"
    exit 1;
fi


##############################################################
# Add generated key to authorized_keys file
##############################################################
{
    op_log "Adding SSH Key to 'authorized_keys' file"

    # Create authorized_keys if it does not exist yet
    touch "$SSH_DIR"/authorized_keys

    # Insert the public key into "authoried_keys" file
    cat "${KEY_FILES[1]}" >> "$SSH_DIR"/authorized_keys || exit 1
} 2>> "$LOGFILE" >&2
if [[ $? -eq 0 ]]; then
    op_log "Adding SSH Key to 'authorized_keys' file" "SUCCESSFUL"
else
    op_log "Adding SSH Key to 'authorized_keys' file" "FAILED"
    finally "ATAF"
    exit 1;
fi


##############################################################
# Secure authorized_keys file
##############################################################
{
    op_log "Securing 'authorized_keys' file"
    
    # Set appropriate permissions for ".ssh" dir and "authorized_key" file
    chown -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chgrp -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chmod 700 "$SSH_DIR" && \
        chmod 400 "$SSH_DIR"/authorized_keys && \
        chattr +i "$SSH_DIR"/authorized_keys
} 2>> "$LOGFILE" >&2
if [[ $? -eq 0 ]]; then
    op_log "Securing 'authorized_keys' file" "SUCCESSFUL"
else
    file_log "Setting restrictive permissions for '~/.ssh/' directory failed"
    file_log "Please do 'ls -lAh ~/.ssh/' and check manually to see what went wrong."
    file_log "Rest of the tasks will continue."
    op_log "Securing 'authorized_keys' file" "FAILED"
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
    op_log "Enabling SSH-only login"

    # Backup the sshd_config file
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || exit 1

    # Remove root login
    set_config_key "/etc/ssh/sshd_config" "PermitRootLogin" "no" 

    # Disable password login
    set_config_key "/etc/ssh/sshd_config" "PasswordAuthentication" "no"

    # Set SSH Authorization-Keys path
    set_config_key "/etc/ssh/sshd_config" "AuthorizedKeysFile" '%h\/\.ssh\/authorized_keys'

    systemctl restart sshd
} 2>> "$LOGFILE" >&2
if [[ $? -eq 0 ]]; then
    op_log "Enabling SSH-only login" "SUCCESSFUL"
else
    op_log "Enabling SSH-only login" "FAILED"
    finally "ESOL"
    exit 1;
fi


##############################################################
# Change default source-list
##############################################################

# Low priority - But what to do if it fails???
op_log "Changing urls in sources.list to defaults"

mv /etc/apt/sources.list /etc/apt/sources.list.bak 2>> "$LOGFILE" >&2
sed -i "1,$(wc -l < /etc/apt/sources.list.bak) s/^/#/" /etc/apt/sources.list.bak 2>> "$LOGFILE" >&2

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
SOURCE_FILES=(/etc/apt/source*/*.list) 2>> "$LOGFILE" >&2
if [[ ${#SOURCE_FILES[@]} -gt 0 ]]; then
    for file in "${SOURCE_FILES[@]}";
    do
        mv "$file" "$file".bak 2>> "$LOGFILE" >&2
        sed -i "1,$(wc -l < "$file") s/^/#/" "$file" 2>> "$LOGFILE" >&2
    done
fi

# Comment out cloud-init generated templates for sources
CLOUD_INIT_FILES=(/etc/cloud/templates*/*.tmpl) 2>> "$LOGFILE" >&2
if [[ ${#CLOUD_INIT_FILES[@]} -gt 0 ]]; then
    for file in "${CLOUD_INIT_FILES[@]}";
    do
        mv "$file" "$file".bak 2>> "$LOGFILE" >&2
        sed -i "1,$(wc -l < "$file") s/^/#/" "$file" 2>> "$LOGFILE" >&2
    done
fi

if [[ $? -eq 0 ]]; then
    op_log "Changing urls in sources.list to defaults" "FAILED"
else
    op_log "Changing urls in sources.list to defaults" "FAILED"
fi


##############################################################
# Install required softwares
##############################################################
{
    op_log "Installing required softwares"
    apt-get update && apt-get upgrade -y && apt-get install -y sudo curl screen 2>> "$LOGFILE" >&2
}
if [[ $? -eq 0 ]]; then
    op_log "Installing required softwares" "FAILED"
else
    op_log "Installing required softwares" "FAILED"
fi

##############################################################
# Recap
##############################################################

finally