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
    # Add timestamp` to all backup files filename.071218_171731_bak
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
BACKUP_EXTENSION='.'$(date '+%d%m%Y%H%M%S')"_bak"

# Colors
CSI='\033['
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"

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

##################################
# Parse script arguments
##################################

# Script takes arguments as follows
# init-linux-harden -username=pratik --resetroot
# init-linux-harden -u pratik --resetroot

function usage() {
    if [ -n "$1" ]; then
        echo ""
        echo -e "${CRED}$1${CEND}\n"
    fi

    echo "Usage: $0 [-u|--username username] [-r|--resetrootpwd] [--defaultsourcelist]"
    echo "  -u, --username            Username for your server (If omitted script will choose an username for you)"
    echo "  -r, --resetrootpwd        Reset current root password"
    echo "  -d, --defaultsourcelist   Updates /etc/apt/sources.list to download software from debian.org."
    echo "                            NOTE - If you fail to update system after using it, you need to manually reset it. This script keeps a backup in the same folder."

    echo ""
    echo "Example: $0 --username myuseraccount --resetrootpwd"
    printf "\\nBelow restrictions apply to username this script accepts - \\n"
    printf "%2s - [a-zA-Z0-9] [-] [_] are allowed\\n%2s - NO special characters.\\n%2s - NO spaces.\\n" " " " " " "
}

# defaults
AUTO_GEN_USERNAME="y"
RESET_ROOT_PWD="n"
DEFAULT_SOURCE_LIST="n"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -u|--username)
            # validate username
            if [[ $(echo "$2" | grep -Pnc '^[a-zA-Z0-9_-]+$') -eq 0 ]]; then
                usage "Invalid characters in the user name."
                exit 1
            elif [[ $(getent passwd "$2" | wc -l) -gt 0 ]]; then
                echo
                echo -e "${CRED}User name ($2) already exists.${CEND}\n"
                exit 1
            else
                AUTO_GEN_USERNAME="n"
                NORM_USER_NAME="$2"
            fi

            shift
            shift
            ;;
        -r|--resetrootpwd)
            RESET_ROOT_PWD="y"
            shift
            ;;
        -d|--defaultsourcelist)
            DEFAULT_SOURCE_LIST="y"
            shift
            ;;
        -h|--help)
            usage
            shift
            ;;
        *)
            usage "Unknown parameter passed: $1" "h"
            exit 1
            shift
            shift
            ;;
    esac
done


##############################################################
# Log
##############################################################

CVERTICAL="|"
CHORIZONTAL="_"


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

function revert_changes(){
    if [[ $1 = "Creating new user" ]]; then
        revert_create_user
    elif [[ $1 = "Creating SSH Key for new user" ]]; then
        revert_create_ssh_key
    elif [[ $1 = "Adding SSH Key to 'authorized_keys' file" ]]; then
        revert_add_to_authorized_key
    elif [[ $1 = "Securing 'authorized_keys' file" ]]; then
        revert_secure_authorized_key
    elif [[ $1 = "Enabling SSH-only login" ]]; then
        revert_ssh_only_login
    elif [[ $1 = "Changing urls in sources.list to defaults" ]]; then
        # This can be reverted back individually
        revert_source_list_changes
    elif [[ $1 = "Installing required softwares" ]]; then
        # This can be reverted back individually
        return 7
    elif [[ $1 = "Changing root password" ]]; then
        # CANNOT be reverted back
        # Just use your old password
        revert_root_pass_change
    fi
}

function revert_create_user(){
    # Remove user and 
    if [[ $(getent passwd "$NORM_USER_NAME" | wc -l) -gt 0 ]]; then
        deluser --remove-home "$NORM_USER_NAME"
    fi
}

function revert_create_ssh_key(){

    revert_create_user

    KEY_FILE_BKPS=("$SSH_DIR"/"$NORM_USER_NAME".pem*"$BACKUP_EXTENSION")

    if [[ ${#KEY_FILE_BKPS[@]} -gt 0 ]]; then
        unalias cp
        for key in "${KEY_FILE_BKPS[@]}"; do
            cp -rf "$key" "${key//$BACKUP_EXTENSION/}" || exit 1
        done
    fi
}

function revert_add_to_authorized_key(){
    revert_create_ssh_key

    if [[ -f "$SSH_DIR"/authorized_keys"$BACKUP_EXTENSION" ]]; then
        unalias cp
        chattr -i "$SSH_DIR"/authorized_keys
        #chmod 700 "$SSH_DIR"/authorized_keys
        cp -rf "$SSH_DIR"/authorized_keys"$BACKUP_EXTENSION" "$SSH_DIR"/authorized_keys
        chmod 400 "$SSH_DIR"/authorized_keys
        chattr +i "$SSH_DIR"/authorized_keys
    fi
}

function revert_secure_authorized_key(){
    revert_add_to_authorized_key
}

function revert_ssh_only_login(){
    revert_secure_authorized_key

    if [[ -f /etc/ssh/sshd_config"$BACKUP_EXTENSION" ]]; then
        unalias cp
        cp -rf /etc/ssh/sshd_config"$BACKUP_EXTENSION" /etc/ssh/sshd_config
    fi
}

function revert_source_list_changes(){
    if [[ -f /etc/apt/sources.list"${BACKUP_EXTENSION}" ]]; then
        unalias cp
        cp -rf /etc/apt/sources.list"${BACKUP_EXTENSION}" /etc/apt/sources.list
    fi

    SOURCE_FILES_BKP=(/etc/apt/source*/*.list"${BACKUP_EXTENSION}")
    if [[ ${#SOURCE_FILES_BKP[@]} -gt 0 ]]; then
        unalias cp
        for file in "${SOURCE_FILES[@]}";
        do
            cp -rf "$file" "${file//$BACKUP_EXTENSION/}" || exit 1
        done
    fi
}

function revert_root_pass_change(){
        # If root password changed - show the new root password
    true
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

    # If something failed - try to revert things back
    if [[ "$#" -gt 0 ]]; then
        # show - something failed - trying to restore required changes
        revert_changes "$1"

        # If restoration failed - well you are f**ked
    fi
}

function file_log(){
    printf "%s - %s\\n" "$(date '+%d-%b-%Y %H:%M:%S')" "$1" >> "$LOGFILE"
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
        finally "$EVENT"
    else
        printf "%30s %7s [${CRED}..${CEND}]" "$EVENT" " "
        file_log "${EVENT} - begin..."
    fi
}

# Reset previous log file
echo "Starting $0 - $(date '+%d-%b-%Y %H:%M:%S')" > "$LOGFILE"


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
    3 - Generate SSH keys on the server and store them at '~/.ssh'
    4 - Adds the public key from the above step to 
        '~/.ssh/authorized_keys' file
    5 - Restricts access to '~/.ssh' folder
    6 - Restricts login method to SSH-only by editing 
        '/etc/ssh/sshd_config' file to enable 
    7 - Restores the '/etc/apt/sources.list'
        (Most server provider alter these to serve software from 
        their CDNs)
    8 - Installs "sudo" "curl" "screen"
    9 - Display the following at the end
            a) root password (if changed)
            b) user name
            c) user password
            d) SSH Private Key
            e) SSH Public Key

Before editing any file, script creates a back up of that file with
in the same directory. If script detects any catastrophic error, then 
it restores the original files. Script assumes you are running this 
on a brand new VPS and that DATALOSS OR LOSS OF ACCESS TO THE SERVER 
IS NOT A MAJOR CONCERN. If you do however lose access to the server 
most VPS provider allow to create a new one easily.

All backup files have extension (${BACKUP_EXTENSION})
A log file can be found at ${LOGFILE}

TO CONTINUE (press enter/return)...
TO EXIT (ctrl + c)...
INFORM

read -r
clear


##############################################################
# Create non-root user
##############################################################

op_log "Creating new user"
{
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
# Create SSH Key for the above new user
##############################################################

op_log "Creating SSH Key for new user"
{
    shopt -s nullglob
    # TODO - Below would capture bak files as well - filter out the bak files
    KEY_FILES=("$SSH_DIR"/"$NORM_USER_NAME".pem*)

    # If SSH files already exist - rename them to .timestamp_bkp
    if [[ ${#KEY_FILES[@]} -gt 0 ]]; then
        for key in "${KEY_FILES[@]}"; do
            cp "$key" "$key""$BACKUP_EXTENSION" || exit 1
        done
    fi

    SSH_DIR=/home/"$NORM_USER_NAME"/.ssh
    mkdir "$SSH_DIR" || exit 1

    # Generate a 15 character random password for key
    KEY_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1
    file_log "Generated SSH Key Passphrase - ${KEY_PASS}"

    # Create a OpenSSH-compliant ed25519-type key
    ssh-keygen -a 1000 -o -t ed25519 -N "$KEY_PASS" -C "$NORM_USER_NAME" -f "$SSH_DIR"/"$NORM_USER_NAME".pem -q || exit 1

    # TODO - Below would capture bak files as well - filter out the bak files
    # See if the files actually got created
    KEY_FILES=("$SSH_DIR"/"$NORM_USER_NAME".pem*)
    if [[ ${#KEY_FILES[@]} -eq 0 ]]; then
        file_log "Unknown error occured."
        file_log "Could not create SSH key files."
        exit 1
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

op_log "Adding SSH Key to 'authorized_keys' file"
{
    # If 'authorized_keys' exists create backup
    # BACKUP_EXTENSION
    if [[ -e "$SSH_DIR"/authorized_keys ]]; then
        cp "$SSH_DIR"/authorized_keys "$SSH_DIR"/authorized_keys"$BACKUP_EXTENSION" || exit 1
    else
        # Create authorized_keys if it does not exist yet
        touch "$SSH_DIR"/authorized_keys || exit 1
    fi

    # Insert the public key into "authoried_keys" file
    cat "$SSH_DIR"/"$NORM_USER_NAME".pem.pub >> "$SSH_DIR"/authorized_keys || exit 1
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

op_log "Securing 'authorized_keys' file"
{
    # Set appropriate permissions for ".ssh" dir and "authorized_key" file
    chown -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chgrp -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chmod 700 "$SSH_DIR" && \
        chmod 400 "$SSH_DIR"/authorized_keys && \
        chattr +i "$SSH_DIR"/authorized_keys

    # Restrict access to the generated SSH Key files as well
    for key in "${KEY_FILES[@]}"; do
        chmod 400 "$key" && \
        chattr +i "$key"
    done
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

op_log "Enabling SSH-only login"
{
    # Backup the sshd_config file
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config"$BACKUP_EXTENSION" || exit 1

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

if [[ $DEFAULT_SOURCE_LIST = "y" ]]; then
    # Low priority - But what to do if it fails???
    op_log "Changing urls in sources.list to defaults"

    cp /etc/apt/sources.list /etc/apt/sources.list"${BACKUP_EXTENSION}" 2>> "$LOGFILE" >&2
    sed -i "1,$(wc -l < /etc/apt/sources.list) s/^/#/" /etc/apt/sources.list 2>> "$LOGFILE" >&2

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
            cp "$file" "$file""${BACKUP_EXTENSION}" 2>> "$LOGFILE" >&2
            sed -i "1,$(wc -l < "$file") s/^/#/" "$file" 2>> "$LOGFILE" >&2
        done
    fi

    # Comment out cloud-init generated templates for sources
    # CLOUD_INIT_FILES=(/etc/cloud/templates*/*.tmpl) 2>> "$LOGFILE" >&2
    # if [[ ${#CLOUD_INIT_FILES[@]} -gt 0 ]]; then
    #     for file in "${CLOUD_INIT_FILES[@]}";
    #     do
    #         cp "$file" "$file""${BACKUP_EXTENSION}" 2>> "$LOGFILE" >&2
    #         sed -i "1,$(wc -l < "$file") s/^/#/" "$file" 2>> "$LOGFILE" >&2
    #     done
    # fi

    if [[ $? -eq 0 ]]; then
        op_log "Changing urls in sources.list to defaults" "FAILED"
    else
        op_log "Changing urls in sources.list to defaults" "FAILED"
    fi
fi



##############################################################
# Install required softwares
##############################################################

op_log "Installing required softwares"
{
    apt-get update && apt-get upgrade -y && apt-get install -y sudo curl screen
} 2>> "$LOGFILE" >&2

if [[ $? -eq 0 ]]; then
    op_log "Installing required softwares" "FAILED"
else
    op_log "Installing required softwares" "FAILED"
fi


##############################################################
# Change root's password
##############################################################

if [[ $RESET_ROOT_PWD == 'y' ]]; then
    op_log "    "
    {
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
# Recap
##############################################################

finally