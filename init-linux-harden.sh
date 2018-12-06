#!/etc/bin/env bash


# Add the user to "sudo"
#   Display the private-key on the screen and ask the user 2times to copy it
# Install sudo curl screen
# Restart systemctl restart ssh
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
# Something important fails
    # Revert everything back to how it was
# Accept user name as a script argument
    # If no username provided
        # generate a random username - all lowercase
# What to do if making .bkp file fails?

declare SESSION_TYPE=""

##############################################################
# Change root's password
##############################################################

# Check if the user connected through SSH
if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
    SESSION_TYPE=remote/ssh
else
    case $(ps -o comm= -p $PPID) in
        sshd|*/sshd)
            SESSION_TYPE=remote/ssh;
    esac
fi

if [ $SESSION_TYPE == "remote/ssh" ]; then
    printf "You are currently connected to an SSH session.\n"
else
    printf "You are currently connected using password authentication.\n"
fi

{
    # Generate a 15 character random password
    PASS_ROOT="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1

    # Change root's password
    echo -e "${PASS_ROOT}\n${PASS_ROOT}" | passwd > /dev/null
}

if [[ $? -eq 0 ]]; then
    printf "Successully changed root password.\n"
else
    printf "Could not reset root password.\n"
    exit 1
fi


##############################################################
# Change default source-list
##############################################################
if [[ $(sed 's/\..*//' /etc/debian_version) -eq 8 ]]; then
    DEB_VER_STR="jessie"
elif [[ $(sed 's/\..*//' /etc/debian_version) -eq 9 ]]; then
    DEB_VER_STR="stretch"
else
    printf "This version of Debian is NOT supported.\n"
    exit 1
fi

mv /etc/apt/sources.list /etc/apt/sources.list.bak
sed -i "1,$(wc -l < /etc/apt/sources.list.bak) s/^/#/" /etc/apt/sources.list.bak

# Find any additional sources listed by the provider and comment them out
if [[ $(ls -fL /etc/apt/source*/*.list | wc -l ) -gt 0 ]]; then
    for file in /etc/apt/source*/*.list;
    do
        mv "$file" "$file".bak
        sed -i "1,$(wc -l < "$file") s/^/#/" "$file" >&2 /dev/null
    done
fi

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

# Comment out cloud-init generated templates for sources
if [[ $(ls -fL /etc/cloud/templates*/*.tmpl | wc -l ) -gt 0 ]]; then
    for file in /etc/cloud/templates*/*.tmpl;
    do
        mv "$file" "$file".bak
        sed -i "1,$(wc -l < "$file") s/^/#/" "$file" >&2 /dev/null
    done
fi

if [[ $? -eq 0 ]]; then
    printf "Successfully updated the source list.\n"
else
    printf "Updating source list failed.\n"
fi


##############################################################
# Create a normal user
##############################################################
{
    clear
    # Ask for a user name
    read -rp "Please provide a user name - " NORM_USER_NAME

    # If the user exists - ask for a different username
    while [ $(getent passwd "$NORM_USER_NAME" | wc -l) -gt 0 ]; do
        echo "${NORM_USER_NAME} already exists."
        read -rp "Please provide another user name - " NORM_USER_NAME
    done

    # Generate a 15 character random password
    USER_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1

    # Create the user and assign the above password
    echo -e "${USER_PASS}\n${USER_PASS}" | adduser "$NORM_USER_NAME" -q --gecos "First Last,RoomNumber,WorkPhone,HomePhone" 2> /dev/null

    # Give root privilages to the above user
    usermod -aG sudo "$NORM_USER_NAME" || exit 1
}

if [[ $? -eq 0 ]]; then
    printf "Successfully created new user %s.\n" "$NORM_USER_NAME"
else
    printf "Creating new user failed.\n"
    exit 1;
fi


##############################################################
# Create SSH Key for the new user created
##############################################################

{
    SSH_DIR=/home/"$NORM_USER_NAME"/.ssh
    mkdir "$SSH_DIR" || exit 1

    # Generate a 15 character random password for key
    KEY_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1

    # Create a OpenSSH-compliant ed25519-type key
    ssh-keygen -a 1000 -o -t ed25519 -N "$KEY_PASS" -C "$NORM_USER_NAME" -f "$SSH_DIR"/"$NORM_USER_NAME".pem -q || exit 1

    # Insert the public key into "authoried_keys" file
    cat "$SSH_DIR"/"$NORM_USER_NAME".pem.pub >> "$SSH_DIR"/authorized_keys || exit 1

    # Set appropriate permissions for ".ssh" dir and "authorized_key" file
    chown -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chgrp -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chmod 700 "$SSH_DIR" && \
        chmod 400 "$SSH_DIR"/authorized_keys && \
        chattr +i "$SSH_DIR"/authorized_keys
}
if [[ $? -eq 0 ]]; then
    printf "Successfully created SSH keys.\n%s" "${SSH_DIR}/${NORM_USER_NAME}".pem
else
    printf "Creating SSH key failed.\n"
    exit 1;
fi


##############################################################
# Enable SSH-only login
##############################################################

# Backup the sshd_config file
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak || exit 1

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

# Remove root login
set_config_key "/etc/ssh/sshd_config" "PermitRootLogin" "no"

# Disable password login
set_config_key "/etc/ssh/sshd_config" "PasswordAuthentication" "no"

# Set SSH Authorization-Keys path
set_config_key "/etc/ssh/sshd_config" "AuthorizedKeysFile" '%h\/\.ssh\/authorized_keys'


##############################################################
# Enable SSH-only login
##############################################################

systemctl restart sshd

