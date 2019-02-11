#!/etc/bin/env bash

SCRIPT_NAME=linux_init_harden
SCRIPT_VERSION=0.9

LOGFILE=/tmp/"$SCRIPT_NAME"_v"$SCRIPT_VERSION".log
# Reset previous log file
TS=$(date '+%d_%m_%Y-%H_%M_%S')
echo "Starting $0 - $TS" > "$LOGFILE"
BACKUP_EXTENSION='.'$TS"_bak"

# Colors
CSI='\033['
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"


##############################################################
# Usage
##############################################################
# Script takes arguments as follows
# server_init_harden -username pratik --resetrootpwd
# server_init_harden -u pratik --resetrootpwd
# server_init_harden -username pratik --resetrootpwd -q

function usage() {
    if [ -n "$1" ]; then
        echo ""
        echo -e "${CRED}$1${CEND}\n"
    fi

    echo "Usage: sudo bash $0 [-u|--username username] [-r|--resetrootpwd] [--defaultsourcelist]"
    echo "  -u, --username            Username for your server (If omitted script will choose an username for you)"
    echo "  -r, --resetrootpwd        Reset current root password"
    echo "  -d, --defaultsourcelist   Updates /etc/apt/sources.list to download software from debian.org."
    echo "                            NOTE - If you fail to update system after using it, you need to manually reset it. This script keeps a backup in the same folder."

    echo ""
    echo "Example: bash ./$SCRIPT_NAME.sh --username myuseraccount --resetrootpwd"
    printf "\\nBelow restrictions apply to username this script accepts - \\n"
    printf "%2s - [a-zA-Z0-9] [-] [_] are allowed\\n%2s - NO special characters.\\n%2s - NO spaces.\\n" " " " " " "
}


##############################################################
# Basic checks before starting
##############################################################

# No root - no good
[ "$(id -u)" != "0" ] && {
    usage "ERROR: You must be root to run this script.\\nPlease login as root and execute the script again."
    exit 1
}

# Check supported OSes
if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
fi

case "$OS" in
    debian)
        if [[ "$VER" -eq 8 ]]; then
            DEB_VER_STR="jessie"
        elif [[ "$VER" -eq 9 ]]; then
            DEB_VER_STR="stretch"
        else
            printf "This script only supports Debian 8 and Debian 9\\n"
            printf "\\tUbuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10\\n"
            printf "Your OS is NOT supported.\\n"
            exit 1
        fi
        ;;
    ubuntu)
        if [[ "$VER" = "14.04" ]]; then
            UBT_VER_STR="trusty"
        elif [[ "$VER" = "16.04" ]]; then
            UBT_VER_STR="xenial"
        elif [[ "$VER" = "18.04" ]]; then
            UBT_VER_STR="bionic"
        elif [[ "$VER" = "18.10" ]]; then
            UBT_VER_STR="cosmic"
        else
            printf "This script only supports Debian 8 and Debian 9\\n"
            printf "\\tUbuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10\\n"
            printf "Your OS is NOT supported.\\n"
            exit 1
        fi
        ;;
    *)
        printf "This script only supports Debian 8 and Debian 9\\n"
        printf "\\tUbuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10\\n"
        printf "Your OS is NOT supported.\\n"
        exit 1
        ;;
esac


##################################
# Parse script arguments
##################################

# defaults
AUTO_GEN_USERNAME="y"
RESET_ROOT_PWD="n"
DEFAULT_SOURCE_LIST="n"
QUIET="n"

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
        -q|--quiet|--nowait|--noprompt)
            QUIET="y"
            shift
            ;;
        -h|--help)
            echo
            usage
            echo
            exit 0
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
# Display what the script does
##############################################################

clear

cat <<INFORM | more
         !!! READ BELOW & PRESS ENTER/RETURN TO CONTINUE !!!
##################################################################

- Before editing any file, script creates a back up of that file in
  the same directory. If script detects any error, then it restores the 
  original files.
- If any operation which involves credentials generation, succeeds - 
  then those credentials will be displayed at the end of all operations.
- If script reports any error or something does not work as expected,
  please take a look at the log file at (${LOGFILE}).
- Operations are NOT idempotent

All backup files have extension (${BACKUP_EXTENSION})
Script logs all operation into (${LOGFILE}) file.

##################################################################

INFORM

echo "Installation options selected - " | tee -a "$LOGFILE"
if [[ "$AUTO_GEN_USERNAME" == "y" ]]; then
    printf "%3s Username will be auto generated by script\\n" " -" | tee -a "$LOGFILE"
else
    printf "%3s Username you opted = %s\\n" " -" "$NORM_USER_NAME" | tee -a "$LOGFILE"
fi
if [[ "$DEFAULT_SOURCE_LIST" == "y" ]]; then
    printf "%3s Reset the url for apt repo from VPS provided CDN to OS provided ones\\n" " -" | tee -a "$LOGFILE"
fi
if [[ "$RESET_ROOT_PWD" == "y" ]]; then
    printf "%3s Reset root password\\n" " -" | tee -a "$LOGFILE"
fi
if [[ "$QUIET" == "y" ]]; then
    printf "%3s No prompt installation selected\\n\\n" " -" | tee -a "$LOGFILE"
fi

echo
echo "TO CONTINUE (press enter/return)..."
echo "TO EXIT (ctrl + c)..."
echo

if [[ $QUIET == "n" ]]; then
    read -r
    clear
fi


##############################################################
# Error Handling
##############################################################

OP_CODE=0
# keep state of the script
# Each step has 3 states
    # 0 - not executed
    # 1 - Started
    # 2 - Completed
    # 3 - Failed
CreateNonRootUser=0
CreateSSHKey=0
SecureAuthkeysfile=0
EnableSSHOnly=0
ChangeSourceList=0
InstallReqSoftwares=0
ConfigureUFW=0
ConfigureFail2Ban=0
ChangeRootPwd=0

function set_op_code() {
    if [[ $OP_CODE -eq 0 ]] && [[ $1 -gt 0 ]]; then
        OP_CODE=$1
    fi
}

function reset_op_code(){
    OP_CODE=0
}

function service_action_and_chk_error() {
    local servicename=$1
    local serviceaction=$2
    local servicemsg

    servicemsg=$(service "$servicename" "$serviceaction" 2>&1)
    file_log "$servicemsg"
    return $(echo "$servicemsg" | grep -c 'ERROR')
}

function get_event_var_from_event() {
    case $1 in
        "${OP_TEXT[0]}")
            echo "CreateNonRootUser"
            ;;
        "${OP_TEXT[1]}")
            echo "CreateSSHKey"
            ;;
        "${OP_TEXT[2]}")
            echo "SecureAuthkeysfile"
            ;;
        "${OP_TEXT[3]}")
            echo "EnableSSHOnly"
            ;;
        "${OP_TEXT[4]}")
            echo "ChangeSourceList"
            ;;
        "${OP_TEXT[5]}")
            echo "InstallReqSoftwares"
            ;;
        "${OP_TEXT[6]}")
            echo "ConfigureUFW"
            ;;
        "${OP_TEXT[7]}")
            echo "ConfigureFail2Ban"
            ;;
        "${OP_TEXT[8]}")
            echo "ChangeRootPwd"
            ;;
        *)
            false
            ;;
    esac
}

function update_event_status() {
    local event
    event=$(get_event_var_from_event "$1")
    eval "$event"="$2"
}

function get_event_status() {
    local event=get_event_var_from_event "$1"
    return ${!event}
}

function revert_changes(){
    file_log "Starting revert operation..."

    if [[ $1 = "${OP_TEXT[0]}" ]]; then
        revert_create_user
    elif [[ $1 = "${OP_TEXT[1]}" ]]; then
        revert_create_ssh_key
    elif [[ $1 = "${OP_TEXT[2]}" ]]; then
        revert_secure_authorized_key
    elif [[ $1 = "${OP_TEXT[3]}" ]]; then
        revert_ssh_only_login
    elif [[ $1 = "${OP_TEXT[4]}" ]]; then
        # This can be reverted back individually
        revert_source_list_changes
    elif [[ $1 = "${OP_TEXT[5]}" ]]; then
        # This can be reverted back individually
        return 7
    fi
}

function error_restoring(){
    op_log "$1" "FAILED"
    file_log "$1 - Failed"
    echo
    center_err_text "!!! Error restoring changes !!!"
    center_err_text "!!! You may have to manually fix this !!!"
    center_err_text "!!! Check the log file for details !!!"
    center_reg_text "Log file at ${LOGFILE}"
    echo
}

function revert_create_user(){
    file_log "Reverting New User Creation..."

    # Remove user and its home directory only if user was created
    if [[ $(getent passwd "$NORM_USER_NAME" | wc -l) -gt 0 ]]; then
        {
            file_log "Deleting user ${NORM_USER_NAME} ..."
            deluser "$NORM_USER_NAME"

            file_log "Deleting user ${NORM_USER_NAME} home directory and all its content ..."
            rm -rf /home/"${NORM_USER_NAME:?}"
            set_op_code $?
        } 2>> "$LOGFILE" >&2
        set_op_code $?
    fi

    if [[ $OP_CODE -eq 0 ]]; then
        op_rev_log "Reverting - New User Creation" "SUCCESSFUL"
    else
        error_restoring "Reverting - New User Creation"
    fi

    reset_op_code
}

function revert_create_ssh_key(){
    file_log "Reverting SSH Key Generation..."
    revert_create_user
    set_op_code $?

    # Since all SSH files are created inside the user's home directory
        # There is nothing to revert if username is deleted

    if [[ $OP_CODE -eq 0 ]]; then
        op_rev_log "Reverting - SSH Key Generation" "SUCCESSFUL"
    else
        error_restoring "Reverting - SSH Key Generation"
    fi

    reset_op_code
}

function revert_secure_authorized_key(){
    file_log "Reverting SSH Key Authorizations..."

    if [[ -f "$SSH_DIR"/authorized_keys ]]; then
        {
            file_log "Removing the immutable flag from every file in /home/${NORM_USER_NAME}/.ssh/ directory ..."
            chattr -i "$SSH_DIR"/*
            set_op_code $?

            # Nothing else to restore since we are going to delete the user & its directories anyways
            # All the files created/changed by the script are inside /home/[username]/.ssh directory only
        } 2>> "$LOGFILE" >&2
    fi

    # Can remove the user only AFTER immutable attributes on authorized_keys is removed
    revert_create_ssh_key

    if [[ $OP_CODE -eq 0 ]]; then
        op_rev_log "Reverting - SSH Key Authorization" "SUCCESSFUL"
    else
        error_restoring "Reverting - SSH Key Authorization"
    fi

    reset_op_code
}

function revert_source_list_changes(){
    file_log "Reverting Source_list Changes..."

    unalias cp &>/dev/null

    if [[ -f /etc/apt/sources.list"${BACKUP_EXTENSION}" ]]; then
        file_log "Restoring /etc/apt/sources.list${BACKUP_EXTENSION} into /etc/apt/sources.list ..."
        cp -rf /etc/apt/sources.list"${BACKUP_EXTENSION}" /etc/apt/sources.list 2>> "$LOGFILE" >&2
        set_op_code $?
    fi

    SOURCE_FILES_BKP=(/etc/apt/source*/*.list"$BACKUP_EXTENSION")
    if [[ ${#SOURCE_FILES_BKP[@]} -gt 0 ]]; then
        for file in "${SOURCE_FILES_BKP[@]}";
        do
            file_log "Restoring ${file} into ${file//$BACKUP_EXTENSION/} ..."
            cp -rf "$file" "${file//$BACKUP_EXTENSION/}" 2>> "$LOGFILE" >&2
            set_op_code $?
        done
    fi

    if [[ $OP_CODE -eq 0 ]]; then
        op_rev_log "Reverting - Source_list Changes" "SUCCESSFUL"
    else
        error_restoring "Reverting - Source_list Changes"
    fi

    reset_op_code
}

function revert_root_pass_change(){
    echo
    center_err_text "Changing root password failed..."
    center_err_text "Your earlier root password remains VALID"
    center_err_text "Script will continue to next step"
}

function revert_config_UFW(){
    file_log "Reverting UFW Configuration..."

    ufw disable 2>> "$LOGFILE" >&2
    set_op_code $?

    if [[ $OP_CODE -eq 0 ]]; then
        op_rev_log "Reverting - UFW Configuration" "SUCCESSFUL"
    else
        error_restoring "Reverting - UFW Configuration"
    fi

    reset_op_code
}

function revert_config_fail2ban(){
    file_log "Reverting Fail2ban Config..."

    unalias cp &>/dev/null

    if [[ -f /etc/fail2ban/jail.local"$BACKUP_EXTENSION" ]]; then
        # If /etc/fail2ban/jail.local/_bkp exists then this is NOT the 1st time script is run
        # So, you would probaly want to get the last existing jail.local file back
        file_log "Restoring /etc/fail2ban/jail.local${BACKUP_EXTENSION} into /etc/fail2ban/jail.local"
        cp -rf /etc/fail2ban/jail.local"$BACKUP_EXTENSION" /etc/fail2ban/jail.local 2>> "$LOGFILE" >&2
        set_op_code $?
    else
        # If /etc/fail2ban/jail.local/_bkp does NOT exists then this IS the 1st time script is run
        # You probably do NOT want the jail.local > which might be corrupted > which is why you are here
        file_log "Removing /etc/fail2ban/jail.local as that might have been the culprit in this failure"
        rm /etc/fail2ban/jail.local 2>> "$LOGFILE" >&2
        set_op_code $?
    fi

    if [[ -f /etc/fail2ban/jail.d/defaults-debian.conf"$BACKUP_EXTENSION" ]]; then
        file_log "Restoring /etc/fail2ban/jail.d/defaults-debian.conf${BACKUP_EXTENSION} into /etc/fail2ban/jail.d/defaults-debian.conf"
        cp -rf /etc/fail2ban/jail.d/defaults-debian.conf"$BACKUP_EXTENSION" /etc/fail2ban/jail.d/defaults-debian.conf 2>> "$LOGFILE" >&2
        set_op_code $?
    fi

    file_log "Stopping fail2ban service ..."
    {
        set_op_code $(service_action_and_chk_error "fail2ban" "stop")
    } 2>> "$LOGFILE" >&2

    if [[ $OP_CODE -eq 0 ]]; then
        op_rev_log "Reverting - Fail2ban Config" "SUCCESSFUL"
    else
        error_restoring "Reverting - Fail2ban Config"
    fi

    reset_op_code
}

revert_software_installs(){
    echo
    center_err_text "Error while installing softwares"
    center_err_text "This may be a false-alarm"
    center_err_text "Script will continue to next step"
    file_log "Installing software failed..."
    file_log "This is NOT a catastrophic error"
}

function revert_ssh_only_login(){
    revert_secure_authorized_key
    if [[ $DEFAULT_SOURCE_LIST = "y" ]]; then
        revert_source_list_changes
    fi
    revert_config_UFW
    revert_config_fail2ban


    file_log "Reverting SSH-only Login..."

    if [[ -f /etc/ssh/sshd_config"$BACKUP_EXTENSION" ]]; then
        unalias cp &>/dev/null

        file_log "Restoring /etc/ssh/sshd_config${BACKUP_EXTENSION} into /etc/ssh/sshd_config ..."
        cp -rf /etc/ssh/sshd_config"$BACKUP_EXTENSION" /etc/ssh/sshd_config 2>> "$LOGFILE" >&2
        set_op_code $?
    fi

    file_log "Restarting ssh service ..."
    {
        set_op_code $(service_action_and_chk_error "sshd" "restart")

        if [[ $OP_CODE -eq 0 ]]; then
            false
        fi
    } || { 
            # Because Ubuntu 14.04 does not have sshd
            set_op_code $(service_action_and_chk_error "ssh" "restart")
        } 2>> "$LOGFILE" >&2

    if [[ $OP_CODE -eq 0 ]]; then
        op_rev_log "Reverting - SSH-only Login" "SUCCESSFUL"
    else
        error_restoring "Reverting - SSH-only Login"
    fi
}

function finally(){
    if [[ $CreateNonRootUser -eq 2 ]] && 
        [[ $CreateSSHKey -eq 2 ]] && 
        [[ $SecureAuthkeysfile -eq 2 ]] && 
        [[ $EnableSSHOnly -eq 2 ]] &&
        [[ $ChangeSourceList -eq 2 ]] &&
        [[ $InstallReqSoftwares -eq 2 ]]; then
        echo
        line_fill "$CHORIZONTAL" "$CLINESIZE"
        line_fill "$CHORIZONTAL" "$CLINESIZE"
        center_reg_text "ALL OPERATIONS COMPLETED SUCCESSFULLY"
    fi

    # If something failed - try to revert things back
    if [[ "$#" -gt 0 ]]; then
        echo
        center_err_text "!!! ERROR OCCURED DURING OPERATION !!!"
        center_err_text "!!! Reverting changes !!!"
        center_err_text "Please look at $LOGFILE for details"
        echo
        revert_changes "$1"

        # If restoration failed - well you are f**ked
    fi
    
    #Recap ONLY if NO IMPORTANT operations reverted
    if [[ $CreateNonRootUser -eq 3 ]] || 
        [[ $CreateSSHKey -eq 3 ]] || 
        [[ $SecureAuthkeysfile -eq 3 ]] || 
        [[ $EnableSSHOnly -eq 3 ]]; then
        return 1
    else
        line_fill "$CHORIZONTAL" "$CLINESIZE"
        recap "User Name" "$CreateNonRootUser" "$NORM_USER_NAME"
        recap "User's Password" "$CreateNonRootUser" "$USER_PASS"
        recap "SSH Private Key File" "$CreateSSHKey" "$SSH_DIR"/"$NORM_USER_NAME".pem
        recap "SSH Public Key File" "$CreateSSHKey" "$SSH_DIR"/"$NORM_USER_NAME".pem.pub
        recap "SSH Key Passphrase" "$CreateSSHKey" "$KEY_PASS"    
        if [[ "$RESET_ROOT_PWD" == "y" ]]; then
            recap "New root Password" "$ChangeRootPwd" "$PASS_ROOT"
        fi
        line_fill "$CHORIZONTAL" "$CLINESIZE"

        recap_file_content "SSH Private Key" "$SSH_DIR"/"$NORM_USER_NAME".pem
        recap_file_content "SSH Public Key" "$SSH_DIR"/"$NORM_USER_NAME".pem.pub
        
        line_fill "$CHORIZONTAL" "$CLINESIZE"
        center_reg_text "!!! DO NOT LOG OUT JUST YET !!!"
        center_reg_text "Use another window to test out the above credentials"
        center_reg_text "If you face issue logging in look at the log file to see what went wrong"
        center_reg_text "Log file at ${LOGFILE}"

        line_fill "$CHORIZONTAL" "$CLINESIZE"
        echo
    fi

    if [[ $ChangeSourceList -eq 3 ]] ||
       [[ $InstallReqSoftwares -eq 3 ]] ||
       [[ $ChangeRootPwd -eq 3 ]]; then
        center_err_text "Some operations failed..."
        center_err_text "These may NOT be catastrophic"
        center_err_text "Please look at $LOGFILE for details"
        revert_changes "$1"
        echo
    fi
}


##############################################################
# Log
##############################################################

CVERTICAL="|"
CHORIZONTAL="_"
CLINESIZE=72

function center_text(){
  textsize=${#1}
  width=$2
  span=$((($width + $textsize) / 2))
  printf "%${span}s" "$1"
}

function center_err_text(){
    printf "${CRED}"
    center_text "$1" "$CLINESIZE"
    printf "${CEND}\\n"
}

function center_reg_text(){
    center_text "$1" $CLINESIZE
    printf "\\n"
}

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

function file_log(){
    printf "%s - %s\\n" "$(date '+%d-%b-%Y %H:%M:%S')" "$1" >> "$LOGFILE"
}

function op_log() {
    local EVENT=$1
    local RESULT=$2

    if [[ "$RESULT" = "SUCCESSFUL" ]]; then
        printf "\r%33s %7s [${CGREEN}${RESULT}${CEND}]\\n" "$EVENT" " "
        file_log "${EVENT} - ${RESULT}"
    elif [[ "$RESULT" = "FAILED" ]]; then
        printf "\r%33s %7s [${CRED}${RESULT}${CEND}]\\n" "$EVENT" " "
        file_log "${EVENT} - ${RESULT}"
    elif [[ "$RESULT" = "NO-OP" ]]; then
        printf "\r%33s %7s [${RESULT}]\\n" "$EVENT" " "
        file_log "${EVENT} - No operation done. Check above for details..."
    else
        printf "%33s %7s [${CRED}..${CEND}]" "$EVENT" " "
        file_log "${EVENT} - begin..."
    fi
}

function op_rev_log(){
    printf "${CRED}"
    op_log "$1" "$2"
    printf "${CEND}"
}

function recap (){
    local purpose=$1
    local status=$2
    local value=$3

    if [[ $status -eq 0 ]]; then
        file_log "${purpose}: Did not start this operation. See log above."
        value="[${CGREEN}--NO_OP--${CEND}]"
    elif [[ $status -eq 2 ]]; then
        file_log "${purpose}: ${value}"
        value="[${CGREEN}${value}${CEND}]"
    elif [[ $status -eq 1 ]] || [[ $status -eq 3 ]]; then
        file_log "${purpose}: ERROR. See log above."
        value="${CRED}--ERROR--${CEND}"
    fi

    horizontal_fill "$CVERTICAL" 1
    printf "%23s:%3s%-54s" "$purpose" " " "$(echo -e "$value")"
    line_fill "$CVERTICAL" 1
}

function recap_file_content(){
    local file_type=$1
    local file_location=$2
    echo

    center_reg_text "$file_type"
    file_log "$file_type"
    echo
    printf "${CGREEN}"
    cat "$file_location"
    cat "$file_location" 2>> "$LOGFILE" >&2
    printf "${CEND}"
}

OP_TEXT=(
    "Creating new user" #0
    "Creating SSH Key for new user" #1
    "Securing 'authorized_keys' file" #2
    "Enabling SSH-only login" #3
    "Reset sources.list to defaults" #4
    "Installing required softwares" #5
    "Configure UFW" #6
    "Configure Fail2Ban" #7
    "Changing root password" #8
)


##############################################################
# Step 1 - Create non-root user
##############################################################

reset_op_code
update_event_status "${OP_TEXT[0]}" 1
op_log "${OP_TEXT[0]}"
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
    set_op_code $?

    # Give root privilages to the above user
    usermod -aG sudo "$NORM_USER_NAME"
    set_op_code $?
} 2>> "$LOGFILE" >&2

if [[ $OP_CODE -eq 0 ]]; then
    update_event_status "${OP_TEXT[0]}" 2
    op_log "${OP_TEXT[0]}" "SUCCESSFUL"
else
    reset_op_code
    update_event_status "${OP_TEXT[0]}" 3
    op_log "${OP_TEXT[0]}" "FAILED"
    finally "${OP_TEXT[0]}"
    exit 1;
fi


##############################################################
# Step 2 - Create SSH Key for the above new user
##############################################################

reset_op_code
update_event_status "${OP_TEXT[1]}" 1
op_log "${OP_TEXT[1]}"
{
    SSH_DIR=/home/"$NORM_USER_NAME"/.ssh
    file_log "Creating SSH directory - $SSH_DIR"
    mkdir "$SSH_DIR"
    set_op_code $?

    # Generate a 15 character random password for key
    file_log "Generating SSH Key Passphrase - ${KEY_PASS}"
    KEY_PASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)"
    set_op_code $?

    # Create a OpenSSH-compliant ed25519-type key
    file_log "Generating SSH Key File - $SSH_DIR/$NORM_USER_NAME.pem"
    ssh-keygen -a 1000 -o -t ed25519 -N "$KEY_PASS" -C "$NORM_USER_NAME" -f "$SSH_DIR"/"$NORM_USER_NAME".pem -q
    set_op_code $?

    # Copy the generated public file to authorized_keys
    cat "$SSH_DIR"/"$NORM_USER_NAME".pem.pub >> "$SSH_DIR"/authorized_keys
    set_op_code $?
} 2>> "$LOGFILE" >&2

if [[ $OP_CODE -eq 0 ]]; then
    update_event_status "${OP_TEXT[1]}" 2
    op_log "${OP_TEXT[1]}" "SUCCESSFUL"
else
    reset_op_code
    file_log "Creating SSH Key for new user failed."
    update_event_status "${OP_TEXT[1]}" 3
    op_log "${OP_TEXT[1]}" "FAILED"
    finally "${OP_TEXT[1]}"
    exit 1;
fi


##############################################################
# Step 3 - Secure authorized_keys file
##############################################################

reset_op_code
update_event_status "${OP_TEXT[2]}" 1
op_log "${OP_TEXT[2]}"
{
    # Set appropriate permissions for ".ssh" dir and "authorized_key" file
    file_log "Setting appropriate permissions for $SSH_DIR dir and $SSH_DIR/authorized_keys file"
    chown -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chgrp -R "$NORM_USER_NAME" "$SSH_DIR" && \
        chmod 700 "$SSH_DIR" && \
        chmod 400 "$SSH_DIR"/authorized_keys && \
        chattr +i "$SSH_DIR"/authorized_keys
    set_op_code $?

    # Restrict access to the generated SSH Key files as well
    shopt -s nullglob
    KEY_FILES=("$SSH_DIR"/"$NORM_USER_NAME".pem*)
    for key in "${KEY_FILES[@]}"; do
        file_log "Restricting access (chmod 400 and chattr +i) to ${key} file"
        chmod 400 "$key" && \
            chattr +i "$key"
        set_op_code $?
    done
} 2>> "$LOGFILE" >&2

if [[ $OP_CODE -eq 0 ]]; then
    update_event_status "${OP_TEXT[2]}" 2
    op_log "${OP_TEXT[2]}" "SUCCESSFUL"
else
    reset_op_code
    file_log "Setting restrictive permissions for '~/.ssh/' directory failed"
    file_log "Please do 'ls -lAh ~/.ssh/' and check manually to see what went wrong."
    update_event_status "${OP_TEXT[2]}" 3
    op_log "${OP_TEXT[2]}" "FAILED"
    finally "${OP_TEXT[2]}"
    exit 1
fi


##############################################################
# Step 4 - Change default source-list
##############################################################

if [[ $DEFAULT_SOURCE_LIST = "y" ]]; then
    # Low priority - But what to do if it fails???
    reset_op_code
    update_event_status "${OP_TEXT[5]}" 1
    op_log "${OP_TEXT[4]}"
    {
        file_log "Backing up /etc/apt/sources.list file to /etc/apt/sources.list${BACKUP_EXTENSION}"
        cp /etc/apt/sources.list /etc/apt/sources.list"${BACKUP_EXTENSION}"
        set_op_code $?

        file_log "Commenting out everthing in /etc/apt/sources.list"
        sed -i "1,$(wc -l < /etc/apt/sources.list) s/^/#/" /etc/apt/sources.list
        set_op_code $?

        if [[ $OS = "debian" ]]; then

            file_log "Adding default CDN sources to /etc/apt/sources.list"

# Default sources list for debian
cat <<DEBIAN >> /etc/apt/sources.list
deb http://deb.debian.org/debian ${DEB_VER_STR} main contrib non-free
deb-src http://deb.debian.org/debian ${DEB_VER_STR} main contrib non-free

## Major bug fix updates produced after the final release of the
## distribution.
deb http://security.debian.org ${DEB_VER_STR}/updates main contrib non-free
deb-src http://security.debian.org ${DEB_VER_STR}/updates main contrib non-free

deb http://deb.debian.org/debian ${DEB_VER_STR}-updates main contrib non-free
deb-src http://deb.debian.org/debian ${DEB_VER_STR}-updates main contrib non-free

deb http://deb.debian.org/debian ${DEB_VER_STR}-backports main contrib non-free
deb-src http://deb.debian.org/debian ${DEB_VER_STR}-backports main contrib non-free
DEBIAN
            set_op_code $?
        
        elif [[ $OS = "ubuntu" ]]; then

cat <<UBUNTU >> /etc/apt/sources.list
deb http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR} main restricted
deb-src http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR} main restricted

deb http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR}-updates main restricted
deb-src http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR}-updates main restricted

deb http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR} universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR} universe multiverse
deb http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR}-updates universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR}-updates universe multiverse

deb http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR}-backports main restricted universe multiverse
deb-src http://archive.ubuntu.com/ubuntu/ ${UBT_VER_STR}-backports main restricted universe multiverse

deb http://security.ubuntu.com/ubuntu ${UBT_VER_STR}-security main restricted
deb-src http://security.ubuntu.com/ubuntu ${UBT_VER_STR}-security main restricted
deb http://security.ubuntu.com/ubuntu ${UBT_VER_STR}-security universe
deb-src http://security.ubuntu.com/ubuntu ${UBT_VER_STR}-security universe
deb http://security.ubuntu.com/ubuntu ${UBT_VER_STR}-security multiverse
deb-src http://security.ubuntu.com/ubuntu ${UBT_VER_STR}-security multiverse
UBUNTU
            set_op_code $?
        fi

        # Find any additional sources listed by the provider and comment them out
        SOURCE_FILES=(/etc/apt/source*/*.list)
        if [[ ${#SOURCE_FILES[@]} -gt 0 ]]; then
            for file in "${SOURCE_FILES[@]}";
            do
                file_log "Backing up ${file} file to ${file}${BACKUP_EXTENSION}"
                cp "$file" "$file""${BACKUP_EXTENSION}"
                set_op_code $?

                file_log "Commenting out the ${file}"
                sed -i "1,$(wc -l < "$file") s/^/#/" "$file"
                set_op_code $?
            done
        fi
    } 2>> "$LOGFILE" >&2

    if [[ $OP_CODE -eq 0 ]]; then
        update_event_status "${OP_TEXT[4]}" 2
        op_log "${OP_TEXT[4]}" "SUCCESSFUL"
    else
        reset_op_code
        update_event_status "${OP_TEXT[4]}" 3
        op_log "${OP_TEXT[4]}" "FAILED"
        revert_source_list_changes
    fi
fi


##############################################################
# Step 5 - Install required softwares
##############################################################

reset_op_code
update_event_status "${OP_TEXT[5]}" 1
op_log "${OP_TEXT[5]}"
{
    apt-get update
    export DEBIAN_FRONTEND=noninteractive ; apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
    apt-get install -y sudo curl screen ufw fail2ban
    set_op_code $?
} 2>> "$LOGFILE" >&2

if [[ $OP_CODE -eq 0 ]]; then
    update_event_status "${OP_TEXT[5]}" 2
    op_log "${OP_TEXT[5]}" "SUCCESSFUL"
else
    reset_op_code
    update_event_status "${OP_TEXT[5]}" 3
    op_log "${OP_TEXT[5]}" "FAILED"
    revert_software_installs
fi


##############################################################
# Step 6 - Configure UFW
##############################################################

# Check if UFW is installed
ufw status 2>> /dev/null >&2 

# Proceed only when UFW is installed
if [[ $? -eq 0 ]]; then
    reset_op_code
    update_event_status "${OP_TEXT[6]}" 1
    op_log "${OP_TEXT[6]}"
    {
        file_log "Setting ufw for ssh, http, https"
        ufw allow ssh && ufw allow http && ufw allow https 
        set_op_code $?

        file_log "Enabling ufw"
        echo "y" | ufw enable
        set_op_code $?
    } 2>> "$LOGFILE" >&2

    if [[ $OP_CODE -eq 0 ]]; then
        update_event_status "${OP_TEXT[6]}" 2
        op_log "${OP_TEXT[6]}" "SUCCESSFUL"
    else
        reset_op_code
        update_event_status "${OP_TEXT[6]}" 3
        op_log "${OP_TEXT[6]}" "FAILED"
        revert_config_UFW
    fi
else
    op_log "${OP_TEXT[6]}" "NO-OP"
    file_log "Skipping UFW Config since software install failed..."
fi


##############################################################
# Step 7 - Configure Fail2Ban
##############################################################

# Proceed only when Fail2ban is installed
if [[ $(dpkg -l | grep -c fail2ban) -gt 0 ]]; then
    reset_op_code
    update_event_status "${OP_TEXT[7]}" 1
    op_log "${OP_TEXT[7]}"
    {
        if [[ -f /etc/fail2ban/jail.local ]]; then
            file_log "Backing up /etc/fail2ban/jail.local to /etc/fail2ban/jail.local${BACKUP_EXTENSION}"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local"$BACKUP_EXTENSION"
            set_op_code $?
        else
            file_log "Copying /etc/fail2ban/jail.conf to /etc/fail2ban/jail.local"
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
            set_op_code $?

            file_log "Backing up /etc/fail2ban/jail.conf to /etc/fail2ban/jail.conf${BACKUP_EXTENSION}"
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf"$BACKUP_EXTENSION"
            set_op_code $?
        fi

        # Do not do anything if copying jail.conf to jail.local failed
        if [[ -f /etc/fail2ban/jail.local ]]; then
            file_log "Determining your physical IP from https://ipinfo.io/ip"
            pub_ip=$(curl https://ipinfo.io/ip 2>> /dev/null) 

            # Start search from the line that contains "[DEFAULT]" - end search before the line that contains "# JAILS"
            file_log "/etc/fail2ban/jail.local - Setting bantime = 18000"
            sed -ri "/^\[DEFAULT\]$/,/^# JAILS$/ s/^bantime[[:blank:]]*= .*/bantime = 18000/" /etc/fail2ban/jail.local
            set_op_code $?

            file_log "/etc/fail2ban/jail.local - Setting backend = polling"
            sed -ri "/^\[DEFAULT\]$/,/^# JAILS$/ s/^backend[[:blank:]]*=.*/backend = polling/" /etc/fail2ban/jail.local
            set_op_code $?

            file_log "/etc/fail2ban/jail.local - Setting ignoreip = 127.0.0.1/8 ::1 ${pub_ip}"
            sed -ri "/^\[DEFAULT\]$/,/^# JAILS$/ s/^ignoreip[[:blank:]]*=.*/ignoreip = 127.0.0.1\/8 ::1 ${pub_ip}/" /etc/fail2ban/jail.local
            set_op_code $?

            # TODO - Exception handle 
                # - No [DEFAULT] section present
                # - no "bantime" or "backend" or "ignoreip" - options present
                # But that is not very important - cause fail2ban defaults are sane anyways
        fi

        if [[ -f /etc/fail2ban/jail.d/defaults-debian.conf ]]; then
            file_log "Backing up /etc/fail2ban/jail.d/defaults-debian.conf to /etc/fail2ban/jail.d/defaults-debian.conf${BACKUP_EXTENSION}"
            cp /etc/fail2ban/jail.d/defaults-debian.conf /etc/fail2ban/jail.d/defaults-debian.conf"$BACKUP_EXTENSION"
            set_op_code $?
        fi
        
        file_log "Enabling jails in /etc/fail2ban/jail.d/defaults-debian.conf"
cat <<FAIL2BAN > /etc/fail2ban/jail.d/defaults-debian.conf
[sshd]
enabled = true
maxretry = 3
bantime = 2592000

[sshd-ddos]
enabled = true
maxretry = 5
bantime = 2592000

[recidive]
enabled = true
bantime  = 31536000             ; 1 year
findtime = 86400                ; 1 days
maxretry = 10
FAIL2BAN
        set_op_code $?

        set_op_code $(service_action_and_chk_error "fail2ban" "start")
    } 2>> "$LOGFILE" >&2

    if [[ $OP_CODE -eq 0 ]]; then
        update_event_status "${OP_TEXT[7]}" 2
        op_log "${OP_TEXT[7]}" "SUCCESSFUL"
    else
        reset_op_code
        update_event_status "${OP_TEXT[7]}" 3
        op_log "${OP_TEXT[7]}" "FAILED"
        revert_config_fail2ban
    fi
else
    op_log "${OP_TEXT[7]}" "NO-OP"
    file_log "Skipping Fail2Ban config since software installation failed..."
fi


##############################################################
# Step 8 - Change root's password
##############################################################

if [[ $RESET_ROOT_PWD == 'y' ]]; then

    reset_op_code
    update_event_status "${OP_TEXT[8]}" 1
    op_log "${OP_TEXT[8]}"
    {
        # Generate a 15 character random password
        file_log "Generating roots new password..."
        PASS_ROOT="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)"
        set_op_code $?

        file_log "Generated root Password - ${PASS_ROOT}"

        # Change root's password
        file_log "Setting the new root password"
        echo -e "${PASS_ROOT}\\n${PASS_ROOT}" | passwd
        set_op_code $?
    } 2>> "$LOGFILE" >&2

    if [[ $OP_CODE -eq 0 ]]; then
        update_event_status "${OP_TEXT[8]}" 2
        op_log "${OP_TEXT[8]}" "SUCCESSFUL"
    else
        reset_op_code
        update_event_status "${OP_TEXT[8]}" 3
        op_log "${OP_TEXT[8]}" "FAILED"
        revert_root_pass_change
    fi
fi


##############################################################
# Step 9 - Enable SSH-only login
##############################################################

# TODO - Make this cleaner
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

    # If no keys present - insert the correct configuration to the end of the file
    if [[ $(grep -Pnc "$INACTIVE_KEYS_REGEX" "$file_location") -eq 0 ]] && [[ $(grep -Pnc "$ACTIVE_KEYS_REGEX" "$file_location") -eq 0 ]];
    then
        echo "$key" "$value" >> "$file_location"
    fi

    # If Config file already has correct configuration
    # Keep only the LAST correct one and comment out the rest
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

    # If Config file has commented configuration and NO active configuration 
    # Append the appropriate configuration below the LAST commented configuration
    if [[ $(grep -Pnc "$INACTIVE_KEYS_REGEX" "$file_location") -gt 0 ]] && [[ $(grep -Pnc "$ACTIVE_KEYS_REGEX" "$file_location") -eq 0 ]]; 
    then
        # Get the line number of - last commented configuration
        LINE_NUMBER=$(grep -Pn "$INACTIVE_KEYS_REGEX" "$file_location" | tail -1 | cut -d: -f 1)

        (( LINE_NUMBER++ ))

        # Insert the correct setting below the last commented configuration
        sed -i "$LINE_NUMBER"'i'"$key"' '"$value" "$file_location"
    fi
}

reset_op_code
update_event_status "${OP_TEXT[3]}" 1
op_log "${OP_TEXT[3]}"
{
    # Backup the sshd_config file
    file_log "Backing up /etc/ssh/sshd_config file to /etc/ssh/sshd_config$BACKUP_EXTENSION"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config"$BACKUP_EXTENSION"
    set_op_code $?

    # Remove root login
    file_log "Removing root login -> PermitRootLogin no"
    set_config_key "/etc/ssh/sshd_config" "PermitRootLogin" "no"
    set_op_code $?

    # Disable password login
    file_log "Disabling password login -> PasswordAuthentication no"
    set_config_key "/etc/ssh/sshd_config" "PasswordAuthentication" "no"
    set_op_code $?

    # Set SSH Authorization-Keys path
    file_log "Setting SSH Authorization-Keys path -> AuthorizedKeysFile '%h\/\.ssh\/authorized_keys'"
    set_config_key "/etc/ssh/sshd_config" "AuthorizedKeysFile" '\.ssh\/authorized_keys %h\/\.ssh\/authorized_keys'
    set_op_code $?

    file_log "Restarting ssh service..."
    { 
        set_op_code $(service_action_and_chk_error "sshd" "restart")
        if [[ $OP_CODE -eq 0 ]]; then
            false
        fi
        } || { 
                # Because Ubuntu 14.04 does not have sshd
                set_op_code $(service_action_and_chk_error "ssh" "restart")
            }
} 2>> "$LOGFILE" >&2

if [[ $OP_CODE -eq 0 ]]; then
    update_event_status "${OP_TEXT[3]}" 2
    op_log "${OP_TEXT[3]}" "SUCCESSFUL"
else
    reset_op_code
    file_log "Enabling SSH-only login failed."
    update_event_status "${OP_TEXT[3]}" 3
    op_log "${OP_TEXT[3]}" "FAILED"
    finally "${OP_TEXT[3]}"
    exit 1;
fi


##############################################################
# Recap
##############################################################

finally