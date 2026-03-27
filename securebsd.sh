#!/bin/sh

# Exit on errors and undefined variables
set -eu

# Define file variables for system hardening (chflags schg)
service_scheduler_files="/var/cron/allow /var/at/at.allow"
full_lockdown_files="$service_scheduler_files /etc/rc.firewall /etc/ipfw.rules /etc/crontab \
/usr/local/etc/sudoers /usr/local/etc/sudoers.d/sudo /etc/sysctl.conf /boot/loader.conf \
/boot/loader.rc /etc/fstab /etc/login.conf /etc/login.access /etc/newsyslog.conf \
/etc/ssh/sshd_config /etc/pam.d/sshd /etc/hosts /etc/hosts.allow /etc/ttys"

# Combine all sensitive files into one list for restricting "others" permissions (chmod o=)
password_related_files="/etc/master.passwd"
service_related_files="/etc/rc.conf /usr/local/etc/anacrontab"
audit_log_files="/var/audit"
sensitive_files="$service_scheduler_files $password_related_files $service_related_files $audit_log_files"
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
template_root="$script_dir/templates"

set_kv_defaults() {
    kv_list=$1
    old_ifs=$IFS
    IFS='
'
    for entry in $kv_list; do
        [ -n "$entry" ] || continue
        var=${entry%%=*}
        value=${entry#*=}
        eval "$var=\${$var-$value}"
    done
    IFS=$old_ifs
}

# Initialize user-configurable variables (can be set via flags or prompts)
script_config_defaults="
user=
ssh_port=
ssh_ipv4=
ssh_ipv6=
log_ssh_hits=
log_wan_tcp_hits=
allow_multicast=
allow_multicast_legacy=
internal_if=
nat_if=
tun_if=
install_auditing=
install_microcode=
install_suricata=
suricata_port=
password_exp=
cpu_type=unknown
"
set_kv_defaults "$script_config_defaults"

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo or run as root user."
    exit 1
fi

# Validate the existence of a user
validate_user() {
    if ! id "$1" >/dev/null 2>&1; then
        echo "User '$1' does not exist."
        return 1
    fi
}

# Validate SSH port input
validate_port() {
    if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        echo "Error: Invalid port number '$1'. Port must be an integer between 1 and 65535."
        return 1
    fi
}

# Validate network interface
validate_interface() {
    if ! ifconfig "$1" >/dev/null 2>&1; then
        echo "Error: Invalid interface '$1'. Please enter a valid network interface."
        return 1
    fi
}

# Validate password expiration input
validate_password_expiration() {
    if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -le 0 ]; then
        echo "Error: Invalid password expiration '$1'. Days must be a positive integer."
        return 1
    fi
}

validate_yes_no() {
    value="$1"
    option_name="$2"
    if [ "$value" != "yes" ] && [ "$value" != "no" ]; then
        echo "Invalid value for $option_name: $value (use yes or no)."
        return 1
    fi
}

validate_optional_yes_no() {
    value="$1"
    option_name="$2"
    [ -z "$value" ] || validate_yes_no "$value" "$option_name"
}

validate_optional_interface() {
    value="$1"
    [ -z "$value" ] || [ "$value" = "none" ] || validate_interface "$value"
}

normalize_ssh_ip_list() {
    value="$1"
    family="$2"

    if [ "$value" = "any" ]; then
        printf "%s\n" "$value"
        return 0
    fi

    case "$family" in
    ipv4)
        allowed_chars='0-9.,'
        ;;
    ipv6)
        allowed_chars='0-9A-Fa-f:.,'
        ;;
    *)
        echo "Error: Unknown IP list family '$family'." >&2
        return 1
        ;;
    esac

    cleaned=$(printf "%s" "$value" |
        sed "s/[[:space:]]//g; s/[^${allowed_chars}]//g; s/,,*/,/g; s/^,//; s/,\$//")
    [ -n "$cleaned" ] || return 1
    printf "%s\n" "$cleaned"
}

prompt_yes_no_default() {
    var_name="$1"
    prompt_text="$2"
    default_value="$3"
    option_name="$4"

    eval "current=\${$var_name-}"
    if [ -z "$current" ]; then
        echo "$prompt_text"
        printf "Enter your choice (default: %s): " "$default_value"
        read -r current
        current="${current:-$default_value}"
        eval "$var_name=\$current"
    fi
    validate_yes_no "$current" "$option_name"
}

prompt_optional_interface() {
    var_name="$1"
    prompt_text="$2"
    prompt_label="$3"
    provided_label="$4"
    disable_var="${5:-}"

    eval "current=\${$var_name-}"
    if [ -z "$current" ]; then
        echo "$prompt_text"
        printf "Enter the %s (default: none): " "$prompt_label"
        read -r current
        current="${current:-none}"
        eval "$var_name=\$current"
        if [ "$current" != "none" ]; then
            validate_interface "$current"
        elif [ -n "$disable_var" ]; then
            eval "$disable_var=no"
        fi
    else
        echo "Using provided $provided_label: $current"
        validate_optional_interface "$current"
    fi
}

make_secure_tmp() {
    tmp_dir="${1:-/var/tmp}"
    old_umask=$(umask)
    umask 077
    tmp_file=$(mktemp "$tmp_dir/securebsd.XXXXXX")
    umask "$old_umask"
    echo "$tmp_file"
}

atomic_replace() {
    target="$1"
    tmp_file="$2"
    orig_mode=""
    orig_owner=""
    orig_group=""

    if [ -e "$target" ]; then
        orig_mode=$(stat -f %Lp "$target" 2>/dev/null || echo "")
        orig_owner=$(stat -f %u "$target" 2>/dev/null || echo "")
        orig_group=$(stat -f %g "$target" 2>/dev/null || echo "")
    fi

    mv "$tmp_file" "$target"

    if [ -n "$orig_mode" ]; then
        chmod "$orig_mode" "$target"
    fi
    if [ -n "$orig_owner" ] && [ -n "$orig_group" ]; then
        chown "$orig_owner:$orig_group" "$target"
    fi
}

atomic_sed_replace() {
    target="$1"
    shift
    tmp_file=$(make_secure_tmp "$(dirname "$target")")
    if ! sed "$@" "$target" >"$tmp_file"; then
        echo "Error: Failed to update $target."
        rm -f "$tmp_file"
        return 1
    fi
    if [ ! -s "$tmp_file" ]; then
        echo "Error: Processing $target failed."
        rm -f "$tmp_file"
        return 1
    fi
    atomic_replace "$target" "$tmp_file"
}

template_path() {
    rel_path="$1"
    printf "%s/%s\n" "$template_root" "$rel_path"
}

run_awk_template() {
    src="$1"
    tmp_file="$2"
    error_label="$3"
    template_rel="$4"
    shift 4
    awk_program=$(template_path "$template_rel")

    if [ ! -f "$awk_program" ]; then
        echo "Error: AWK template not found: $awk_program"
        rm -f "$tmp_file"
        return 1
    fi

    if ! awk "$@" -f "$awk_program" "$src" >"$tmp_file"; then
        echo "Error: Failed to update $error_label."
        rm -f "$tmp_file"
        return 1
    fi
    if [ ! -s "$tmp_file" ]; then
        echo "Error: Processing $error_label failed."
        rm -f "$tmp_file"
        return 1
    fi
}

write_temp_content() {
    content="$1"
    tmp_file=$(make_secure_tmp)
    if ! printf "%s" "$content" >"$tmp_file"; then
        echo "Error: Failed to write temporary content file."
        rm -f "$tmp_file"
        return 1
    fi
    printf "%s\n" "$tmp_file"
}

render_template_file() {
    template_rel="$1"
    target="$2"
    shift 2

    template_file=$(template_path "$template_rel")
    if [ ! -f "$template_file" ]; then
        echo "Error: Template not found: $template_file"
        return 1
    fi

    tmp_file=$(make_secure_tmp "$(dirname "$target")")
    if ! cp "$template_file" "$tmp_file"; then
        echo "Error: Failed to copy template $template_file."
        rm -f "$tmp_file"
        return 1
    fi

    for replacement in "$@"; do
        placeholder=${replacement%%=*}
        value=${replacement#*=}
        escaped_value=$(printf "%s" "$value" | sed 's/[&|\\]/\\&/g')
        next_tmp="${tmp_file}.next"
        if ! sed "s|$placeholder|$escaped_value|g" "$tmp_file" >"$next_tmp"; then
            echo "Error: Failed to render template $template_file."
            rm -f "$tmp_file" "$next_tmp"
            return 1
        fi
        mv "$next_tmp" "$tmp_file"
    done

    if [ ! -s "$tmp_file" ]; then
        echo "Error: Rendering template $template_file failed."
        rm -f "$tmp_file"
        return 1
    fi

    atomic_replace "$target" "$tmp_file"
}

apply_kv_settings_file() {
    target_file="$1"
    settings="$2"
    append_missing="${3:-no}"

    apply_settings_merge_template "$target_file" "awk/kv_settings_merge.awk" "$settings" -v append_missing="$append_missing"
}

apply_settings_merge_template() {
    target_file="$1"
    template_rel="$2"
    settings="$3"
    shift 3

    if [ ! -f "$target_file" ]; then
        echo "Error: $target_file not found."
        return 1
    fi

    tmp_file=$(make_secure_tmp "$(dirname "$target_file")")
    settings_file=$(write_temp_content "$settings") || {
        rm -f "$tmp_file"
        return 1
    }
    if ! run_awk_template "$target_file" "$tmp_file" "$target_file" "$template_rel" -v settings_file="$settings_file" "$@"; then
        rm -f "$settings_file"
        return 1
    fi
    rm -f "$settings_file"
    atomic_replace "$target_file" "$tmp_file"
}

emit_kv_settings() {
    var_list=$1
    old_ifs=$IFS
    IFS=' '
    for var_name in $var_list; do
        eval "var_value=\${$var_name}"
        printf '%s="%s"\n' "$var_name" "${var_value-}"
    done
    IFS=$old_ifs
}

emit_field_settings() {
    field_list=$1
    old_ifs=$IFS
    IFS='
'
    for entry in $field_list; do
        [ -n "$entry" ] || continue
        key=${entry%%=*}
        value=${entry#*=}
        printf '%s %s\n' "$key" "$value"
    done
    IFS=$old_ifs
}

append_setting_line() {
    settings_block=$1
    setting_line=$2
    if [ -n "$settings_block" ]; then
        printf '%s\n%s\n' "$settings_block" "$setting_line"
    else
        printf '%s\n' "$setting_line"
    fi
}

set_default_if_empty() {
    var_name=$1
    default_value=$2
    eval "[ -n \"\${$var_name-}\" ] || $var_name=\$default_value"
}

usage() {
    exit_code="${1:-1}"
    cat <<EOF
Usage: $0 [options]

All options are optional; missing values will be prompted interactively.

  -u, --user USER                 Username to allow for SSH/sudo
  -p, --ssh-port PORT             SSH port (default: 2222)
      --ssh-ipv4 LIST             Comma-separated IPv4 list or 'any'
      --ssh-ipv6 LIST             Comma-separated IPv6 list or 'any'
      --log-ssh-hits yes|no       Enable SSH SYN count/log rules (default: no)
      --log-wan-tcp-hits yes|no   Enable WAN TCP SYN count/log rules (default: no)
      --allow-multicast yes|no    Allow modern multicast on the trusted bridge path (default: no)
      --allow-multicast-legacy yes|no
                                  Allow legacy IGMP/MLD compatibility when multicast is enabled (default: no)
      --internal-if IFACE         Internal interface (bridge), or 'none'
      --nat-if IFACE              IPv4 VPN/bootstrap egress interface, or 'none'
      --tunnel-if IFACE           Protected IPv6-over-VPN interface (e.g. tun0 or gif0), or 'none'
      --install-auditing yes|no   Install auditing tools (default: yes)
      --install-microcode yes|no  Install CPU microcode (default: yes)
      --install-suricata yes|no   Install Suricata IPS (default: no)
      --suricata-port PORT        Suricata divert port (default: 8000)
      --password-exp DAYS|none    Password expiration in days (default: 120)
  -h, --help                      Show this help and exit

Examples:
  $0 --user alice --ssh-port 2222 --ssh-ipv4 203.0.113.10,198.51.100.5 --nat-if tun0 --internal-if bridge0
EOF
    exit "$exit_code"
}

normalize_option_name() {
    case "$1" in
    -u | --user)
        printf "%s\n" "user"
        ;;
    -p | --ssh-port)
        printf "%s\n" "ssh_port"
        ;;
    --*)
        printf "%s\n" "${1#--}" | tr '-' '_'
        ;;
    *)
        return 1
        ;;
    esac
}

set_option_value() {
    option_name=$(normalize_option_name "$1") || return 1
    eval "$option_name=\$2"
}

parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
        -u | --user | -p | --ssh-port | --ssh-ipv4 | --ssh-ipv6 | --log-ssh-hits | --log-wan-tcp-hits | --allow-multicast | --allow-multicast-legacy | --internal-if | --nat-if | --tunnel-if | --install-auditing | --install-microcode | --install-suricata | --suricata-port | --password-exp)
            [ $# -ge 2 ] || usage 2
            set_option_value "$1" "$2" || usage 2
            shift 2
            ;;
        -h | --help)
            usage 0
            ;;
        *)
            echo "Unknown option: $1"
            usage 2
            ;;
        esac
    done

    # Validate arguments provided via flags
    if [ -n "$user" ]; then
        validate_user "$user" || usage 2
    fi
    if [ -n "$ssh_port" ]; then
        validate_port "$ssh_port" || usage 2
    fi
    if [ -n "$ssh_ipv4" ]; then
        normalized_ssh_ipv4=$(normalize_ssh_ip_list "$ssh_ipv4" ipv4) || {
            echo "Invalid IPv4 list '$ssh_ipv4'. Use comma-separated IPv4 addresses or 'any'."
            usage 2
        }
        ssh_ipv4="$normalized_ssh_ipv4"
    fi
    if [ -n "$ssh_ipv6" ]; then
        normalized_ssh_ipv6=$(normalize_ssh_ip_list "$ssh_ipv6" ipv6) || {
            echo "Invalid IPv6 list '$ssh_ipv6'. Use comma-separated IPv6 addresses or 'any'."
            usage 2
        }
        ssh_ipv6="$normalized_ssh_ipv6"
    fi
    validate_optional_yes_no "${log_ssh_hits-}" "--log-ssh-hits" || usage 2
    validate_optional_yes_no "${log_wan_tcp_hits-}" "--log-wan-tcp-hits" || usage 2
    validate_optional_yes_no "${allow_multicast-}" "--allow-multicast" || usage 2
    validate_optional_yes_no "${allow_multicast_legacy-}" "--allow-multicast-legacy" || usage 2
    if [ "${allow_multicast_legacy:-no}" = "yes" ] && [ "${allow_multicast:-no}" != "yes" ]; then
        echo "--allow-multicast-legacy yes requires --allow-multicast yes."
        usage 2
    fi
    validate_optional_interface "${internal_if-}" || usage 2
    validate_optional_interface "${nat_if-}" || usage 2
    validate_optional_interface "${tun_if-}" || usage 2
    validate_optional_yes_no "${install_auditing-}" "--install-auditing" || usage 2
    validate_optional_yes_no "${install_microcode-}" "--install-microcode" || usage 2
    validate_optional_yes_no "${install_suricata-}" "--install-suricata" || usage 2
    if [ -n "$suricata_port" ]; then
        validate_port "$suricata_port" || usage 2
    fi
    if [ -n "$password_exp" ] && [ "$password_exp" != "none" ]; then
        validate_password_expiration "$password_exp" || usage 2
        password_exp="${password_exp}d"
    fi
}

ensure_scalar_setting() {
    target_file="$1"
    setting="$2"
    key="${setting%%=*}"

    if grep -qE "^${setting}([[:space:]]+#.*)?$" "$target_file"; then
        return 0
    fi
    if grep -q "^${key}=" "$target_file"; then
        atomic_sed_replace "$target_file" "s|^${key}=.*|${setting}|"
    else
        printf "%s\n" "$setting" >>"$target_file"
    fi
}

ensure_portacl_rule() {
    target_file="$1"
    managed_rule="$2"
    tmp_file=$(make_secure_tmp "$(dirname "$target_file")")
    root_uid=${managed_rule#uid:}
    root_uid=${root_uid%%:*}

    if ! run_awk_template "$target_file" "$tmp_file" "$target_file" "awk/portacl_merge.awk" -v managed_rule="$managed_rule" -v root_uid="$root_uid"; then
        return 1
    fi
    atomic_replace "$target_file" "$tmp_file"
}

# Clear immutable flags on system files for updates
clear_immutable_flags() {
    echo "Clearing immutable flags on system files for updates..."
    for file in $full_lockdown_files; do
        if [ ! -e "$file" ]; then
            echo "Warning: $file does not exist, skipping."
            continue
        fi
        chflags noschg "$file"
    done
}

# Reapply immutable flags after updates
reapply_immutable_flags() {
    echo "Reapplying immutable flags on system files..."
    for file in $full_lockdown_files; do
        chflags schg "$file"
    done
}

# Collect user input for SSH, IPs, Suricata, and password expiration settings
collect_user_input() {
    echo "This script will harden your FreeBSD system by securing SSH, enabling firewall rules, configuring automatic updates, and more."

    # SSH user input
    if [ -z "$user" ]; then
        echo "Enter a valid username for SSH access and sudo privileges."
        printf "Enter the username to allow for SSH access: "
        read -r user
        if ! validate_user "$user"; then
            echo "Please provide a valid username."
            return 1
        fi
    else
        echo "Using provided username: $user"
    fi

    # SSH port input
    if [ -z "$ssh_port" ]; then
        echo "Choose a custom SSH port (not the default 22)."
        printf "Enter the SSH port to use (default: 2222): "
        read -r ssh_port
        ssh_port="${ssh_port:-2222}"
        validate_port "$ssh_port" || return 1
    else
        echo "Using provided SSH port: $ssh_port"
    fi

    # SSH IPv4 input
    if [ -z "$ssh_ipv4" ]; then
        echo "Enter a comma-separated list of IPv4 addresses allowed to SSH into the server, or type 'any' to allow all IPv4 access (not recommended)."
        printf "Enter the SSH IPv4 addresses (comma-separated) for SSH access: "
        read -r ssh_ipv4
        normalized_ssh_ipv4=$(normalize_ssh_ip_list "$ssh_ipv4" ipv4) || {
            echo "Invalid input. Please enter comma-separated IPv4 addresses or 'any'."
            return 1
        }
        ssh_ipv4="$normalized_ssh_ipv4"
    else
        echo "Using provided SSH IPv4 list: $ssh_ipv4"
    fi

    # SSH IPv6 input
    if [ -z "$ssh_ipv6" ]; then
        echo "Enter a comma-separated list of IPv6 addresses allowed to SSH into the server, or type 'any' to allow all IPv6 access (not recommended)."
        printf "Enter the SSH IPv6 addresses (comma-separated) for SSH access: "
        read -r ssh_ipv6
        normalized_ssh_ipv6=$(normalize_ssh_ip_list "$ssh_ipv6" ipv6) || {
            echo "Invalid input. Please enter comma-separated IPv6 addresses or 'any'."
            return 1
        }
        ssh_ipv6="$normalized_ssh_ipv6"
    else
        echo "Using provided SSH IPv6 list: $ssh_ipv6"
    fi

    prompt_yes_no_default "log_ssh_hits" "Enable SSH SYN count/log rules for firewall debugging? (yes/no)" "no" "--log-ssh-hits" || return 1
    prompt_yes_no_default "log_wan_tcp_hits" "Enable WAN TCP SYN count/log rules for firewall debugging? (yes/no)" "no" "--log-wan-tcp-hits" || return 1
    prompt_yes_no_default "allow_multicast" "Allow modern multicast on the trusted internal bridge path? (yes/no)" "no" "--allow-multicast" || return 1
    if [ "$allow_multicast" = "yes" ]; then
        prompt_yes_no_default \
            "allow_multicast_legacy" \
            "Allow legacy multicast compatibility (IGMPv1, IGMPv2, MLDv1)? (yes/no)" \
        "no" \
        "--allow-multicast-legacy" || return 1
    else
        allow_multicast_legacy="no"
    fi

    # Interface selection for firewall policy and optional Suricata netmap support
    prompt_optional_interface \
        "internal_if" \
        "Set the internal network interface for IPFW. Type 'none' if not using a gateway/bridge (default: none)." \
        "internal network interface (e.g., bridge0)" \
        "internal interface" \
        "install_suricata" || return 1
    prompt_optional_interface \
        "nat_if" \
        "Set the IPv4 VPN/bootstrap egress interface for IPFW. Type 'none' if not using a VPN bootstrap path (default: none)." \
        "IPv4 VPN/bootstrap egress interface (e.g., tun0)" \
        "IPv4 VPN/bootstrap interface" || return 1
    prompt_optional_interface \
        "tun_if" \
        "Set the protected IPv6-over-VPN interface for IPFW. This can be the main VPN interface or a 6in4 interface such as gif0 when it runs inside the IPv4 VPN. Type 'none' if not using one (default: none)." \
        "protected IPv6-over-VPN interface (e.g., tun0, gif0)" \
        "protected tunnel interface" || return 1

    prompt_yes_no_default "install_auditing" "Do you want to install security auditing tools? (yes/no)" "yes" "--install-auditing" || return 1
    prompt_yes_no_default "install_microcode" "Would you like to install CPU microcode for your processor to enhance security? (yes/no)" "yes" "--install-microcode" || return 1
    if [ "$install_microcode" = "yes" ]; then
        cpu_info=$(sysctl -n hw.model | tr '[:upper:]' '[:lower:]')
        if echo "$cpu_info" | grep -qF "intel"; then
            cpu_type="intel"
        elif echo "$cpu_info" | grep -qF "amd"; then
            cpu_type="amd"
        else
            cpu_type="unknown"
        fi
    fi

    # Suricata installation choice
    prompt_yes_no_default "install_suricata" "Do you want to install and configure Suricata? (yes/no)" "no" "--install-suricata" || return 1
    if [ "$install_suricata" != "no" ]; then
        set_default_if_empty "suricata_port" "8000"
        validate_port "$suricata_port" || return 1
    else
        suricata_port="none"
    fi

    # Password expiration input
    if [ -z "$password_exp" ]; then
        echo "Set the password expiration period in days. Type 'none' to disable expiration (not recommended)."
        printf "Enter the password expiration period in days (default: 120): "
        read -r password_exp
        set_default_if_empty "password_exp" "120"
        if [ "$password_exp" != "none" ]; then
            validate_password_expiration "$password_exp" || return 1
            password_exp="${password_exp}d"
        fi
    fi
}

# Backup critical system configuration files
backup_configs() {
    echo "Creating backups of critical configuration files..."
    backup_dir="/etc/backup_$(date +%Y%m%d_%H%M%S)"
    backup_files="/etc/rc.conf /etc/sysctl.conf /etc/login.conf /boot/loader.conf /etc/ssh/sshd_config /etc/pam.d/sshd /etc/ttys"
    mkdir -p "$backup_dir"
    chmod 750 "$backup_dir"
    for conf_file in $backup_files; do
        cp "$conf_file" "$backup_dir"
    done
    chflags -R schg "$backup_dir"
    echo "Backup completed and made immutable. Files saved in $backup_dir."
}

# Update FreeBSD and install necessary packages (sudo-rs, fail2ban, Suricata, Google Authenticator)
update_and_install_packages() {
    echo "Updating FreeBSD and installing necessary packages (sudo-rs, fail2ban, Google Authenticator)..."
    # FreeBSD update is not supported on all architectures
    freebsd_update_supported="no"
    if freebsd-update fetch install; then
        freebsd_update_supported="yes"
    fi
    pkg upgrade -y
    pkg install -y sudo-rs anacron pam_google_authenticator py311-fail2ban

    # Install security auditing tools if the user opted in
    if [ "$install_auditing" = "yes" ]; then
        pkg install -y lynis spectre-meltdown-checker
    else
        echo "Skipping auditing tools installation."
    fi

    # Install CPU microcode if the user opted in
    if [ "$cpu_type" = "intel" ]; then
        echo "Detected Intel CPU. Installing 'cpu-microcode-intel' package."
        pkg install -y cpu-microcode-intel
    elif [ "$cpu_type" = "amd" ]; then
        echo "Detected AMD CPU. Installing 'cpu-microcode-amd' package."
        pkg install -y cpu-microcode-amd
    else
        echo "Could not detect Intel or AMD CPU. Skipping microcode installation."
    fi

    # Install Suricata if the user opted in
    if [ "$install_suricata" = "yes" ]; then
        echo "Installing Suricata..."
        pkg install -y suricata
        suricata-update
        echo "Suricata installed and updated."
    else
        echo "Skipping Suricata installation."
    fi

    # Fetch pkg audit database
    pkg audit -Frq || true

    # Check package integrity
    pkg check -sa
}

# Configure SSH security settings
configure_ssh() {
    echo "Configuring SSH security with public key and Google Authenticator authentication..."
    sshd_config="/etc/ssh/sshd_config"

    # Define SSH settings as key-value pairs
    settings=$(emit_field_settings "
PermitRootLogin=no
MaxAuthTries=3
PasswordAuthentication=no
KbdInteractiveAuthentication=yes
PubkeyAuthentication=yes
UsePAM=yes
UseDNS=no
AuthenticationMethods=publickey,keyboard-interactive
AllowUsers=$user
Port=$ssh_port
ClientAliveInterval=60
ClientAliveCountMax=1
")

    if ! apply_settings_merge_template "$sshd_config" "awk/sshd_settings_merge.awk" "$settings"; then
        return 1
    fi

    echo "SSH configured to require public key and Google Authenticator authentication and disconnect inactive sessions."

    # Configure SSH keys for the SSH user
    ssh_dir="/home/$user/.ssh"
    ssh_key="$ssh_dir/id_ed25519"
    ssh_pub_key="${ssh_key}.pub"
    authorized_keys="$ssh_dir/authorized_keys"

    # Ensure .ssh directory exists with correct permissions
    if [ ! -d "$ssh_dir" ]; then
        echo "Creating .ssh directory for $user..."
        mkdir -p "$ssh_dir"
    fi

    # Always enforce correct permissions on .ssh directory
    chmod 700 "$ssh_dir"
    chown "$user:$user" "$ssh_dir"

    # Check for any existing SSH key pairs in the .ssh directory
    if [ -f "$ssh_key" ] || [ -f "$ssh_pub_key" ]; then
        echo "SSH key pair already exists for $user."
    else
        echo "No SSH key found for $user. Generating a new key pair..."
        su - "$user" -c "ssh-keygen -t ed25519 -f $ssh_key -N '' -q"
    fi

    # Set up authorized_keys
    if [ ! -f "$authorized_keys" ]; then
        echo "Creating authorized_keys for $user..."
        if [ -f "$ssh_pub_key" ]; then
            cat "$ssh_pub_key" >"$authorized_keys"
        else
            echo "Public key not found. Ensure a key pair exists before running this script."
            return 1
        fi
    else
        echo "authorized_keys already exists for $user. Checking if the public key is present..."
        # Extract key type and key value from the public key file
        key_type_and_value=$(awk '{print $1, $2}' "$ssh_pub_key")
        if ! grep -qF "$key_type_and_value" "$authorized_keys"; then
            echo "Adding missing public key to authorized_keys."
            cat "$ssh_pub_key" >>"$authorized_keys"
        else
            echo "Public key already exists in authorized_keys."
        fi
    fi

    # Always enforce correct permissions on authorized_keys
    chmod 600 "$authorized_keys"
    chown "$user:$user" "$authorized_keys"

    # Enforce correct permissions on all SSH key files
    if [ -f "$ssh_key" ]; then
        chmod 600 "$ssh_key"
        chown "$user:$user" "$ssh_key"
    fi
    if [ -f "$ssh_pub_key" ]; then
        chmod 644 "$ssh_pub_key"
        chown "$user:$user" "$ssh_pub_key"
    fi

    echo "Public key authentication enabled for $user."

    # Provide clear instructions for private key management
    echo ""
    echo "IMPORTANT: You must securely copy the private key to your local machine before rebooting."
    echo "To securely transfer the private key, run the following command on your local machine:"
    echo ""
    echo "scp <username>@<remote_host>:$ssh_dir/id_ed25519 ~/.ssh/"
    echo ""
    echo "After copying the private key, delete it from the remote server for security:"
    echo "ssh <username>@<remote_host> 'rm $ssh_dir/id_ed25519'"
    echo ""
    echo "Ensure the permissions for the private key on your local machine are set correctly with:"
    echo "chmod 600 ~/.ssh/id_ed25519"
    echo ""

    # Pause and wait for user confirmation
    echo "Press ENTER to confirm you have securely copied the private key and are ready to proceed."
    read -r _dummy_variable
}

# Configure PAM security settings
configure_ssh_pam() {
    echo "Configuring SSH PAM for Google Authenticator..."
    pam_sshd_config="/etc/pam.d/sshd"
    ga_pam_line="auth requisite pam_google_authenticator.so"

    # Check if pam_google_authenticator.so is already present
    if grep -q "^$ga_pam_line" "$pam_sshd_config"; then
        echo "Google Authenticator is already enabled in PAM SSH configuration."
        return
    fi
    pam_sshd_tmp=$(make_secure_tmp "$(dirname "$pam_sshd_config")")

    if ! run_awk_template "$pam_sshd_config" "$pam_sshd_tmp" "$pam_sshd_config" "awk/pam_sshd_google_auth.awk" -v ga_line="$ga_pam_line"; then
        return 1
    fi

    # Replace the sshd config file atomically
    atomic_replace "$pam_sshd_config" "$pam_sshd_tmp"

    echo "Google Authenticator added to the auth section of PAM SSH configuration."
}

# Configure Google Authenticator TOTP for the SSH user
configure_google_auth() {
    echo "Configuring Google Authenticator TOTP for the SSH user..."

    # Define the configuration file path
    ga_config="/home/$user/.google_authenticator"

    # Run google-authenticator as the SSH user with secure options
    su - "$user" -c "google-authenticator -t -d -r 3 -R 30 -W -s '$ga_config'"

    # Secure permissions on the .google_authenticator file
    chmod 600 "$ga_config"
    chown "$user:$user" "$ga_config"

    # Provide clear instructions for the user
    echo ""
    echo "Google Authenticator TOTP configuration is complete."
    echo "IMPORTANT: Copy and securely store the following details:"
    echo "1. Your secret key (used to set up TOTP in your app)."
    echo "2. Emergency scratch codes (for recovery if your TOTP device is unavailable)."
    echo ""
    echo "Without these details, you may lose access to this system."
    echo ""
    echo "You can always re-run this script to regenerate a new secret key, but doing so will invalidate any previously configured TOTP apps."
    echo ""

    # Pause and wait for user confirmation
    echo "Press ENTER to confirm you have securely saved the secret key and scratch codes."
    read -r _dummy_variable
}

# Configure sudo for the SSH user
configure_sudo() {
    echo "Configuring sudo for administrative users..."

    # Create the sudo group if it doesn't exist
    if ! getent group sudo >/dev/null; then
        echo "Creating sudo group..."
        pw groupadd sudo
    fi

    # Prompt administrator for users to add to the sudo group
    printf "The following users currently belong to the wheel group: "
    getent group wheel | cut -d ':' -f 4

    printf "\nEnter additional usernames to add to the sudo group (comma-separated, leave blank to skip): "
    read -r users_to_add
    users_to_add="${user},${users_to_add}"

    if [ -n "$users_to_add" ]; then
        users_added=""
        # Split input into individual usernames
        for member_user in $(echo "$users_to_add" | tr ',' '\n'); do
            member_user=$(echo "$member_user" | xargs) # Trim whitespace
            if validate_user "$member_user"; then
                pw groupmod sudo -m "$member_user"
                users_added="${users_added}${member_user},"
            fi
        done

        # Print added users, trimming the trailing comma
        if [ -n "$users_added" ]; then
            users_added=$(echo "$users_added" | sed 's/,$//') # Remove trailing comma
            echo "Users added to the sudo group: ${users_added}"
        else
            echo "No users added to the sudo group."
        fi
    fi

    # Configure sudoers file for the sudo group
    if [ ! -f /usr/local/etc/sudoers.d/sudo ]; then
        echo '%sudo ALL=(ALL:ALL) ALL' >/usr/local/etc/sudoers.d/sudo
        chmod 440 /usr/local/etc/sudoers.d/sudo
    fi

    # Prompt before disabling wheel group sudo access
    disable_wheel=""
    prompt_yes_no_default \
        "disable_wheel" \
        "Do you want to disable sudo access for the wheel group? (yes/no)" \
        "yes" \
        "disable_wheel" || return 1

    if [ "$disable_wheel" = "yes" ]; then
        echo "Disabling sudo access for the wheel group..."

        # Regex to catch all variations of %wheel entries
        WHEEL_REGEX='^%wheel[[:blank:]]+ALL=\(ALL(:ALL)?\)[[:blank:]]+(NOPASSWD:[[:blank:]]+)?ALL'

        if grep -qE "$WHEEL_REGEX" /usr/local/etc/sudoers; then
            atomic_sed_replace /usr/local/etc/sudoers -E "s/${WHEEL_REGEX}/# &/"
            echo "Commented out %wheel group sudo access in /usr/local/etc/sudoers."
        fi

        # Disable any custom sudoers.d files for the wheel group
        if [ -f /usr/local/etc/sudoers.d/wheel ]; then
            mv /usr/local/etc/sudoers.d/wheel /usr/local/etc/sudoers.d/wheel.disabled
            echo "Disabled /usr/local/etc/sudoers.d/wheel."
        fi
    else
        echo "Wheel group sudo access remains enabled."
    fi

    # Prompt to remove non-root members from the wheel group
    remove_wheel_members=""
    prompt_yes_no_default \
        "remove_wheel_members" \
        "Do you want to remove non-root members from the wheel group? (yes/no)" \
        "yes" \
        "remove_wheel_members" || return 1

    if [ "$remove_wheel_members" = "yes" ]; then
        users_removed=""
        echo "Removing non-root users from the wheel group..."
        for wheel_user in $(getent group wheel | cut -d ':' -f 4 | tr ',' '\n'); do
            if [ "$wheel_user" != "root" ] && [ -n "$wheel_user" ]; then
                pw groupmod wheel -d "$wheel_user"
                users_removed="${users_removed}${wheel_user},"
            fi
        done

        # Print removed users, trimming the trailing comma
        if [ -n "$users_removed" ]; then
            users_removed=$(echo "$users_removed" | sed 's/,$//') # Remove trailing comma
            echo "Users removed from the wheel group: ${users_removed}"
        else
            echo "No users removed from the wheel group."
        fi
    else
        echo "No users removed from the wheel group."
    fi

    echo "Sudo configuration complete. Please log out and log in again to apply changes."
}

# Configure Suricata for IPS mode and include custom config
configure_suricata() {
    echo "Configuring Suricata for IPS mode with IPFW..."

    # Define the configuration file paths as variables
    suricata_conf="/usr/local/etc/suricata/suricata.yaml"
    suricata_custom_conf="/usr/local/etc/suricata/suricata-custom.yaml"
    suricata_rules="/var/lib/suricata/rules/custom.rules"

    if ! render_template_file "config/suricata-custom.yaml.tmpl" "$suricata_custom_conf" \
        "@NAT_INTERFACE@=$nat_if" \
        "@SURICATA_PORT@=$suricata_port"; then
        return 1
    fi

    # Update SSH port in suricata.yaml using sed to match single values or lists
    atomic_sed_replace "$suricata_conf" -E "s/(SSH_PORTS: )([0-9]+|\\[[0-9, ]+\\])/\1$ssh_port/"

    # Append the custom configuration to the existing suricata.yaml using the `include` directive
    if ! grep -q "^include: $suricata_custom_conf" "$suricata_conf"; then
        echo "include: $suricata_custom_conf" >>"$suricata_conf"
        echo "Custom Suricata configuration included."
    else
        echo "Custom Suricata configuration is already included."
    fi

    # Add custom Suricata rule for SSH port if not present
    if ! grep -qF "port $ssh_port" "$suricata_rules"; then
        echo "alert tcp any any -> any $ssh_port (msg:\"SSH connection on custom port $ssh_port\"; sid:1000001; rev:1;)" >>"$suricata_rules"
        echo "Custom SSH port rule added to Suricata."
    else
        echo "Custom SSH port rule already exists in Suricata."
    fi

    # Test the Suricata configuration
    if ! suricata -T -c "$suricata_conf"; then
        echo "Suricata configuration test failed. Please review the configuration."
        return 1
    fi

    # Enable Suricata at boot
    sysrc suricata_enable="YES"
    echo "Suricata configured to enable at next reboot on interface $nat_if."
}

# Configure Fail2Ban to protect SSH
configure_fail2ban() {
    echo "Configuring Fail2Ban to protect SSH and add manual permanent ban jail..."

    echo "Creating Fail2Ban jail.local for SSH and manual bans..."
    if ! render_template_file "config/fail2ban-jail.local.tmpl" "/usr/local/etc/fail2ban/jail.local"; then
        return 1
    fi

    # Enable Fail2Ban service
    echo "Enabling Fail2Ban service..."
    sysrc fail2ban_enable="YES"

    echo "Fail2Ban configuration completed. Restart the service to apply changes."
}

# Harden system kernel with sysctl settings
harden_sysctl() {
    echo "Applying sysctl hardening..."
    sysctl_conf="/etc/sysctl.conf"

    multicast_legacy_value=0
    if [ "${allow_multicast:-no}" = "yes" ] && [ "${allow_multicast_legacy:-no}" = "yes" ]; then
        multicast_legacy_value=1
    fi

    multicast_sysctls='
net.inet.igmp.legacysupp='"$multicast_legacy_value"'
net.inet.igmp.v2enable='"$multicast_legacy_value"'
net.inet.igmp.v1enable='"$multicast_legacy_value"'
net.inet6.mld.v1enable='"$multicast_legacy_value"

    # Define the sysctl values to be set
    settings=$(
        cat <<EOF
net.link.bridge.pfil_bridge=1
net.inet.icmp.bmcastecho=0
net.inet.icmp.drop_redirect=1
net.inet.icmp.icmplim=50
$multicast_sysctls
net.inet.tcp.blackhole=2
net.inet.tcp.drop_synfin=1
net.inet.tcp.syncookies=1
net.inet.udp.blackhole=1
net.inet.ip.random_id=1
net.inet.ip.process_options=0
net.inet.ip.redirect=0
net.inet.ip.dummynet.io_fast=1
net.inet.ip.fw.one_pass=0
net.inet6.icmp6.rediraccept=0
net.inet6.ip6.redirect=0
net.inet6.ip6.use_tempaddr=1
net.inet6.ip6.prefer_tempaddr=1
kern.randompid=1
security.bsd.hardlink_check_gid=1
security.bsd.hardlink_check_uid=1
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
security.bsd.see_jail_proc=0
security.bsd.unprivileged_read_msgbuf=0
security.bsd.unprivileged_proc_debug=0
security.mac.bsdextended.logging=1
security.mac.portacl.suser_exempt=1
security.mac.portacl.rules=uid:$(id -u "root"):tcp:$ssh_port
security.mac.portacl.port_high=5000
net.inet.ip.portrange.reservedlow=0
net.inet.ip.portrange.reservedhigh=0
hw.ibrs_disable=0
hw.spec_store_bypass_disable=2
hw.mds_disable=3
vm.pmap.allow_2m_x_ept=0
EOF
    )

    loader_updates=""
    for setting in $settings; do
        key="${setting%%=*}"

        # Use sysctl -d to check if the key exists
        if echo "$key" | grep -qF "net.inet.ip.fw." || sysctl -d "$key" >/dev/null 2>&1; then
            # Merge list-style portacl rules; replace simple scalar keys exactly.
            if [ "$key" = "security.mac.portacl.rules" ]; then
                if ! ensure_portacl_rule "$sysctl_conf" "${setting#*=}"; then
                    return 1
                fi
            else
                if ! ensure_scalar_setting "$sysctl_conf" "$setting"; then
                    return 1
                fi
            fi
        else
            echo "Warning: sysctl key '${key}' does not exist on this system."
        fi
    done

    echo "System kernel hardened with secure sysctl settings."
}

# Harden loader.conf with additional kernel security modules
harden_loader_conf() {
    echo "Configuring loader.conf for additional kernel security and microcode..."
    loader_conf="/boot/loader.conf"

    # Define the loader.conf values to be set for security modules
    settings='
mac_bsdextended_load="YES"
mac_portacl_load="YES"
mac_seeotheruids_load="YES"
ipfw_load="YES"
dummynet_load="YES"'

    # Load ipfw_nat when an IPv4 VPN/bootstrap interface is configured for the firewall ruleset
    if [ "$nat_if" != "none" ]; then
        settings=$(append_setting_line "$settings" 'ipfw_nat_load="YES"')
    fi

    # Load ipdivert when Suricata divert processing is enabled
    if [ "$install_suricata" = "yes" ] && [ "$suricata_port" != "none" ]; then
        settings=$(append_setting_line "$settings" 'ipdivert_load="YES"')
    fi

    # Add CPU microcode settings to loader.conf if detected
    if [ "$cpu_type" != "unknown" ]; then
        microcode_settings='
cpuctl_load="YES"
cpu_microcode_load="YES"'
        if [ "$cpu_type" = "intel" ]; then
            microcode_settings=$(append_setting_line "$microcode_settings" 'coretemp_load="YES"')
            microcode_settings=$(append_setting_line "$microcode_settings" 'cpu_microcode_name="/boot/firmware/intel-ucode.bin"')
        elif [ "$cpu_type" = "amd" ]; then
            microcode_settings=$(append_setting_line "$microcode_settings" 'amdtemp_load="YES"')
            microcode_settings=$(append_setting_line "$microcode_settings" 'cpu_microcode_name="/boot/firmware/amd-ucode.bin"')
        fi
        settings=$(append_setting_line "$settings" "$microcode_settings")
    fi

    for setting in $settings; do
        key="${setting%%=*}"

        # Determine if the entry is a loadable module
        if echo "$key" | grep -qF "_load"; then
            module="${key%_load}"
            module_path="/boot/kernel/${module}.ko"
            module_alt_path="/boot/modules/${module}.ko"
        else
            module="not_a_module"
        fi

        # Special case for cpu_microcode_load
        if [ "$module" = "cpu_microcode" ]; then
            module="not_a_module"
        fi

        # Check if the module file exists for loadable modules
        if [ "$module" = "not_a_module" ] || [ -f "$module_path" ] || [ -f "$module_alt_path" ]; then
            if [ "$module" != "not_a_module" ]; then
                # Attempt to detect the registered name using kldstat -v (only if the module is loaded)
                registered_name=$(kldstat -v 2>/dev/null | awk -v mod="${module}$" '$NF ~ mod && !($NF ~ /\.ko/) {print $NF; exit}')

                # If no registered name is found, use the default name
                if [ -n "$registered_name" ]; then
                    module="$registered_name"
                fi

                # Attempt to load the kernel module
                if kldstat -q -m "$module"; then
                    echo "Module '${module}' already loaded."
                elif [ "$module" != "ipfw" ] && [ "$module" != "ipfw_nat" ]; then
                    if kldload "$module" 2>/dev/null; then
                        echo "Module '${module}' successfully loaded."
                    else
                        echo "Warning: Failed to load kernel module '${module}'."
                        continue
                    fi
                fi
            fi

            loader_updates=$(append_setting_line "$loader_updates" "$setting")
        else
            echo "Warning: Kernel module '${module}' not found in /boot/kernel/ or /boot/modules/"
        fi
    done

    if [ -n "$loader_updates" ]; then
        if ! apply_kv_settings_file "$loader_conf" "$loader_updates" "yes"; then
            return 1
        fi
    fi

    echo "loader.conf hardened with additional kernel security modules and microcode settings."
}

# Set securelevel in rc.conf
configure_securelevel() {
    echo "Configuring securelevel in rc.conf..."
    sysrc kern_securelevel_enable="YES"
    sysrc kern_securelevel="1"
    echo "Securelevel configured in rc.conf."
}

harden_ttys() {
    echo "Hardening /etc/ttys for console password requirement and disabling extra VTs..."
    ttys_conf="/etc/ttys"

    if [ ! -f "$ttys_conf" ]; then
        echo "Warning: $ttys_conf not found; skipping."
        return 0
    fi
    ttys_tmp=$(make_secure_tmp "$(dirname "$ttys_conf")")

    if ! run_awk_template "$ttys_conf" "$ttys_tmp" "$ttys_conf" "awk/ttys_harden.awk"; then
        return 1
    fi

    if ! awk -f "$(template_path "awk/ttys_validate.awk")" "$ttys_tmp"; then
        echo "Error: Validation failed for $ttys_tmp."
        rm "$ttys_tmp"
        return 1
    fi

    atomic_replace "$ttys_conf" "$ttys_tmp"
    echo "Hardened /etc/ttys and disabled VTs."
}

# Set Blowfish password hashing, enforce password expiration, and configure umask
configure_password_and_umask() {
    echo "Configuring password security with Blowfish encryption and setting a secure umask..."
    login_conf="/etc/login.conf"

    # Check if the 'default' block exists
    if ! grep -q '^default:' "$login_conf"; then
        echo "Error: 'default:' block not found in $login_conf. Cannot proceed."
        return 1
    fi
    login_conf_tmp=$(make_secure_tmp "$(dirname "$login_conf")")

    # Check if Blowfish hashing is already enabled
    blf_enabled=$(grep -qE '^[[:blank:]]*:passwd_format=blf:' "$login_conf" && echo 1 || echo 0)

    if ! run_awk_template "$login_conf" "$login_conf_tmp" "$login_conf" "awk/login_conf_defaults.awk" -v new_passwd_format="blf" -v new_umask="027" -v password_expiration="${password_exp:-none}"; then
        return 1
    fi

    # Replace the login.conf file atomically
    atomic_replace "$login_conf" "$login_conf_tmp"

    # Rebuild login capabilities database
    if ! cap_mkdb "$login_conf"; then
        echo "Error: Failed to rebuild the login.conf database."
        return 1
    fi

    # Check if Blowfish hashing needs to be enabled
    if [ "$blf_enabled" -ne 1 ]; then
        # Inform the user about the password reset
        echo "Resetting the password for $user and root to ensure Blowfish encryption is applied."

        # Reset the password for the SSH user to apply Blowfish hashing
        if ! passwd "$user"; then
            echo "Error: Failed to reset password for $user."
            return 1
        fi

        # Reset the password for the root user to apply Blowfish hashing
        if ! passwd; then
            echo "Error: Failed to reset password for root."
            return 1
        fi
    fi

    echo "Password security configured with umask 027 and Blowfish encryption for $user."
}

# Configure IPFW firewall with updated rules
configure_ipfw() {
    echo "Configuring IPFW firewall with Suricata and Dummynet..."
    ipfw_rules="/etc/ipfw.rules"
    local_ipfw_rules="$script_dir/ipfw.rules"

    settings=$(emit_kv_settings "
nat_if tun_if internal_if suricata_port
ssh_ipv4 ssh_ipv6 ssh_port
log_ssh_hits log_wan_tcp_hits
allow_multicast allow_multicast_legacy
")

    if ! apply_kv_settings_file "$local_ipfw_rules" "$settings"; then
        return 1
    fi

    # Create /etc/ipfw.rules with the necessary firewall rules
    chmod 640 "$local_ipfw_rules"
    cp "$local_ipfw_rules" "$ipfw_rules"

    # Set the firewall to load on boot and specify the rules file
    sysrc firewall_enable="YES"
    sysrc firewall_script="$ipfw_rules"
    sysrc firewall_logging="YES" # Enable firewall logging

    echo "IPFW firewall with Suricata and Dummynet configured, rules saved to $ipfw_rules, and enabled at boot."
}

# Secure syslog and configure /tmp cleanup at startup
secure_syslog_and_tmp() {
    echo "Securing syslog and configuring /tmp cleanup at startup..."
    sysrc syslogd_flags="-ss"
    service syslogd restart
    sysrc clear_tmp_enable="YES"
    echo "Syslog secured and /tmp cleanup configured."
}

# Configure cron jobs for system updates and suricata-update
configure_cron_updates() {
    echo "Setting up automatic updates via cron for the root user..."

    # Fetch the current root crontab
    current_crontab=$(crontab -l 2>/dev/null || true)

    # Define cron jobs
    suricata_cmd="suricata-update"
    freebsd_update_cmd="freebsd-update cron"
    pkg_update_cmd="pkg upgrade -y"
    suricata_cron="0 2 * * 0 $suricata_cmd 2>&1 | logger -t suricata-update -p cron.notice"
    freebsd_update_cron="0 3 * * 0 PAGER=cat $freebsd_update_cmd 2>&1 | logger -t freebsd-update -p cron.notice"
    pkg_update_cron="0 4 * * 0 $pkg_update_cmd 2>&1 | logger -t pkg-upgrade -p cron.notice"

    # Temporary file to store updated crontab, specify /tmp directory explicitly
    temp_crontab=$(mktemp /tmp/root_crontab.XXXXXX)

    # Write the existing crontab to the temporary file
    echo "$current_crontab" >"$temp_crontab"

    # Add Suricata update cron job if applicable
    if [ "$install_suricata" = "yes" ] && ! echo "$current_crontab" | grep -qF "$suricata_cmd"; then
        echo "$suricata_cron" >>"$temp_crontab"
        echo "Added Suricata update cron job."
    else
        echo "Suricata update cron job already exists or not applicable. Skipping..."
    fi

    # Add FreeBSD update cron job if not already present
    if [ "$freebsd_update_supported" = "yes" ] && ! echo "$current_crontab" | grep -qF "$freebsd_update_cmd"; then
        echo "$freebsd_update_cron" >>"$temp_crontab"
        echo "Added FreeBSD update cron job."
    else
        echo "FreeBSD update cron job already exists or not supported. Skipping..."
    fi

    # Add pkg update cron job if not already present
    if ! echo "$current_crontab" | grep -qF "$pkg_update_cmd"; then
        echo "$pkg_update_cron" >>"$temp_crontab"
        echo "Added pkg update cron job."
    else
        echo "pkg update cron job already exists. Skipping..."
    fi

    # Install the updated crontab
    crontab "$temp_crontab"

    # Clean up the temporary file
    rm "$temp_crontab"

    echo "Cron jobs for system and Suricata updates configured for the root user."
}

# Lock down sensitive system files
lock_down_system() {
    echo "Locking down critical system files..."
    for file in $service_scheduler_files; do
        echo "root" >"$file"
    done
    for file in $sensitive_files; do
        chmod o= "$file"
    done
    reapply_immutable_flags
    echo "System files locked down and cron/at restricted to root only."
}

# Main function to run all steps
main() {
    parse_arguments "$@"
    collect_user_input
    clear_immutable_flags
    backup_configs
    update_and_install_packages
    configure_password_and_umask
    configure_ssh
    configure_google_auth
    configure_ssh_pam
    configure_sudo
    configure_fail2ban
    if [ "$install_suricata" = "yes" ]; then
        configure_suricata
    fi
    configure_ipfw
    secure_syslog_and_tmp
    configure_cron_updates
    configure_securelevel
    harden_ttys
    harden_loader_conf
    harden_sysctl
    lock_down_system
    echo "Security hardening complete. Please reboot to apply all changes."
}

# Run the main function
main "$@"
