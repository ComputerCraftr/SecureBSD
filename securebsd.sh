#!/bin/sh

# Exit on errors and undefined variables
set -eu

###############################################################################
# Global Constants And State
###############################################################################

# Repository and managed-state paths
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
template_root="$script_dir/templates"
cutover_state_dir="/var/db/securebsd"
cutover_state_file="$cutover_state_dir/admin_cutover.state"

# Managed system config paths
sshd_config_file="/etc/ssh/sshd_config"
pam_sshd_config_file="/etc/pam.d/sshd"
loader_conf_file="/boot/loader.conf"
rc_conf_file="/etc/rc.conf"
managed_ipfw_rules_file="/etc/ipfw.rules"
source_ipfw_rules_file="$script_dir/ipfw.rules"
suricata_conf_file="/usr/local/etc/suricata/suricata.yaml"
suricata_custom_conf_file="/usr/local/etc/suricata/suricata-custom.yaml"
suricata_rules_file="/var/lib/suricata/rules/custom.rules"

# Immutable file sets
service_scheduler_files="/var/cron/allow /var/at/at.allow"
full_lockdown_files="$service_scheduler_files /etc/rc.firewall /etc/ipfw.rules /etc/crontab \
/usr/local/etc/sudoers /usr/local/etc/sudoers.d/sudo /etc/sysctl.conf /boot/loader.conf \
/boot/loader.rc /etc/fstab /etc/login.conf /etc/login.access /etc/newsyslog.conf \
/etc/ssh/sshd_config /etc/pam.d/sshd /etc/hosts /etc/hosts.allow /etc/ttys"
password_related_files="/etc/master.passwd"
service_related_files="/etc/rc.conf /usr/local/etc/anacrontab"
audit_log_files="/var/audit"
sensitive_files="$service_scheduler_files $password_related_files $service_related_files $audit_log_files"

# FreeBSD config literals
freebsd_true="YES"
freebsd_false="NO"

# Default input values
default_ssh_port="2222"
default_suricata_port="8000"
default_password_expiration_days="120"

# Shared policy strings and regex
sudo_policy_line='%sudo ALL=(ALL:ALL) ALL'
ssh_pam_ga_line='auth requisite pam_google_authenticator.so'
strict_ssh_effective_policy_lines='
passwordauthentication no
kbdinteractiveauthentication yes
pubkeyauthentication yes
usepam yes
authenticationmethods publickey,keyboard-interactive
'

# Firewall policy surfaces
firewall_full_scope_set="load,reapply,validate,render"
firewall_transition_scope_set="validate,render"
firewall_policy_var_defs="
internal_if=$firewall_full_scope_set
nat_if=$firewall_full_scope_set
tun_if=$firewall_full_scope_set
ssh_ipv4=$firewall_full_scope_set
ssh_ipv6=$firewall_full_scope_set
log_ssh_hits=$firewall_full_scope_set
log_wan_tcp_hits=$firewall_full_scope_set
allow_multicast=$firewall_full_scope_set
allow_multicast_legacy=$firewall_full_scope_set
suricata_port=$firewall_full_scope_set
install_suricata=reapply
ssh_port=render
port_transition_old_port=$firewall_transition_scope_set
"

# Managed FreeBSD config blocks
managed_firewall_rc_conf_settings='
firewall_enable=YES
firewall_script=/etc/ipfw.rules
firewall_logging=YES
'
suricata_rc_conf_settings='
suricata_enable=YES
'
fail2ban_rc_conf_settings='
fail2ban_enable=YES
'
securelevel_rc_conf_settings='
kern_securelevel_enable=YES
kern_securelevel=1
'
syslog_tmp_rc_conf_settings='
syslogd_flags=-ss
clear_tmp_enable=YES
'

# Operator-facing status and guidance messages
managed_cutover_cli_omit_message="Rerun without --user, --ssh-port, --disable-wheel, or --remove-wheel-members for a normal managed baseline reapply."
managed_cutover_cli_preserve_state_message="Do not clear the managed cutover state just to continue an existing managed cutover, especially during SSH port migration."
managed_cutover_cli_restart_message="Only clear the managed cutover state if you are intentionally abandoning the current managed cutover context and starting a brand-new staged cutover from scratch."
managed_ssh_port_transition_resolution_message="A new --ssh-port on a committed managed host uses the staged SSH port migration flow. Keep the managed cutover state in place and let the script perform the staged port transition; do not clear the managed cutover state just to change the SSH port."
committed_ssh_port_transition_mode_message="Committed managed state detected. This run is switching from fast-path baseline reapply to staged SSH port migration because --ssh-port changed."
pending_cutover_cli_resolution_message="An in-progress managed cutover already owns --user, --ssh-port, --disable-wheel, and --remove-wheel-members. Rerun without cutover-defining flags and use only --confirm-stage-advance yes to continue the current cutover."
stale_cutover_cli_resolution_message="The saved managed cutover state is stale or incomplete. Rerun without cutover-defining flags for ordinary managed maintenance. Only clear the managed cutover state if you are intentionally abandoning the current cutover context and starting a brand-new staged cutover from scratch; do not clear it to continue an SSH port migration."
pending_port_reboot_next_step="Reboot the host, verify a fresh login on the new SSH port, then rerun this script with --confirm-stage-advance yes to remove the old SSH port from the managed boot policy."
pending_port_commit_reboot_next_step="Reboot the host, verify a fresh login on the new SSH port again, then rerun this script with --confirm-stage-advance yes to finalize the port migration."

# Public operator inputs
public_cli_config_defaults="
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
disable_wheel=
remove_wheel_members=
confirm_stage_advance=
cpu_type=unknown
"
runtime_default_values="
allow_multicast=no
allow_multicast_legacy=no
confirm_stage_advance=no
"
package_option_default_values="
install_auditing=yes
install_microcode=yes
"

# Persisted cutover schema
cutover_state_var_defs='
cutover_stage=stage
cutover_boot_marker=direct
user=direct
cutover_user_uid=direct
ssh_port=direct
transitional_ssh_port=stage
disable_wheel=direct
remove_wheel_members=direct
wheel_sudo_finalized=direct
wheel_membership_finalized=direct
port_transition_old_port=stage
'

# Persisted internal cutover defaults
internal_cutover_state_defaults="
transitional_ssh_port=
wheel_sudo_finalized=
wheel_membership_finalized=
cutover_boot_marker=
port_transition_old_port=
"

# Derived mutable runtime state
public_cutover_fields="user ssh_port disable_wheel remove_wheel_members"
desired_mutable_baseline_settings=""
saved_public_cutover_settings=""

###############################################################################
# Generic Utility Helpers
###############################################################################

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

set_kv_defaults_if_empty() {
    kv_list=$1
    old_ifs=$IFS
    IFS='
'
    for entry in $kv_list; do
        [ -n "$entry" ] || continue
        set_var_if_empty "${entry%%=*}" "${entry#*=}"
    done
    IFS=$old_ifs
}

get_var_value() {
    target_var="$1"
    eval "printf '%s\n' \"\${$target_var-}\""
}

set_var_value() {
    target_var="$1"
    target_value="${2-}"
    eval "$target_var=\$target_value"
}

clear_vars() {
    var_list="$1"
    old_ifs=$IFS
    IFS=' '
    for target_var in $var_list; do
        [ -n "$target_var" ] || continue
        set_var_value "$target_var" ""
    done
    IFS=$old_ifs
}

set_var_if_empty() {
    target_var="$1"
    default_value="$2"
    current_value=$(get_var_value "$target_var")
    [ -n "$current_value" ] || set_var_value "$target_var" "$default_value"
}

set_default_if_empty() {
    var_name=$1
    default_value=$2
    set_var_if_empty "$var_name" "$default_value"
}

say() {
    printf '%s\n' "$*"
}

say_err() {
    printf '%s\n' "$*" >&2
}

warn_msg() {
    say "Warning: $*"
}

error_msg() {
    say_err "Error: $*"
}

defined_kv_vars() {
    kv_list="$1"
    old_ifs=$IFS
    IFS='
'
    for entry in $kv_list; do
        [ -n "$entry" ] || continue
        printf '%s ' "${entry%%=*}"
    done
    IFS=$old_ifs
}

policy_vars_for_scope() {
    target_scope="$1"
    old_ifs=$IFS
    IFS='
'
    for policy_entry in $firewall_policy_var_defs; do
        [ -n "$policy_entry" ] || continue
        policy_var=${policy_entry%%=*}
        policy_scopes=${policy_entry#*=}
        case ",$policy_scopes," in
        *",$target_scope,"*)
            printf '%s ' "$policy_var"
            ;;
        esac
    done
    IFS=$old_ifs
}

cutover_state_value() {
    state_field="$1"

    case "$(settings_block_value "$cutover_state_var_defs" "$state_field" 2>/dev/null || printf 'direct')" in
    stage)
        stage_owned_cutover_state_value "$state_field"
        ;;
    *)
        get_var_value "$state_field"
        ;;
    esac
}

resolved_wheel_policy_finalized_state() {
    requested_value="$1"
    finalized_value="$2"
    if ! value_is_yes "$requested_value" || value_is_yes "$finalized_value"; then
        printf '%s\n' "yes"
    else
        printf '%s\n' "no"
    fi
}

value_is_yes() {
    [ "${1:-no}" = "yes" ]
}

value_is_none() {
    [ "${1:-}" = "none" ]
}

value_is_configured() {
    [ -n "${1:-}" ] && ! value_is_none "$1"
}

resolve_install_suricata_default() {
    if [ -z "${install_suricata-}" ]; then
        if value_is_configured "${suricata_port-}"; then
            install_suricata="yes"
        else
            install_suricata="no"
        fi
    fi
}

resolve_suricata_port_default() {
    if suricata_requested; then
        set_var_if_empty "suricata_port" "$default_suricata_port"
    fi
}

resolve_runtime_defaults() {
    set_kv_defaults_if_empty "$runtime_default_values"
    resolve_install_suricata_default
    resolve_suricata_port_default
}

resolve_package_option_defaults() {
    set_kv_defaults_if_empty "$package_option_default_values"
    resolve_install_suricata_default
}

detect_cpu_type() {
    cpu_info=$(sysctl -n hw.model | tr '[:upper:]' '[:lower:]')
    if printf '%s\n' "$cpu_info" | grep -qF "intel"; then
        printf '%s\n' "intel"
    elif printf '%s\n' "$cpu_info" | grep -qF "amd"; then
        printf '%s\n' "amd"
    else
        printf '%s\n' "unknown"
    fi
}

validate_cpu_type() {
    case "$1" in
    intel | amd | unknown)
        ;;
    *)
        error_msg "Invalid cpu_type '$1'. Use intel, amd, or unknown."
        return 1
        ;;
    esac
}

resolve_password_expiration_value() {
    set_var_if_empty "password_exp" "$default_password_expiration_days"

    case "$password_exp" in
    none)
        printf '%s\n' "none"
        ;;
    *d)
        printf '%s\n' "$password_exp"
        ;;
    *)
        printf '%sd\n' "$password_exp"
        ;;
    esac
}

validate_password_expiration_value() {
    value="$1"

    case "$value" in
    none)
        return 0
        ;;
    *d)
        validate_password_expiration "${value%d}"
        ;;
    *)
        validate_password_expiration "$value"
        ;;
    esac
}

validate_suricata_cli_consistency() {
    if value_is_configured "${suricata_port-}" && ! suricata_requested; then
        error_msg "--suricata-port requires --install-suricata yes."
        return 1
    fi

    if suricata_requested && value_is_none "${suricata_port:-}"; then
        error_msg "--install-suricata yes requires a real --suricata-port, not 'none'."
        return 1
    fi

    if suricata_requested && suricata_ports_defined && ! value_is_configured "${nat_if:-none}"; then
        error_msg "Suricata firewall integration requires --nat-if to be set to a real interface."
        return 1
    fi
}

set_kv_defaults "$public_cli_config_defaults"
set_kv_defaults "$internal_cutover_state_defaults"

reapplied_firewall_vars=$(policy_vars_for_scope reapply)
loaded_firewall_vars=$(policy_vars_for_scope load)
validated_firewall_vars=$(policy_vars_for_scope validate)
rendered_firewall_vars=$(policy_vars_for_scope render)
supported_cli_options=$(defined_kv_vars "$public_cli_config_defaults")
persisted_cutover_state_vars=$(defined_kv_vars "$cutover_state_var_defs")

# Captured CLI identity/policy values
cli_user="${user-}"
cli_ssh_port="${ssh_port-}"
cli_disable_wheel="${disable_wheel-}"
cli_remove_wheel_members="${remove_wheel_members-}"

capture_desired_mutable_baseline_settings() {
    desired_mutable_baseline_settings=$(settings_block_for_vars "$reapplied_firewall_vars")
}

restore_desired_mutable_baseline_settings() {
    restore_vars_from_settings_block "$reapplied_firewall_vars" "$desired_mutable_baseline_settings"
}

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    say_err "This script must be run as root. Please use sudo or run as root user."
    exit 1
fi

###############################################################################
# Validation Helpers
###############################################################################

# Validate the existence of a user
validate_user() {
    if ! id "$1" >/dev/null 2>&1; then
        say_err "User '$1' does not exist."
        return 1
    fi
}

# Validate SSH port input
validate_port() {
    if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        error_msg "Invalid port number '$1'. Port must be an integer between 1 and 65535."
        return 1
    fi
}

# Validate network interface
validate_interface() {
    if ! ifconfig "$1" >/dev/null 2>&1; then
        error_msg "Invalid interface '$1'. Please enter a valid network interface."
        return 1
    fi
}

# Validate password expiration input
validate_password_expiration() {
    if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -le 0 ]; then
        error_msg "Invalid password expiration '$1'. Days must be a positive integer."
        return 1
    fi
}

validate_yes_no() {
    value="$1"
    option_name="$2"
    if [ "$value" != "yes" ] && [ "$value" != "no" ]; then
        say_err "Invalid value for $option_name: $value (use yes or no)."
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
    [ -z "$value" ] || value_is_none "$value" || validate_interface "$value"
}

user_in_group() {
    target_user="$1"
    target_group="$2"
    id -Gn "$target_user" | tr ' ' '\n' | grep -qx "$target_group"
}

set_user_auth_paths() {
    auth_user="$1"
    ssh_dir="/home/$auth_user/.ssh"
    ssh_key="$ssh_dir/id_ed25519"
    ssh_pub_key="${ssh_key}.pub"
    authorized_keys="$ssh_dir/authorized_keys"
    ga_config="/home/$auth_user/.google_authenticator"
}

read_simple_assignment_value() {
    target_file="$1"
    target_key="$2"

    [ -f "$target_file" ] || return 1

    awk -v target_key="$target_key" '
        index($0, "=") {
            key = substr($0, 1, index($0, "=") - 1)
            if (key != target_key) {
                next
            }
            value = substr($0, index($0, "=") + 1)
            sub(/^"/, "", value)
            sub(/"$/, "", value)
            print value
            found = 1
            exit
        }
        END { exit(found ? 0 : 1) }
    ' "$target_file"
}

assignment_settings_block_from_file() {
    target_file="$1"

    [ -f "$target_file" ] || return 1

    awk '
        index($0, "=") {
            key = substr($0, 1, index($0, "=") - 1)
            value = substr($0, index($0, "=") + 1)
            sub(/^"/, "", value)
            sub(/"$/, "", value)
            print key "=" value
        }
    ' "$target_file"
}

text_has_all_exact_lines() {
    text_block="$1"
    expected_lines="$2"

    printf '%s\n' "$text_block" |
        awk -v expected_lines="$expected_lines" '
            BEGIN {
                expected_count = split(expected_lines, expected, "\n")
                for (i = 1; i <= expected_count; i++) {
                    if (expected[i] != "") {
                        required[expected[i]] = 1
                    }
                }
            }
            {
                seen[$0] = 1
            }
            END {
                for (line in required) {
                    if (!(line in seen)) {
                        exit 1
                    }
                }
            }
        '
}

file_has_all_exact_lines() {
    target_file="$1"
    expected_lines="$2"
    [ -f "$target_file" ] || return 1
    text_has_all_exact_lines "$(cat "$target_file")" "$expected_lines"
}

settings_block_value() {
    settings_block="$1"
    target_key="$2"
    printf '%s\n' "$settings_block" |
        awk -F '=' -v target_key="$target_key" '
            $1 == target_key {
                value = substr($0, index($0, "=") + 1)
                print value
                found = 1
                exit
            }
            END { exit(found ? 0 : 1) }
        '
}

settings_block_for_vars() {
    var_list="$1"
    settings_block_for_vars_with_value_fn "$var_list" "get_var_value"
}

settings_block_for_vars_with_value_fn() {
    var_list="$1"
    value_fn="$2"
    old_ifs=$IFS
    IFS=' '
    for var_name in $var_list; do
        [ -n "$var_name" ] || continue
        var_value=$("$value_fn" "$var_name")
        printf '%s=%s\n' "$var_name" "${var_value-}"
    done
    IFS=$old_ifs
}

each_settings_block_entry() {
    settings_block="$1"
    callback_fn="$2"
    old_ifs=$IFS
    IFS='
'
    for setting in $settings_block; do
        [ -n "$setting" ] || continue
        "$callback_fn" "${setting%%=*}" "${setting#*=}"
    done
    IFS=$old_ifs
}

quoted_setting_line() {
    key="$1"
    value="$2"
    escaped_value=$(printf '%s' "$value" | sed 's/["\\]/\\&/g')
    printf '%s="%s"\n' "$key" "$escaped_value"
}

emit_overridden_settings_entry() {
    setting_key="$1"
    setting_value="$2"
    override_value=$(settings_block_value "$current_settings_overrides" "$setting_key" 2>/dev/null || printf '%s' "$setting_value")
    printf '%s=%s\n' "$setting_key" "$override_value"
}

emit_quoted_settings_entry() {
    setting_key="$1"
    setting_value="$2"
    quoted_setting_line "$setting_key" "$setting_value"
}

apply_sysrc_settings_entry() {
    setting_key="$1"
    setting_value="$2"
    sysrc "$(quoted_setting_line "$setting_key" "$setting_value")"
}

settings_block_with_overrides() {
    base_block="$1"
    current_settings_overrides="$2"
    each_settings_block_entry "$base_block" "emit_overridden_settings_entry"
}

render_quoted_settings_block() {
    settings_block="$1"
    each_settings_block_entry "$settings_block" "emit_quoted_settings_entry"
}

settings_blocks_match() {
    expected_block="$1"
    actual_block="$2"

    awk -v expected_block="$expected_block" -v actual_block="$actual_block" '
        BEGIN {
            expected_count = split(expected_block, expected_lines, "\n")
            for (i = 1; i <= expected_count; i++) {
                if (expected_lines[i] == "") {
                    continue
                }
                split(expected_lines[i], expected_parts, "=")
                expected_key = expected_parts[1]
                expected_value = substr(expected_lines[i], index(expected_lines[i], "=") + 1)
                expected_map[expected_key] = expected_value
            }

            actual_count = split(actual_block, actual_lines, "\n")
            for (i = 1; i <= actual_count; i++) {
                if (actual_lines[i] == "") {
                    continue
                }
                split(actual_lines[i], actual_parts, "=")
                actual_key = actual_parts[1]
                actual_value = substr(actual_lines[i], index(actual_lines[i], "=") + 1)
                actual_map[actual_key] = actual_value
            }

            for (key in expected_map) {
                if (!(key in actual_map) || actual_map[key] != expected_map[key]) {
                    exit 1
                }
            }
        }
    ' </dev/null
}

restore_vars_from_settings_block() {
    var_list="$1"
    settings_block="$2"
    only_if_missing="${3:-no}"
    wanted_vars=" $var_list "

    each_settings_block_entry "$settings_block" "restore_settings_block_entry"
}

restore_settings_block_entry() {
    target_var="$1"
    target_value="$2"

    case "$wanted_vars" in
    *" $target_var "*) ;;
    *)
        return 0
        ;;
    esac

    if [ "$only_if_missing" = "yes" ] && [ -n "$(get_var_value "$target_var")" ]; then
        return 0
    fi

    set_var_value "$target_var" "$target_value"
}

sudo_policy_is_valid() {
    [ -f /usr/local/etc/sudoers.d/sudo ] &&
        grep -qxF "$sudo_policy_line" /usr/local/etc/sudoers.d/sudo &&
        visudo -c >/dev/null
}

wheel_sudo_is_active() {
    awk '
        /^%wheel[[:blank:]]+ALL=\(ALL(:ALL)?\)[[:blank:]]+(NOPASSWD:[[:blank:]]+)?ALL$/ {
            found = 1
            exit
        }
        END { exit(found ? 0 : 1) }
    ' /usr/local/etc/sudoers ||
        { [ -f /usr/local/etc/sudoers.d/wheel ] && [ ! -f /usr/local/etc/sudoers.d/wheel.disabled ]; }
}

non_root_wheel_members_present() {
    getent group wheel | cut -d ':' -f 4 | tr ',' '\n' | grep -qEv '^(|root)$'
}

load_live_managed_firewall_context() {
    [ -f "$managed_ipfw_rules_file" ] || return 0
    managed_firewall_settings=$(assignment_settings_block_from_file "$managed_ipfw_rules_file" 2>/dev/null || printf '')
    restore_vars_from_settings_block "$loaded_firewall_vars" "$managed_firewall_settings" "yes"

    resolve_install_suricata_default
}

###############################################################################
# SSH, Firewall, And Live-State Validation
###############################################################################

effective_sshd_has_line() {
    sshd_effective="$1"
    expected_line="$2"
    printf '%s\n' "$sshd_effective" | grep -qxF "$expected_line"
}

effective_sshd_lacks_line() {
    sshd_effective="$1"
    blocked_line="$2"
    if effective_sshd_has_line "$sshd_effective" "$blocked_line"; then
        return 1
    fi
}

effective_sshd_matches_lines() {
    sshd_effective="$1"
    expected_lines="$2"
    text_has_all_exact_lines "$sshd_effective" "$expected_lines"
}

normalize_csv_set() {
    csv_value="$1"

    if [ -z "$csv_value" ]; then
        printf '\n'
        return 0
    fi

    printf '%s\n' "$csv_value" |
        tr ',' '\n' |
        sed '/^$/d' |
        sort -u |
        paste -sd, -
}

compose_normalized_port_set() {
    primary_port="$1"
    extra_port="${2:-}"

    ports_csv="$primary_port"
    if value_is_configured "$extra_port" && [ "$extra_port" != "$primary_port" ]; then
        ports_csv="$extra_port,$primary_port"
    fi

    normalize_csv_set "$ports_csv"
}

csv_items_lines() {
    csv_value="$1"

    [ -n "$csv_value" ] || return 0

    printf '%s\n' "$csv_value" |
        tr ',' '\n' |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d'
}

group_member_lines() {
    group_name="$1"
    getent group "$group_name" | cut -d ':' -f 4 | tr ',' '\n' | sed '/^$/d'
}

append_line_block() {
    line_block="$1"
    new_line="$2"
    if [ -n "$line_block" ]; then
        printf '%s\n%s\n' "$line_block" "$new_line"
    else
        printf '%s\n' "$new_line"
    fi
}

normalize_line_block_csv() {
    line_block="$1"
    printf '%s\n' "$line_block" | sed '/^$/d' | awk '!seen[$0]++' | paste -sd, -
}

update_group_membership() {
    group_name="$1"
    action="$2"
    user_list="$3"
    success_message="$4"
    empty_message="$5"
    changed_users=""

    for member_user in $user_list; do
        [ -n "$member_user" ] || continue
        case "$action" in
        add)
            pw groupmod "$group_name" -m "$member_user"
            ;;
        remove)
            pw groupmod "$group_name" -d "$member_user"
            ;;
        *)
            error_msg "Unknown group membership action '$action'."
            return 1
            ;;
        esac
        changed_users=$(append_line_block "$changed_users" "$member_user")
    done

    if [ -n "$changed_users" ]; then
        say "$success_message $(normalize_line_block_csv "$changed_users")"
    else
        say "$empty_message"
    fi
}

load_effective_sshd() {
    if ! sshd -t -f "$sshd_config_file" >/dev/null 2>&1; then
        return 1
    fi

    sshd -T -f "$sshd_config_file" 2>/dev/null
}

effective_sshd_ports_csv() {
    sshd_effective="$1"
    actual_ports_csv=$(printf '%s\n' "$sshd_effective" |
        awk '$1 == "port" { print $2 }' |
        sort -u |
        paste -sd, -)
    normalize_csv_set "$actual_ports_csv"
}

effective_sshd_ports_match() {
    sshd_effective="$1"
    expected_ports_csv="$2"
    [ "$(effective_sshd_ports_csv "$sshd_effective")" = "$(normalize_csv_set "$expected_ports_csv")" ]
}

effective_sshd_has_single_port() {
    sshd_effective="$1"
    port_count=$(printf '%s\n' "$sshd_effective" | awk '$1 == "port" { count++ } END { print count + 0 }')
    [ "$port_count" -eq 1 ]
}

effective_sshd_allowusers_includes() {
    sshd_effective="$1"
    allow_user="$2"
    printf '%s\n' "$sshd_effective" |
        awk -v allow_user="$allow_user" '
            $1 == "allowusers" {
                for (i = 2; i <= NF; i++) {
                    if ($i == allow_user) {
                        found = 1
                    }
                }
            }
            END { exit(found ? 0 : 1) }
        '
}

admin_access_error() {
    error_msg "$1. Deferred admin fallback policy has not been changed."
}

strict_ssh_config_ready() {
    [ -n "${user-}" ] || return 1
    [ -n "${ssh_port-}" ] || return 1

    sshd_effective=$(load_effective_sshd) || return 1

    effective_sshd_matches_lines "$sshd_effective" "$strict_ssh_effective_policy_lines" &&
        effective_sshd_ports_match "$sshd_effective" "$ssh_port" &&
        effective_sshd_allowusers_includes "$sshd_effective" "$user"
}

transitional_ssh_config_ready() {
    [ -n "${user-}" ] || return 1

    sshd_effective=$(load_effective_sshd) || return 1

    effective_sshd_has_line "$sshd_effective" "passwordauthentication yes" &&
        effective_sshd_has_line "$sshd_effective" "kbdinteractiveauthentication yes" &&
        effective_sshd_has_line "$sshd_effective" "pubkeyauthentication yes" &&
        effective_sshd_has_line "$sshd_effective" "usepam yes" &&
        effective_sshd_allowusers_includes "$sshd_effective" "$user" &&
        effective_sshd_has_single_port "$sshd_effective" &&
        [ -n "${transitional_ssh_port:-}" ] &&
        effective_sshd_ports_match "$sshd_effective" "$transitional_ssh_port" &&
        effective_sshd_lacks_line "$sshd_effective" "authenticationmethods publickey,keyboard-interactive"
}

pending_port_transition_sshd_matches_state() {
    [ -n "${user-}" ] || return 1
    [ -n "${ssh_port-}" ] || return 1

    sshd_effective=$(load_effective_sshd) || return 1

    case "${cutover_stage:-}" in
    pending_port_transition_reboot)
        effective_sshd_matches_lines "$sshd_effective" "$strict_ssh_effective_policy_lines" &&
            effective_sshd_allowusers_includes "$sshd_effective" "$user" &&
            effective_sshd_ports_match "$sshd_effective" "$port_transition_old_port,$ssh_port"
        ;;
    pending_port_commit_reboot)
        effective_sshd_matches_lines "$sshd_effective" "$strict_ssh_effective_policy_lines" &&
            effective_sshd_allowusers_includes "$sshd_effective" "$user" &&
            effective_sshd_ports_match "$sshd_effective" "$ssh_port"
        ;;
    *)
        return 1
        ;;
    esac
}

ssh_admin_path_matches_state() {
    [ -n "${user-}" ] || return 1
    validate_user "$user" >/dev/null 2>&1 || return 1
    strict_ssh_config_ready || return 1
    set_user_auth_paths "$user"
    [ -f "$authorized_keys" ] &&
        [ -s "$authorized_keys" ] &&
        [ -f "$ga_config" ] &&
        [ -s "$ga_config" ]
}

cutover_state_matches_live_identity() {
    [ -n "${user-}" ] || return 1
    [ -n "${cutover_user_uid-}" ] || return 1
    validate_user "$user" >/dev/null 2>&1 || return 1
    [ "$(id -u "$user")" = "$cutover_user_uid" ]
}

sudo_admin_path_matches_state() {
    [ -n "${user-}" ] || return 1
    validate_user "$user" >/dev/null 2>&1 || return 1
    sudo_policy_is_valid &&
        user_in_group "$user" "sudo"
}

option_enabled() {
    option_var="$1"
    set_default_if_empty "$option_var" "no"
    value_is_yes "$(get_var_value "$option_var")"
}

freebsd_bool_value() {
    if value_is_yes "${1:-no}"; then
        printf '%s\n' "$freebsd_true"
    else
        printf '%s\n' "$freebsd_false"
    fi
}

freebsd_true_setting() {
    quoted_setting_line "$1" "$freebsd_true"
}

resolved_option_enabled() {
    requested_var="$1"
    finalized_var="$2"
    value_is_yes "$(resolved_finalized_state "$requested_var" "$finalized_var")"
}

resolved_finalized_state() {
    requested_var="$1"
    finalized_var="$2"
    set_default_if_empty "$finalized_var" "no"
    requested_value=$(option_enabled "$requested_var" && printf 'yes' || printf 'no')
    resolved_wheel_policy_finalized_state "$requested_value" "$(get_var_value "$finalized_var")"
}

wheel_policy_fully_finalized() {
    resolved_option_enabled "disable_wheel" "wheel_sudo_finalized" &&
        resolved_option_enabled "remove_wheel_members" "wheel_membership_finalized"
}

suricata_requested() {
    resolve_install_suricata_default
    option_enabled "install_suricata"
}

suricata_ports_defined() {
    value_is_configured "${suricata_port:-none}"
}

record_committed_cutover_state() {
    wheel_policy_state="${1:-current}"
    cutover_boot_marker=""

    case "$wheel_policy_state" in
    final)
        wheel_sudo_finalized="yes"
        wheel_membership_finalized="yes"
        ;;
    pending)
        wheel_sudo_finalized=$(option_enabled "disable_wheel" && printf 'no' || printf 'yes')
        wheel_membership_finalized=$(option_enabled "remove_wheel_members" && printf 'no' || printf 'yes')
        ;;
    current)
        wheel_sudo_finalized=$(resolved_finalized_state "disable_wheel" "wheel_sudo_finalized")
        wheel_membership_finalized=$(resolved_finalized_state "remove_wheel_members" "wheel_membership_finalized")
        ;;
    *)
        error_msg "Unknown wheel policy state '$wheel_policy_state'."
        return 1
        ;;
    esac

    write_cutover_state "committed_strict_ready" "$wheel_sudo_finalized" "$wheel_membership_finalized"
}

wheel_sudo_matches_saved_policy() {
    if ! option_enabled "disable_wheel"; then
        return 0
    fi

    if resolved_option_enabled "disable_wheel" "wheel_sudo_finalized"; then
        if wheel_sudo_is_active; then
            return 1
        fi
        return 0
    fi

    wheel_sudo_is_active
}

wheel_membership_matches_saved_policy() {
    if ! option_enabled "remove_wheel_members"; then
        return 0
    fi

    if resolved_option_enabled "remove_wheel_members" "wheel_membership_finalized"; then
        if non_root_wheel_members_present; then
            return 1
        fi
        return 0
    fi

    non_root_wheel_members_present
}

firewall_rules_match_state() {
    [ -f "$managed_ipfw_rules_file" ] || return 1

    expected_settings=$(settings_block_for_vars "$validated_firewall_vars")
    actual_settings=$(assignment_settings_block_from_file "$managed_ipfw_rules_file" 2>/dev/null || printf '')
    settings_blocks_match "$expected_settings" "$actual_settings"
}

firewall_boot_state_matches_state() {
    file_has_all_exact_lines "$loader_conf_file" "$(build_firewall_loader_settings)" &&
        file_has_all_exact_lines "$rc_conf_file" "$(render_quoted_settings_block "$managed_firewall_rc_conf_settings")" &&
        firewall_rules_match_state &&
        suricata_config_matches_state
}

staged_live_ssh_ports() {
    case "${cutover_stage:-}" in
    pending_transitional_verify)
        printf '%s\n' "${transitional_ssh_port:-}"
        ;;
    pending_port_transition_reboot)
        compose_normalized_port_set "$ssh_port" "${port_transition_old_port:-}"
        ;;
    *)
        compose_normalized_port_set "$ssh_port"
        ;;
    esac
}

suricata_ssh_ports_value() {
    ssh_ports_csv="$1"

    case "$ssh_ports_csv" in
    *,*)
        printf '[%s]\n' "$(printf '%s' "$ssh_ports_csv" | sed 's/,/, /g')"
        ;;
    *)
        printf '%s\n' "$ssh_ports_csv"
        ;;
    esac
}

normalize_suricata_ssh_ports_value() {
    ssh_ports_value="$1"

    normalized_value=$(printf '%s' "$ssh_ports_value" | tr -d '[]' | tr -d '[:space:]')
    normalize_csv_set "$normalized_value"
}

suricata_ssh_rule_ports_value() {
    ssh_ports_csv="$1"

    case "$ssh_ports_csv" in
    *,*)
        printf '[%s]\n' "$ssh_ports_csv"
        ;;
    *)
        printf '%s\n' "$ssh_ports_csv"
        ;;
    esac
}

managed_suricata_ssh_rule() {
    ssh_ports_csv="$1"
    suricata_rule_ports=$(suricata_ssh_rule_ports_value "$ssh_ports_csv")
    printf '%s\n' "alert tcp any any -> any $suricata_rule_ports (msg:\"Managed SSH connection on staged ports $suricata_rule_ports\"; sid:1000001; rev:2;)"
}

suricata_config_matches_state() {
    ssh_ports_csv=$(staged_live_ssh_ports)
    expected_yaml_ports=$(suricata_ssh_ports_value "$ssh_ports_csv")
    expected_rule_ports=$(normalize_csv_set "$ssh_ports_csv")

    if ! suricata_requested || ! suricata_ports_defined; then
        return 0
    fi

    [ -f "$suricata_conf_file" ] || return 1
    [ -f "$suricata_custom_conf_file" ] || return 1
    [ -f "$suricata_rules_file" ] || return 1

    grep -q "^include: $suricata_custom_conf_file" "$suricata_conf_file" || return 1

    actual_ssh_ports=$(awk '
        /^[[:space:]]*SSH_PORTS:[[:space:]]*/ {
            sub(/^[[:space:]]*SSH_PORTS:[[:space:]]*/, "", $0)
            print
            exit
        }
    ' "$suricata_conf_file")
    [ "$(normalize_suricata_ssh_ports_value "$actual_ssh_ports")" = "$(normalize_suricata_ssh_ports_value "$expected_yaml_ports")" ] || return 1

    awk -v expected_rule_ports="$expected_rule_ports" '
        /sid:1000001;/ {
            count++
            rule = $0
            sub(/^alert tcp any any -> any /, "", rule)
            sub(/ \(msg:.*$/, "", rule)
            gsub(/\[|\]| /, "", rule)
            if (rule == expected_rule_ports) {
                match_count++
            }
        }
        END { exit(count == 1 && match_count == 1 ? 0 : 1) }
    ' "$suricata_rules_file"
}

runtime_has_managed_ssh_rule() {
    runtime_rules="$1"
    address_family="$2"
    expected_ports="$3"

    case "$address_family" in
    ipv4)
        value_is_configured "${ssh_ipv4:-}" || return 0
        expected_source="$ssh_ipv4"
        expected_destination="me"
        ;;
    ipv6)
        value_is_configured "${ssh_ipv6:-}" || return 0
        expected_source="$ssh_ipv6"
        expected_destination="me6"
        ;;
    *)
        return 1
        ;;
    esac

    expected_ports=$(normalize_csv_set "$expected_ports")
    candidate_ports=$(
        printf '%s\n' "$runtime_rules" |
            awk -v expected_source="$expected_source" -v expected_destination="$expected_destination" '
                {
                    line = $0
                    sub(/^[0-9]+[[:space:]]+/, "", line)
                    source_pattern = " from " expected_source " to " expected_destination " "
                    tcpflags_pattern = " tcpflags syn,!ack,!fin,!rst in limit dst-addr 2"
                    source_index = index(line, source_pattern)
                    tcpflags_index = index(line, tcpflags_pattern)
                    if (substr(line, 1, 6) != "allow " || source_index == 0 || tcpflags_index == 0 || tcpflags_index <= source_index) {
                        next
                    }
                    ports = substr(line, source_index + length(source_pattern), tcpflags_index - (source_index + length(source_pattern)))
                    print ports
                }
            '
    )

    while IFS= read -r actual_ports; do
        [ -n "$actual_ports" ] || continue
        if [ "$(normalize_csv_set "$actual_ports")" = "$expected_ports" ]; then
            return 0
        fi
    done <<EOF
$candidate_ports
EOF

    return 1
}

runtime_has_managed_suricata_divert_rule() {
    runtime_rules="$1"

    if ! suricata_requested || ! suricata_ports_defined || ! value_is_configured "${nat_if:-none}"; then
        return 0
    fi

    expected_rule="divert $suricata_port ip from any to any not proto icmp not proto ipv6-icmp in recv $nat_if"
    printf '%s\n' "$runtime_rules" | grep -Fq "$expected_rule"
}

runtime_has_managed_nat_rule() {
    runtime_rules="$1"

    if ! value_is_configured "${nat_if:-none}"; then
        return 0
    fi

    expected_rule="nat 1 ip4 from any to any via $nat_if"
    printf '%s\n' "$runtime_rules" | grep -Fq "$expected_rule"
}

firewall_runtime_state_class() {
    runtime_rules=""
    expected_ssh_ports=""

    if ! kldstat -q -m ipfw >/dev/null 2>&1; then
        printf '%s\n' "absent"
        return 0
    fi

    runtime_rules=$(ipfw list 2>/dev/null) || {
        printf '%s\n' "misaligned"
        return 0
    }
    if ! printf '%s\n' "$runtime_rules" | grep -q '[[:digit:]]'; then
        printf '%s\n' "misaligned"
        return 0
    fi

    expected_ssh_ports=$(staged_live_ssh_ports)
    if ! runtime_has_managed_ssh_rule "$runtime_rules" ipv4 "$expected_ssh_ports" ||
        ! runtime_has_managed_ssh_rule "$runtime_rules" ipv6 "$expected_ssh_ports"; then
        printf '%s\n' "misaligned"
        return 0
    fi

    if ! ipfw table all list >/dev/null 2>&1; then
        printf '%s\n' "misaligned"
        return 0
    fi

    if value_is_configured "${nat_if:-none}"; then
        if ! runtime_has_managed_nat_rule "$runtime_rules" || ! ipfw nat show config >/dev/null 2>&1; then
            printf '%s\n' "misaligned"
            return 0
        fi
    fi

    if suricata_requested && suricata_ports_defined; then
        if ! runtime_has_managed_suricata_divert_rule "$runtime_rules"; then
            printf '%s\n' "misaligned"
            return 0
        fi
    fi

    printf '%s\n' "aligned"
}

warn_if_firewall_runtime_absent() {
    runtime_state="${1:-$(firewall_runtime_state_class 2>/dev/null || printf '')}"
    if [ "$runtime_state" = "absent" ]; then
        warn_msg "Managed firewall boot state is committed, but runtime ipfw is currently inactive. A future reboot or firewall activation will enforce the managed rules."
    fi
}

validate_pending_port_transition_alignment() {
    active_boot_marker=$(current_boot_marker)
    if [ -n "${cutover_boot_marker:-}" ] && [ -n "$active_boot_marker" ] && [ "$active_boot_marker" = "$cutover_boot_marker" ]; then
        error_msg "The host has not rebooted since the pending SSH port transition state was written. Reboot and verify login on the new SSH port before advancing this stage."
        return 1
    fi
    validate_stage_alignment_common "pending_port_transition" "pending_port_transition_sshd_matches_state" "yes"
}

validate_pending_transitional_alignment() {
    validate_stage_alignment_common "pending_transitional" "transitional_ssh_config_ready"
}

managed_state_is_aligned_with_live_state() {
    [ "${cutover_stage:-}" = "committed_strict_ready" ] || {
        cutover_alignment_error="cutover stage is not committed_strict_ready"
        return 1
    }

    cutover_state_matches_live_identity || {
        cutover_alignment_error="saved managed user identity no longer matches the live account"
        return 1
    }

    ssh_admin_path_matches_state || {
        cutover_alignment_error="managed SSH public key or Google Authenticator path is no longer aligned"
        return 1
    }

    managed_admin_path_matches_state || {
        cutover_alignment_error="managed admin path is no longer aligned"
        return 1
    }

    if ! wheel_sudo_matches_saved_policy; then
        cutover_alignment_error="saved %wheel sudo policy no longer matches the live host"
        return 1
    fi

    if ! wheel_membership_matches_saved_policy; then
        cutover_alignment_error="saved wheel group membership policy no longer matches the live host"
        return 1
    fi

    if ! firewall_boot_state_matches_state; then
        cutover_alignment_error="managed firewall boot state is no longer aligned"
        return 1
    fi

    runtime_state=$(firewall_runtime_state_class) || {
        cutover_alignment_error="managed firewall runtime state could not be classified"
        return 1
    }
    if [ "$runtime_state" = "misaligned" ]; then
        cutover_alignment_error="managed firewall runtime state is loaded but no longer aligned"
        return 1
    fi
}

managed_ssh_auth_assets_ready() {
    set_user_auth_paths "$user"
    [ -f "$authorized_keys" ] && [ -s "$authorized_keys" ] &&
        [ -f "$ga_config" ] && [ -s "$ga_config" ]
}

stage_identity_context_label() {
    case "$1" in
    pending_port_transition)
        printf '%s\n' "saved SSH port transition state"
        ;;
    pending_transitional)
        printf '%s\n' "pending transitional SSH verification state"
        ;;
    pending_strict)
        printf '%s\n' "pending strict SSH verification state"
        ;;
    *)
        error_msg "Unknown stage identity context '$1'."
        return 1
        ;;
    esac
}

stage_alignment_error_message() {
    stage_key="$1"
    subject="$2"

    case "$stage_key:$subject" in
    pending_port_transition:ssh)
        printf '%s\n' "The live sshd configuration no longer matches the pending SSH port transition state."
        ;;
    pending_port_transition:auth)
        printf '%s\n' "The managed SSH public key or Google Authenticator path no longer matches the pending SSH port transition state."
        ;;
    pending_port_transition:sudo)
        printf '%s\n' "The managed sudo path no longer matches the pending SSH port transition state."
        ;;
    pending_port_transition:wheel_sudo)
        printf '%s\n' "The saved %wheel sudo policy no longer matches the live host during the SSH port transition."
        ;;
    pending_port_transition:wheel_members)
        printf '%s\n' "The saved wheel membership policy no longer matches the live host during the SSH port transition."
        ;;
    pending_port_transition:firewall_boot)
        printf '%s\n' "The managed firewall boot state no longer matches the pending SSH port transition."
        ;;
    pending_port_transition:firewall_runtime_classify)
        printf '%s\n' "The live ipfw runtime state could not be classified during the SSH port transition."
        ;;
    pending_port_transition:firewall_runtime_misaligned)
        printf '%s\n' "The live ipfw runtime state no longer matches the pending SSH port transition."
        ;;
    pending_transitional:ssh)
        printf '%s\n' "The live sshd configuration no longer matches the pending transitional SSH verification state."
        ;;
    pending_transitional:auth)
        printf '%s\n' "The managed SSH public key or Google Authenticator path no longer matches the pending transitional SSH verification state."
        ;;
    pending_transitional:sudo)
        printf '%s\n' "The managed sudo path no longer matches the pending transitional SSH verification state."
        ;;
    pending_transitional:wheel_sudo)
        printf '%s\n' "The saved %wheel sudo policy no longer matches the live host during pending transitional verification."
        ;;
    pending_transitional:wheel_members)
        printf '%s\n' "The saved wheel membership policy no longer matches the live host during pending transitional verification."
        ;;
    pending_strict:ssh | pending_strict:auth)
        printf '%s\n' "The managed SSH public key, Google Authenticator, or strict sshd configuration no longer matches the pending strict SSH verification state."
        ;;
    pending_strict:sudo)
        printf '%s\n' "The managed sudo path no longer matches the pending strict SSH verification state."
        ;;
    pending_strict:wheel_sudo)
        printf '%s\n' "The saved %wheel sudo policy no longer matches the live host during pending strict verification."
        ;;
    pending_strict:wheel_members)
        printf '%s\n' "The saved wheel membership policy no longer matches the live host during pending strict verification."
        ;;
    pending_strict:firewall_boot)
        printf '%s\n' "The managed firewall boot state no longer matches the pending strict SSH verification state."
        ;;
    pending_strict:firewall_runtime_classify)
        printf '%s\n' "The live ipfw runtime state could not be classified during pending strict SSH verification."
        ;;
    pending_strict:firewall_runtime_misaligned)
        printf '%s\n' "The live ipfw runtime state no longer matches the pending strict SSH verification state."
        ;;
    *)
        error_msg "Unknown stage alignment message '$stage_key:$subject'."
        return 1
        ;;
    esac
}

managed_admin_path_matches_state() {
    managed_ssh_auth_assets_ready &&
        sudo_admin_path_matches_state
}

stage_alignment_check() {
    stage_key="$1"
    subject="$2"
    shift 2

    if "$@"; then
        return 0
    fi

    error_msg "$(stage_alignment_error_message "$stage_key" "$subject")"
    return 1
}

validate_stage_alignment_common() {
    stage_key="$1"
    ssh_validator="$2"
    include_firewall_checks="${3:-no}"
    stage_identity_context=$(stage_identity_context_label "$stage_key") || return 1

    if ! cutover_state_matches_live_identity; then
        error_msg "The managed user identity no longer matches the $stage_identity_context."
        return 1
    fi

    stage_alignment_check "$stage_key" "ssh" "$ssh_validator" || return 1
    stage_alignment_check "$stage_key" "auth" managed_ssh_auth_assets_ready || return 1
    stage_alignment_check "$stage_key" "sudo" sudo_admin_path_matches_state || return 1
    stage_alignment_check "$stage_key" "wheel_sudo" wheel_sudo_matches_saved_policy || return 1
    stage_alignment_check "$stage_key" "wheel_members" wheel_membership_matches_saved_policy || return 1

    if value_is_yes "$include_firewall_checks"; then
        stage_alignment_check "$stage_key" "firewall_boot" firewall_boot_state_matches_state || return 1

        runtime_state=$(firewall_runtime_state_class) || {
            error_msg "$(stage_alignment_error_message "$stage_key" "firewall_runtime_classify")"
            return 1
        }
        if [ "$runtime_state" = "misaligned" ]; then
            error_msg "$(stage_alignment_error_message "$stage_key" "firewall_runtime_misaligned")"
            return 1
        fi
    fi
}

validate_cutover_state_alignment() {
    if ! managed_state_is_aligned_with_live_state; then
        error_msg "Managed cutover state is stale or inconsistent with the live host (${cutover_alignment_error:-unknown mismatch}). Clear the managed cutover state and start a fresh staged cutover."
        return 1
    fi
}

validate_pending_strict_alignment() {
    validate_stage_alignment_common "pending_strict" "ssh_admin_path_matches_state" "yes"
}

cutover_defining_cli_requested() {
    [ -n "${cli_user-}" ] ||
        [ -n "${cli_ssh_port-}" ] ||
        [ -n "${cli_disable_wheel-}" ] ||
        [ -n "${cli_remove_wheel_members-}" ]
}

managed_cutover_cli_policy_allows_port_transition() {
    [ "${cutover_stage:-}" = "committed_strict_ready" ] &&
        [ -n "${cli_ssh_port-}" ] &&
        [ "$cli_ssh_port" != "$ssh_port" ] &&
        [ -z "${cli_user-}" ] &&
        [ -z "${cli_disable_wheel-}" ] &&
        [ -z "${cli_remove_wheel_members-}" ]
}

managed_cutover_cli_restart_guidance() {
    printf '%s\n%s\n' "$managed_cutover_cli_preserve_state_message" "$managed_cutover_cli_restart_message"
}

reject_managed_cutover_cli() {
    rejection_reason="$1"

    case "$rejection_reason" in
    pending_state)
        error_msg "$pending_cutover_cli_resolution_message $managed_cutover_cli_preserve_state_message"
        ;;
    stale_state)
        error_msg "$stale_cutover_cli_resolution_message"
        ;;
    committed_state)
        if [ -n "${cli_ssh_port-}" ]; then
            error_msg "$managed_ssh_port_transition_resolution_message $managed_cutover_cli_omit_message $(managed_cutover_cli_restart_guidance)"
        else
            error_msg "$managed_cutover_cli_omit_message $(managed_cutover_cli_restart_guidance)"
        fi
        ;;
    *)
        error_msg "Unknown managed cutover CLI rejection reason '$rejection_reason'."
        ;;
    esac
    return 1
}

enforce_managed_cutover_cli_policy() {
    cli_policy_context="$1"

    if ! cutover_defining_cli_requested; then
        return 0
    fi

    case "$cli_policy_context" in
    pending_state)
        reject_managed_cutover_cli "pending_state"
        ;;
    stale_state)
        reject_managed_cutover_cli "stale_state"
        ;;
    committed_state)
        if managed_cutover_cli_policy_allows_port_transition; then
            return 0
        fi
        reject_managed_cutover_cli "committed_state"
        ;;
    *)
        error_msg "Unknown managed cutover CLI policy context '$cli_policy_context'."
        return 1
        ;;
    esac
}

detect_cutover_mode() {
    cutover_mode="needs_stage_one"

    if managed_state_is_aligned_with_live_state &&
        [ -n "${user-}" ] &&
        validate_user "$user" >/dev/null 2>&1 &&
        managed_admin_path_matches_state; then
        if { option_enabled "disable_wheel" || option_enabled "remove_wheel_members"; } && ! wheel_policy_fully_finalized; then
            cutover_mode="strict_ready_for_finalize"
        else
            cutover_mode="fully_hardened"
        fi
        return 0
    fi

    if [ -n "${cutover_stage-}" ]; then
        case "${cutover_stage:-}" in
        pending_transitional_verify | pending_strict_verify | pending_port_transition_reboot | pending_port_commit_reboot)
            cutover_mode="$cutover_stage"
            ;;
        *)
            cutover_mode="needs_stage_one"
            ;;
        esac
    fi
}

###############################################################################
# Prompting And Input Normalization
###############################################################################

is_deferred_sysctl_key() {
    case "$1" in
    net.inet.ip.fw.* | security.mac.portacl.* | security.mac.bsdextended.* | security.mac.seeotheruids.*)
        return 0
        ;;
    *)
        return 1
        ;;
    esac
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
        allowed_pattern='^[0-9.,]+$'
        ;;
    ipv6)
        allowed_pattern='^[0-9A-Fa-f:.,]+$'
        ;;
    *)
        error_msg "Unknown IP list family '$family'."
        return 1
        ;;
    esac

    compact_value=$(printf "%s" "$value" | tr -d '[:space:]')
    [ -n "$compact_value" ] || return 1
    if ! printf '%s\n' "$compact_value" | grep -Eq "$allowed_pattern"; then
        return 1
    fi

    cleaned=$(printf "%s" "$compact_value" | sed "s/,,*/,/g; s/^,//; s/,\$//")
    [ -n "$cleaned" ] || return 1
    printf "%s\n" "$cleaned"
}

prompt_yes_no_default() {
    var_name="$1"
    prompt_text="$2"
    default_value="$3"
    option_name="$4"

    current=$(get_var_value "$var_name")
    if [ -z "$current" ]; then
        say "$prompt_text"
        printf "Enter your choice (default: %s): " "$default_value"
        read -r current
        current="${current:-$default_value}"
        set_var_value "$var_name" "$current"
    fi
    validate_yes_no "$current" "$option_name"
}

prompt_optional_interface() {
    var_name="$1"
    prompt_text="$2"
    prompt_label="$3"
    provided_label="$4"
    disable_var="${5:-}"

    current=$(get_var_value "$var_name")
    if [ -z "$current" ]; then
        say "$prompt_text"
        printf "Enter the %s (default: none): " "$prompt_label"
        read -r current
        current="${current:-none}"
        set_var_value "$var_name" "$current"
        if ! value_is_none "$current"; then
            validate_interface "$current"
        elif [ -n "$disable_var" ]; then
            set_var_value "$disable_var" "no"
        fi
    else
        say "Using provided $provided_label: $current"
        validate_optional_interface "$current"
    fi
}

###############################################################################
# File, Template, And State Persistence Helpers
###############################################################################

make_secure_tmp() {
    tmp_dir="${1:-/var/tmp}"
    old_umask=$(umask)
    umask 077
    tmp_file=$(mktemp "$tmp_dir/securebsd.XXXXXX")
    umask "$old_umask"
    printf '%s\n' "$tmp_file"
}

atomic_replace() {
    target="$1"
    tmp_file="$2"
    orig_mode=""
    orig_owner=""
    orig_group=""

    if [ -e "$target" ]; then
        orig_mode=$(stat -f %Lp "$target" 2>/dev/null || printf '')
        orig_owner=$(stat -f %u "$target" 2>/dev/null || printf '')
        orig_group=$(stat -f %g "$target" 2>/dev/null || printf '')
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
        error_msg "Failed to update $target."
        rm -f "$tmp_file"
        return 1
    fi
    if [ ! -s "$tmp_file" ]; then
        error_msg "Processing $target failed."
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
        error_msg "AWK template not found: $awk_program"
        rm -f "$tmp_file"
        return 1
    fi

    if ! awk "$@" -f "$awk_program" "$src" >"$tmp_file"; then
        error_msg "Failed to update $error_label."
        rm -f "$tmp_file"
        return 1
    fi
    if [ ! -s "$tmp_file" ]; then
        error_msg "Processing $error_label failed."
        rm -f "$tmp_file"
        return 1
    fi
}

write_temp_content() {
    content="$1"
    tmp_file=$(make_secure_tmp)
    if ! printf "%s" "$content" >"$tmp_file"; then
        error_msg "Failed to write temporary content file."
        rm -f "$tmp_file"
        return 1
    fi
    printf "%s\n" "$tmp_file"
}

current_boot_marker() {
    sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9][0-9]*\).*/\1/p'
}

stage_owned_cutover_state_value() {
    state_field="$1"

    case "$cutover_stage:$state_field" in
    pending_transitional_verify:transitional_ssh_port)
        printf '%s\n' "${transitional_ssh_port:-}"
        ;;
    pending_port_transition_reboot:port_transition_old_port | pending_port_commit_reboot:port_transition_old_port)
        printf '%s\n' "${port_transition_old_port:-}"
        ;;
    *)
        printf '\n'
        ;;
    esac
}

load_cutover_state() {
    [ -f "$cutover_state_file" ] || return 1
    set_kv_defaults "$internal_cutover_state_defaults"
    # shellcheck source=/dev/null
    . "$cutover_state_file"
}

write_cutover_state() {
    cutover_stage="$1"
    wheel_sudo_finalized_state="${2:-${wheel_sudo_finalized:-}}"
    wheel_membership_finalized_state="${3:-${wheel_membership_finalized:-}}"
    cutover_user_uid=$(id -u "$user")
    [ -d "$cutover_state_dir" ] || mkdir -p "$cutover_state_dir"
    chmod 700 "$cutover_state_dir"
    tmp_file=$(make_secure_tmp "$cutover_state_dir")
    state_overrides=$(
        cat <<EOF
cutover_stage=$cutover_stage
cutover_user_uid=$cutover_user_uid
wheel_sudo_finalized=$wheel_sudo_finalized_state
wheel_membership_finalized=$wheel_membership_finalized_state
EOF
    )
    base_state_settings=$(settings_block_for_vars_with_value_fn "$persisted_cutover_state_vars" "cutover_state_value")
    render_quoted_settings_block "$(settings_block_with_overrides "$base_state_settings" "$state_overrides")" >"$tmp_file"
    chmod 600 "$tmp_file"
    atomic_replace "$cutover_state_file" "$tmp_file"
}

clear_cutover_state() {
    [ ! -f "$cutover_state_file" ] || rm -f "$cutover_state_file"
    unset cutover_stage cutover_boot_marker cutover_user_uid wheel_sudo_finalized wheel_membership_finalized port_transition_old_port transitional_ssh_port
    user="${cli_user-}"
    ssh_port="${cli_ssh_port-}"
    disable_wheel="${cli_disable_wheel-}"
    remove_wheel_members="${cli_remove_wheel_members-}"
}

load_cutover_context() {
    saved_public_cutover_settings=$(settings_block_for_vars "$public_cutover_fields")

    if ! load_cutover_state; then
        return 1
    fi

    restore_vars_from_settings_block "$public_cutover_fields" "$saved_public_cutover_settings" "yes"

    clear_vars "$reapplied_firewall_vars"
    load_live_managed_firewall_context
}

###############################################################################
# Rendering And Config-Build Helpers
###############################################################################

render_template_file() {
    template_rel="$1"
    target="$2"
    shift 2

    template_file=$(template_path "$template_rel")
    if [ ! -f "$template_file" ]; then
        error_msg "Template not found: $template_file"
        return 1
    fi

    tmp_file=$(make_secure_tmp "$(dirname "$target")")
    if ! cp "$template_file" "$tmp_file"; then
        error_msg "Failed to copy template $template_file."
        rm -f "$tmp_file"
        return 1
    fi

    for replacement in "$@"; do
        placeholder=${replacement%%=*}
        value=${replacement#*=}
        escaped_value=$(printf "%s" "$value" | sed 's/[&|\\]/\\&/g')
        next_tmp="${tmp_file}.next"
        if ! sed "s|$placeholder|$escaped_value|g" "$tmp_file" >"$next_tmp"; then
            error_msg "Failed to render template $template_file."
            rm -f "$tmp_file" "$next_tmp"
            return 1
        fi
        mv "$next_tmp" "$tmp_file"
    done

    if [ ! -s "$tmp_file" ]; then
        error_msg "Rendering template $template_file failed."
        rm -f "$tmp_file"
        return 1
    fi

    atomic_replace "$target" "$tmp_file"
}

apply_sysrc_settings_block() {
    settings_block="$1"
    each_settings_block_entry "$settings_block" "apply_sysrc_settings_entry"
}

apply_settings_merge_template() {
    target_file="$1"
    template_rel="$2"
    settings="$3"
    shift 3

    if [ ! -f "$target_file" ]; then
        error_msg "$target_file not found."
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

build_firewall_loader_settings() {
    ipfw_nat_enabled="no"
    ipdivert_enabled="no"
    if value_is_configured "${nat_if:-none}"; then
        ipfw_nat_enabled="yes"
    fi
    if suricata_ports_defined && suricata_requested; then
        ipdivert_enabled="yes"
    fi
    ipfw_nat_load=$(freebsd_bool_value "$ipfw_nat_enabled")
    ipdivert_load=$(freebsd_bool_value "$ipdivert_enabled")
    settings=$(freebsd_true_setting "ipfw_load")
    settings=$(append_line_block "$settings" "$(freebsd_true_setting "dummynet_load")")
    settings=$(append_line_block "$settings" "$(quoted_setting_line "ipfw_nat_load" "$ipfw_nat_load")")
    settings=$(append_line_block "$settings" "$(quoted_setting_line "ipdivert_load" "$ipdivert_load")")
    printf '%s\n' "$settings"
}

###############################################################################
# CLI Parsing
###############################################################################

usage() {
    exit_code="${1:-1}"
    cat <<EOF
Usage: $0 [options]

All options are optional; missing values will be prompted interactively.

  -u, --user USER                 Username to allow for SSH/sudo
  -p, --ssh-port PORT             SSH port (default: $default_ssh_port)
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
      --suricata-port PORT        Suricata divert port (default when enabled: $default_suricata_port)
      --password-exp DAYS|none    Password expiration in days (default: $default_password_expiration_days)
      --disable-wheel yes|no      Disable %wheel sudo after final admin-path validation
      --remove-wheel-members yes|no
                                  Remove non-root wheel members after final admin-path validation
      --confirm-stage-advance yes|no
                                  Confirm a verified fresh login and advance a pending staged transition
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

cli_option_is_supported() {
    printf '%s\n' "$supported_cli_options" | tr ' ' '\n' | grep -qxF "$1"
}

set_option_value() {
    option_name=$(normalize_option_name "$1") || return 1
    cli_option_is_supported "$option_name" || return 1
    set_var_value "$option_name" "$2"
}

parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
        -u | --user | -p | --ssh-port)
            [ $# -ge 2 ] || usage 2
            set_option_value "$1" "$2" || usage 2
            shift 2
            ;;
        -h | --help)
            usage 0
            ;;
        --*)
            [ $# -ge 2 ] || usage 2
            set_option_value "$1" "$2" || usage 2
            shift 2
            ;;
        *)
            say_err "Unknown option: $1"
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
            say_err "Invalid IPv4 list '$ssh_ipv4'. Use comma-separated IPv4 addresses or 'any'."
            usage 2
        }
        ssh_ipv4="$normalized_ssh_ipv4"
    fi
    if [ -n "$ssh_ipv6" ]; then
        normalized_ssh_ipv6=$(normalize_ssh_ip_list "$ssh_ipv6" ipv6) || {
            say_err "Invalid IPv6 list '$ssh_ipv6'. Use comma-separated IPv6 addresses or 'any'."
            usage 2
        }
        ssh_ipv6="$normalized_ssh_ipv6"
    fi
    validate_optional_yes_no "${log_ssh_hits-}" "--log-ssh-hits" || usage 2
    validate_optional_yes_no "${log_wan_tcp_hits-}" "--log-wan-tcp-hits" || usage 2
    validate_optional_yes_no "${allow_multicast-}" "--allow-multicast" || usage 2
    validate_optional_yes_no "${allow_multicast_legacy-}" "--allow-multicast-legacy" || usage 2
    resolve_runtime_defaults
    if value_is_yes "$allow_multicast_legacy" && ! value_is_yes "$allow_multicast"; then
        say_err "--allow-multicast-legacy yes requires --allow-multicast yes."
        usage 2
    fi
    validate_optional_interface "${internal_if-}" || usage 2
    validate_optional_interface "${nat_if-}" || usage 2
    validate_optional_interface "${tun_if-}" || usage 2
    validate_optional_yes_no "${install_auditing-}" "--install-auditing" || usage 2
    validate_optional_yes_no "${install_microcode-}" "--install-microcode" || usage 2
    validate_optional_yes_no "${install_suricata-}" "--install-suricata" || usage 2
    validate_optional_yes_no "${disable_wheel-}" "--disable-wheel" || usage 2
    validate_optional_yes_no "${remove_wheel_members-}" "--remove-wheel-members" || usage 2
    validate_optional_yes_no "${confirm_stage_advance-}" "--confirm-stage-advance" || usage 2
    if [ -n "${cpu_type-}" ]; then
        validate_cpu_type "$cpu_type" || usage 2
    fi
    if [ -n "$suricata_port" ]; then
        validate_port "$suricata_port" || usage 2
    fi
    validate_suricata_cli_consistency || usage 2
    if [ -n "$password_exp" ]; then
        validate_password_expiration_value "$password_exp" || usage 2
        password_exp=$(resolve_password_expiration_value)
    fi
}

ensure_scalar_setting() {
    target_file="$1"
    setting="$2"
    key="${setting%%=*}"
    tmp_file=$(make_secure_tmp "$(dirname "$target_file")")

    awk -v setting_key="$key" -v replacement="$setting" '
        {
            line = $0
            candidate = $0
            sub(/[[:space:]]+#.*$/, "", candidate)
            if (candidate == replacement) {
                found_exact = 1
            }
            if (index(candidate, "=") && substr(candidate, 1, index(candidate, "=") - 1) == setting_key) {
                if (!replaced) {
                    print replacement
                    replaced = 1
                }
                next
            }
            print line
        }
        END {
            if (!found_exact && !replaced) {
                print replacement
            }
        }
    ' "$target_file" >"$tmp_file" || {
        rm -f "$tmp_file"
        return 1
    }

    atomic_replace "$target_file" "$tmp_file"
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

###############################################################################
# Mutation Helpers
###############################################################################

# Clear immutable flags on system files for updates
clear_immutable_flags() {
    say "Clearing immutable flags on system files for updates..."
    for file in $full_lockdown_files; do
        if [ ! -e "$file" ]; then
            warn_msg "$file does not exist, skipping."
            continue
        fi
        chflags noschg "$file"
    done
}

# Reapply immutable flags after updates
reapply_immutable_flags() {
    say "Reapplying immutable flags on system files..."
    for file in $full_lockdown_files; do
        chflags schg "$file"
    done
}

###############################################################################
# Interactive Input Collection
###############################################################################

collect_user_input() {
    say "This script will harden your FreeBSD system by securing SSH, enabling firewall rules, configuring automatic updates, and more."

    # SSH user input
    if [ -z "$user" ]; then
        say "Enter a valid username for SSH access and sudo privileges."
        printf "Enter the username to allow for SSH access: "
        read -r user
        if ! validate_user "$user"; then
            say_err "Please provide a valid username."
            return 1
        fi
    else
        say "Using provided username: $user"
    fi

    # SSH port input
    if [ -z "$ssh_port" ]; then
        say "Choose a custom SSH port (not the default 22)."
        printf "Enter the SSH port to use (default: %s): " "$default_ssh_port"
        read -r ssh_port
        ssh_port="${ssh_port:-$default_ssh_port}"
        validate_port "$ssh_port" || return 1
    else
        say "Using provided SSH port: $ssh_port"
    fi

    # SSH IPv4 input
    if [ -z "$ssh_ipv4" ]; then
        say "Enter a comma-separated list of IPv4 addresses allowed to SSH into the server, or type 'any' to allow all IPv4 access (not recommended)."
        printf "Enter the SSH IPv4 addresses (comma-separated) for SSH access: "
        read -r ssh_ipv4
        normalized_ssh_ipv4=$(normalize_ssh_ip_list "$ssh_ipv4" ipv4) || {
            say_err "Invalid input. Please enter comma-separated IPv4 addresses or 'any'."
            return 1
        }
        ssh_ipv4="$normalized_ssh_ipv4"
    else
        say "Using provided SSH IPv4 list: $ssh_ipv4"
    fi

    # SSH IPv6 input
    if [ -z "$ssh_ipv6" ]; then
        say "Enter a comma-separated list of IPv6 addresses allowed to SSH into the server, or type 'any' to allow all IPv6 access (not recommended)."
        printf "Enter the SSH IPv6 addresses (comma-separated) for SSH access: "
        read -r ssh_ipv6
        normalized_ssh_ipv6=$(normalize_ssh_ip_list "$ssh_ipv6" ipv6) || {
            say_err "Invalid input. Please enter comma-separated IPv6 addresses or 'any'."
            return 1
        }
        ssh_ipv6="$normalized_ssh_ipv6"
    else
        say "Using provided SSH IPv6 list: $ssh_ipv6"
    fi

    prompt_yes_no_default "log_ssh_hits" "Enable SSH SYN count/log rules for firewall debugging?" "no" "--log-ssh-hits" || return 1
    prompt_yes_no_default "log_wan_tcp_hits" "Enable WAN TCP SYN count/log rules for firewall debugging?" "no" "--log-wan-tcp-hits" || return 1
    prompt_yes_no_default "allow_multicast" "Allow modern multicast on the trusted internal bridge path?" "no" "--allow-multicast" || return 1
    if value_is_yes "$allow_multicast"; then
        prompt_yes_no_default \
            "allow_multicast_legacy" \
            "Allow legacy multicast compatibility (IGMPv1, IGMPv2, MLDv1)?" \
            "no" \
            "--allow-multicast-legacy" || return 1
    else
        allow_multicast_legacy="no"
    fi

    # Interface selection for firewall policy and optional Suricata netmap support
    prompt_optional_interface \
        "internal_if" \
        "Set the internal network interface for IPFW. Type 'none' if not using a gateway/bridge." \
        "internal network interface (e.g., bridge0)" \
        "internal interface" \
        "install_suricata" || return 1
    prompt_optional_interface \
        "nat_if" \
        "Set the IPv4 VPN/bootstrap egress interface for IPFW. Type 'none' if not using a VPN bootstrap path." \
        "IPv4 VPN/bootstrap egress interface (e.g., tun0)" \
        "IPv4 VPN/bootstrap interface" || return 1
    prompt_optional_interface \
        "tun_if" \
        "Set the protected IPv6-over-VPN interface for IPFW. This can be the main VPN interface or a 6in4 interface such as gif0 when it runs inside the IPv4 VPN. Type 'none' if not using one." \
        "protected IPv6-over-VPN interface (e.g., tun0, gif0)" \
        "protected tunnel interface" || return 1

    prompt_yes_no_default "install_auditing" "Do you want to install security auditing tools?" "yes" "--install-auditing" || return 1
    prompt_yes_no_default "install_microcode" "Would you like to install CPU microcode for your processor to enhance security?" "yes" "--install-microcode" || return 1
    if option_enabled "install_microcode"; then
        cpu_type=$(detect_cpu_type)
    fi

    # Suricata installation choice
    prompt_yes_no_default "install_suricata" "Do you want to install and configure Suricata?" "no" "--install-suricata" || return 1
    if suricata_requested; then
        resolve_suricata_port_default
        validate_port "$suricata_port" || return 1
    else
        suricata_port="none"
    fi

    # Password expiration input
    if [ -z "$password_exp" ]; then
        say "Set the password expiration period in days. Type 'none' to disable expiration (not recommended)."
        printf "Enter the password expiration period in days (default: %s): " "$default_password_expiration_days"
        read -r password_exp
        set_var_if_empty "password_exp" "$default_password_expiration_days"
        if ! value_is_none "$password_exp"; then
            validate_password_expiration "$password_exp" || return 1
            password_exp=$(resolve_password_expiration_value)
        fi
    fi
}

###############################################################################
# Baseline Preparation Helpers
###############################################################################

# Backup critical system configuration files
backup_configs() {
    say "Creating backups of critical configuration files..."
    backup_dir="/etc/backup_$(date +%Y%m%d_%H%M%S)"
    backup_files="/etc/rc.conf /etc/sysctl.conf /etc/login.conf /boot/loader.conf /etc/ssh/sshd_config /etc/pam.d/sshd /etc/ttys"
    mkdir -p "$backup_dir"
    chmod 750 "$backup_dir"
    for conf_file in $backup_files; do
        cp "$conf_file" "$backup_dir"
    done
    chflags -R schg "$backup_dir"
    say "Backup completed and made immutable. Files saved in $backup_dir."
}

# Update FreeBSD and install necessary packages (sudo-rs, fail2ban, Suricata, Google Authenticator)
update_and_install_packages() {
    say "Updating FreeBSD and installing necessary packages (sudo-rs, fail2ban, Google Authenticator)..."
    resolve_package_option_defaults
    if option_enabled "install_microcode" && [ "${cpu_type:-unknown}" = "unknown" ]; then
        cpu_type=$(detect_cpu_type)
    fi

    # FreeBSD update is not supported on all architectures
    freebsd_update_supported="no"
    if freebsd-update fetch install; then
        freebsd_update_supported="yes"
    fi
    pkg upgrade -y
    pkg install -y sudo-rs anacron pam_google_authenticator py311-fail2ban

    # Install security auditing tools if the user opted in
    if option_enabled "install_auditing"; then
        pkg install -y lynis spectre-meltdown-checker
    else
        say "Skipping auditing tools installation."
    fi

    # Install CPU microcode if the user opted in
    if [ "$cpu_type" = "intel" ]; then
        say "Detected Intel CPU. Installing 'cpu-microcode-intel' package."
        pkg install -y cpu-microcode-intel
    elif [ "$cpu_type" = "amd" ]; then
        say "Detected AMD CPU. Installing 'cpu-microcode-amd' package."
        pkg install -y cpu-microcode-amd
    else
        say "Could not detect Intel or AMD CPU. Skipping microcode installation."
    fi

    # Install Suricata if the user opted in
    if suricata_requested; then
        say "Installing Suricata..."
        pkg install -y suricata
        suricata-update
        say "Suricata installed and updated."
    else
        say "Skipping Suricata installation."
    fi

    # Fetch pkg audit database
    pkg audit -Frq || true

    # Check package integrity
    pkg check -sa
}

# Prepare SSH key material for the SSH user
prepare_ssh_user_access() {
    say "Preparing SSH key access for the SSH user..."
    set_user_auth_paths "$user"
    generated_ssh_key="no"

    # Ensure .ssh directory exists with correct permissions
    if [ ! -d "$ssh_dir" ]; then
        say "Creating .ssh directory for $user..."
        mkdir -p "$ssh_dir"
    fi

    # Always enforce correct permissions on .ssh directory
    chmod 700 "$ssh_dir"
    chown "$user:$user" "$ssh_dir"

    # Check for any existing SSH key pairs in the .ssh directory
    if [ -f "$ssh_key" ] || [ -f "$ssh_pub_key" ]; then
        say "SSH key pair already exists for $user."
    else
        say "No SSH key found for $user. Generating a new key pair..."
        su - "$user" -c "ssh-keygen -t ed25519 -f $ssh_key -N '' -q"
        generated_ssh_key="yes"
    fi

    # Set up authorized_keys
    if [ ! -f "$authorized_keys" ]; then
        say "Creating authorized_keys for $user..."
        if [ -f "$ssh_pub_key" ]; then
            cat "$ssh_pub_key" >"$authorized_keys"
        else
            say_err "Public key not found. Ensure a key pair exists before running this script."
            return 1
        fi
    else
        say "authorized_keys already exists for $user. Checking if the public key is present..."
        # Extract key type and key value from the public key file
        key_type_and_value=$(awk '{print $1, $2}' "$ssh_pub_key")
        if ! grep -qF "$key_type_and_value" "$authorized_keys"; then
            say "Adding missing public key to authorized_keys."
            cat "$ssh_pub_key" >>"$authorized_keys"
        else
            say "Public key already exists in authorized_keys."
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

    say "Public key authentication prepared for $user."

    if value_is_yes "$generated_ssh_key"; then
        cat <<EOF

IMPORTANT: You must securely copy the private key to your local machine before rebooting.
To securely transfer the private key, run the following command on your local machine:

scp <username>@<remote_host>:$ssh_dir/id_ed25519 ~/.ssh/

After copying the private key, delete it from the remote server for security:
ssh <username>@<remote_host> 'rm $ssh_dir/id_ed25519'

Ensure the permissions for the private key on your local machine are set correctly with:
chmod 600 ~/.ssh/id_ed25519

Press ENTER to confirm you have securely copied the private key and are ready to proceed.
EOF
        read -r _dummy_variable
    else
        say "Existing SSH key access is already present for $user."
    fi
}

###############################################################################
# SSH Profiles And Transition Stages
###############################################################################

build_sshd_settings() {
    ssh_profile="$1"
    ssh_ports_block=""
    strict_auth_block=""

    base_settings='
PermitRootLogin no
MaxAuthTries 3
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
UsePAM yes
UseDNS no
ClientAliveInterval 60
ClientAliveCountMax 1'

    case "$ssh_profile" in
    transitional)
        printf '%s\nPasswordAuthentication yes\n' "$base_settings"
        ;;
    port_transition)
        strict_auth_block=$(cat <<EOF
PasswordAuthentication no
AuthenticationMethods publickey,keyboard-interactive
AllowUsers $user
EOF
)
        ssh_ports_block=$(cat <<EOF
Port $port_transition_old_port
Port $ssh_port
EOF
)
        printf '%s\n%s\n%s\n' "$base_settings" "$strict_auth_block" "$ssh_ports_block"
        ;;
    strict)
        strict_auth_block=$(cat <<EOF
PasswordAuthentication no
AuthenticationMethods publickey,keyboard-interactive
AllowUsers $user
Port $ssh_port
EOF
)
        printf '%s\n%s\n' "$base_settings" "$strict_auth_block"
        ;;
    *)
        error_msg "Unknown SSH profile '$ssh_profile'."
        return 1
        ;;
    esac
}

apply_sshd_profile() {
    ssh_profile="$1"
    settings=$(build_sshd_settings "$ssh_profile") || return 1

    if ! apply_settings_merge_template "$sshd_config_file" "awk/sshd_settings_merge.awk" "$settings"; then
        return 1
    fi
}

ssh_port_transition_requested() {
    [ "${cutover_stage:-}" = "committed_strict_ready" ] &&
        [ -n "${cli_ssh_port-}" ] &&
        [ "$cli_ssh_port" != "$ssh_port" ]
}

write_port_transition_state() {
    transition_stage="$1"
    cutover_boot_marker=$(current_boot_marker)
    wheel_sudo_finalized=$(resolved_finalized_state "disable_wheel" "wheel_sudo_finalized")
    wheel_membership_finalized=$(resolved_finalized_state "remove_wheel_members" "wheel_membership_finalized")
    write_cutover_state "$transition_stage" "$wheel_sudo_finalized" "$wheel_membership_finalized"
}

validate_port_transition_cli_consistency() {
    if [ -n "${cli_ssh_port-}" ] && [ "$cli_ssh_port" != "$ssh_port" ]; then
        error_msg "A staged SSH port transition to '$ssh_port' is already pending, but --ssh-port requested '$cli_ssh_port'. Complete or clear the pending port transition first."
        return 1
    fi
}

run_port_transition_stage_one() {
    old_ssh_port="$ssh_port"
    new_ssh_port="$cli_ssh_port"

    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    port_transition_old_port="$old_ssh_port"
    ssh_port="$new_ssh_port"
    configure_firewall_boot || return 1
    apply_sshd_profile port_transition || return 1
    write_port_transition_state "pending_port_transition_reboot"
    runtime_state=$(firewall_runtime_state_class)
    reapply_immutable_flags
    say "SSH port transition stage 1 complete. Boot policy now allows both the old port ($old_ssh_port) and the new port ($new_ssh_port)."
    if kldstat -q -m ipfw >/dev/null 2>&1; then
        say "Runtime ipfw is still enforcing the pre-reboot ruleset on this boot. The dual-port firewall policy will take effect after reboot."
    fi
    warn_if_firewall_runtime_absent "$runtime_state"
    say "$pending_port_reboot_next_step"
}

run_port_transition_stage_two() {
    old_ssh_port="$port_transition_old_port"
    new_ssh_port="$ssh_port"

    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    ssh_port="$new_ssh_port"
    port_transition_old_port=""
    configure_firewall_boot || return 1
    apply_sshd_profile strict || return 1
    port_transition_old_port="$old_ssh_port"
    write_port_transition_state "pending_port_commit_reboot"
    runtime_state=$(firewall_runtime_state_class)
    reapply_immutable_flags
    say "SSH port transition stage 2 complete. Managed boot policy now keeps only the new SSH port ($new_ssh_port)."
    if kldstat -q -m ipfw >/dev/null 2>&1; then
        say "Runtime ipfw is still enforcing the pre-reboot ruleset on this boot. The new-port-only firewall policy will take effect after reboot."
    fi
    warn_if_firewall_runtime_absent "$runtime_state"
    say "$pending_port_commit_reboot_next_step"
}

run_port_transition_stage_three() {
    new_ssh_port="$ssh_port"

    clear_immutable_flags
    ssh_port="$new_ssh_port"
    transitional_ssh_port=""
    port_transition_old_port=""
    record_committed_cutover_state current || return 1
    reapply_immutable_flags
    say "SSH port migration to $new_ssh_port has been finalized."
}

reload_sshd_safe() {
    if ! sshd -t -f "$sshd_config_file" >/dev/null 2>&1; then
        error_msg "sshd configuration validation failed."
        return 1
    fi

    if ! service sshd reload >/dev/null 2>&1; then
        error_msg "Failed to reload sshd."
        return 1
    fi
}

apply_and_reload_sshd_profile() {
    ssh_profile="$1"
    apply_sshd_profile "$ssh_profile" || return 1
    reload_sshd_safe
}

###############################################################################
# Admin Path Preparation And Finalization
###############################################################################

# Configure PAM security settings
configure_ssh_pam() {
    say "Configuring SSH PAM for Google Authenticator..."

    # Check if pam_google_authenticator.so is already present
    if grep -qxF "$ssh_pam_ga_line" "$pam_sshd_config_file"; then
        say "Google Authenticator is already enabled in PAM SSH configuration."
        return
    fi
    pam_sshd_tmp=$(make_secure_tmp "$(dirname "$pam_sshd_config_file")")

    if ! run_awk_template "$pam_sshd_config_file" "$pam_sshd_tmp" "$pam_sshd_config_file" "awk/pam_sshd_google_auth.awk" -v ga_line="$ssh_pam_ga_line"; then
        return 1
    fi

    # Replace the sshd config file atomically
    atomic_replace "$pam_sshd_config_file" "$pam_sshd_tmp"

    say "Google Authenticator added to the auth section of PAM SSH configuration."
    say "SSH and PAM changes have been written to disk; the staged cutover will validate and reload sshd explicitly."
}

# Configure Google Authenticator TOTP for the SSH user
configure_google_auth() {
    say "Configuring Google Authenticator TOTP for the SSH user..."

    set_user_auth_paths "$user"

    if [ -f "$ga_config" ] && [ -s "$ga_config" ]; then
        say "Google Authenticator TOTP is already configured for $user."
        return 0
    fi

    # Run google-authenticator as the SSH user with secure options
    su - "$user" -c "google-authenticator -t -d -r 3 -R 30 -W -s '$ga_config'"

    # Secure permissions on the .google_authenticator file
    chmod 600 "$ga_config"
    chown "$user:$user" "$ga_config"

    # Provide clear instructions for the user
    cat <<'EOF'

Google Authenticator TOTP configuration is complete.
IMPORTANT: Copy and securely store the following details:
1. Your secret key (used to set up TOTP in your app).
2. Emergency scratch codes (for recovery if your TOTP device is unavailable).

Without these details, you may lose access to this system.
EOF
    cat <<'EOF'

You can always re-run this script to regenerate a new secret key, but doing so will invalidate any previously configured TOTP apps.

EOF

    # Pause and wait for user confirmation
    say "Press ENTER to confirm you have securely saved the secret key and scratch codes."
    read -r _dummy_variable
}

# Prepare sudo access for the SSH user without changing deferred admin fallback policy yet
prepare_sudo_access() {
    say "Preparing sudo access for administrative users..."

    # Create the sudo group if it doesn't exist
    if ! getent group sudo >/dev/null; then
        say "Creating sudo group..."
        pw groupadd sudo
    fi

    # Prompt administrator for users to add to the sudo group
    printf "The following users currently belong to the wheel group: "
    getent group wheel | cut -d ':' -f 4

    printf "\nEnter additional usernames to add to the sudo group (comma-separated, leave blank to skip): "
    read -r users_to_add
    users_to_add=$(csv_items_lines "${user},${users_to_add}")

    if [ -n "$users_to_add" ]; then
        # Split input into individual usernames
        valid_users_to_add=""
        for member_user in $users_to_add; do
            if validate_user "$member_user"; then
                valid_users_to_add=$(append_line_block "$valid_users_to_add" "$member_user")
            fi
        done

        update_group_membership \
            "sudo" \
            "add" \
            "$valid_users_to_add" \
            "Users added to the sudo group:" \
            "No users added to the sudo group." || return 1
    fi

    # Configure sudoers file for the sudo group
    if [ ! -f /usr/local/etc/sudoers.d/sudo ]; then
        printf '%s\n' "$sudo_policy_line" >/usr/local/etc/sudoers.d/sudo
        chmod 440 /usr/local/etc/sudoers.d/sudo
    fi

    if ! visudo -c >/dev/null; then
        error_msg "sudoers validation failed. Wheel access will not be changed."
        return 1
    fi

    if [ -z "${disable_wheel-}" ]; then
        prompt_yes_no_default \
            "disable_wheel" \
            "Do you want to disable sudo access for the wheel group after final admin-path validation?" \
            "yes" \
            "disable_wheel" || return 1
    fi

    # Prompt to remove non-root members from the wheel group
    if [ -z "${remove_wheel_members-}" ]; then
        prompt_yes_no_default \
            "remove_wheel_members" \
            "Do you want to remove non-root members from the wheel group after final admin-path validation?" \
            "yes" \
            "remove_wheel_members" || return 1
    fi

    say "Sudo access prepared and validated. Deferred admin fallback policy changes will wait until the final admin-path validation passes."
}

# Validate that the replacement admin path exists before any deferred admin fallback policy changes happen
assert_admin_access_ready() {
    set_user_auth_paths "$user"

    if [ -n "${user-}" ] &&
        validate_user "$user" >/dev/null 2>&1 &&
        managed_admin_path_matches_state; then
        say "Final admin-path validation passed. SSH/PAM config is syntax-valid and the replacement sudo path is present."
        return 0
    fi

    if ! visudo -c >/dev/null; then
        admin_access_error "sudoers validation failed"
        return 1
    fi

    if ! sshd -t -f "$sshd_config_file" >/dev/null 2>&1; then
        admin_access_error "sshd configuration validation failed"
        return 1
    fi

    if [ ! -f /usr/local/etc/sudoers.d/sudo ] || ! grep -qxF "$sudo_policy_line" /usr/local/etc/sudoers.d/sudo; then
        admin_access_error "%sudo policy file is missing or invalid"
        return 1
    fi

    if ! user_in_group "$user" "sudo"; then
        admin_access_error "User '$user' is not a member of the sudo group"
        return 1
    fi

    if [ ! -f "$authorized_keys" ] || [ ! -s "$authorized_keys" ]; then
        admin_access_error "Authorized keys are missing for '$user'"
        return 1
    fi

    if [ ! -f "$ga_config" ] || [ ! -s "$ga_config" ]; then
        admin_access_error "Google Authenticator configuration is missing for '$user'"
        return 1
    fi

    say "Final admin-path validation passed. SSH/PAM config is syntax-valid and the replacement sudo path is present."
}

# Finalize sudo hardening only after the replacement admin path has been validated
finalize_sudo_access() {
    say "Finalizing sudo hardening..."
    set_default_if_empty "disable_wheel" "no"
    set_default_if_empty "remove_wheel_members" "no"

    if option_enabled "disable_wheel"; then
        say "Disabling sudo access for the wheel group..."

        if awk '
            /^%wheel[[:blank:]]+ALL=\(ALL(:ALL)?\)[[:blank:]]+(NOPASSWD:[[:blank:]]+)?ALL$/ {
                found = 1
                exit
            }
            END { exit(found ? 0 : 1) }
        ' /usr/local/etc/sudoers; then
            sudoers_tmp=$(make_secure_tmp /usr/local/etc)
            if ! run_awk_template /usr/local/etc/sudoers "$sudoers_tmp" /usr/local/etc/sudoers "awk/sudoers_disable_wheel.awk"; then
                return 1
            fi
            atomic_replace /usr/local/etc/sudoers "$sudoers_tmp"
            say "Commented out %wheel group sudo access in /usr/local/etc/sudoers."
        fi

        if [ -f /usr/local/etc/sudoers.d/wheel ]; then
            mv /usr/local/etc/sudoers.d/wheel /usr/local/etc/sudoers.d/wheel.disabled
            say "Disabled /usr/local/etc/sudoers.d/wheel."
        fi
    else
        say "Wheel group sudo access remains enabled."
    fi

    if option_enabled "remove_wheel_members"; then
        say "Removing non-root users from the wheel group..."
        removable_wheel_users=$(printf '%s\n' "$(group_member_lines wheel)" | grep -vx 'root' || true)
        update_group_membership \
            "wheel" \
            "remove" \
            "$removable_wheel_users" \
            "Users removed from the wheel group:" \
            "No users removed from the wheel group." || return 1
    else
        say "No users removed from the wheel group."
    fi

    say "Sudo hardening finalized. Log out and log in again before relying on the new sudo group membership."
}

###############################################################################
# Stage Orchestration
###############################################################################

run_stage_one_after_input() {
    clear_immutable_flags
    backup_configs
    update_and_install_packages
    configure_password_and_umask
    prepare_ssh_user_access
    configure_google_auth
    configure_ssh_pam
    apply_and_reload_sshd_profile transitional || return 1
    sshd_effective=$(load_effective_sshd) || return 1
    transitional_ssh_port=$(effective_sshd_ports_csv "$sshd_effective")
    [ -n "$transitional_ssh_port" ] || {
        error_msg "Could not determine the transitional SSH port after reloading sshd."
        return 1
    }
    prepare_sudo_access
    assert_admin_access_ready
    configure_fail2ban
    secure_syslog_and_tmp
    configure_cron_updates
    configure_securelevel
    harden_ttys
    harden_loader_conf
    harden_sysctl
    write_cutover_state "pending_transitional_verify"
    lock_down_system
    say "Stage 1 complete. A transitional SSH configuration has been reloaded."
    say "Verify that you can log in through a fresh SSH session using the new path, then rerun this script with --confirm-stage-advance yes to enforce strict SSH authentication."
    say "Firewall boot activation is still deferred. Rebooting now will not activate the managed ipfw boot path yet."
}

run_stage_two() {
    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    transitional_ssh_port=""
    apply_and_reload_sshd_profile strict || return 1
    assert_admin_access_ready
    configure_firewall_boot
    wheel_sudo_finalized=$(resolved_finalized_state "disable_wheel" "wheel_sudo_finalized")
    wheel_membership_finalized=$(resolved_finalized_state "remove_wheel_members" "wheel_membership_finalized")
    write_cutover_state "pending_strict_verify" "$wheel_sudo_finalized" "$wheel_membership_finalized"
    reapply_immutable_flags
    say "Stage 2 complete. Strict SSH authentication has been reloaded."
    say "Firewall boot handling has now been committed and future reboots will use the managed firewall configuration."
    say "Verify a fresh pubkey+TOTP login, then rerun this script with --confirm-stage-advance yes to finalize the deferred admin fallback policy."
}

advance_pending_strict_stage() {
    converge_strict_cutover_state || return 1
    if { option_enabled "disable_wheel" || option_enabled "remove_wheel_members"; } && ! wheel_policy_fully_finalized; then
        finalize_deferred_admin_fallback || return 1
        say "Strict SSH has been externally verified. Deferred admin fallback policy has now been finalized."
    else
        record_committed_cutover_state || return 1
        say "Strict SSH has been externally verified and committed without deferred admin fallback changes."
    fi
}

advance_pending_port_commit_stage() {
    run_port_transition_stage_three || return 1
    if { option_enabled "disable_wheel" || option_enabled "remove_wheel_members"; } && ! wheel_policy_fully_finalized; then
        say "SSH port migration is complete. Rerun the script to finalize the deferred admin fallback policy."
    fi
}

handle_pending_stage() {
    stage_label="$1"
    next_step="$2"
    validate_fn="$3"
    advance_fn="$4"

    validate_port_transition_cli_consistency || return 1
    enforce_managed_cutover_cli_policy "pending_state" || return 1
    if [ "$confirm_stage_advance" != "yes" ]; then
        printf '%s is pending verification.\n' "$stage_label"
        printf '%s\n' "$next_step"
        return 0
    fi
    "$validate_fn" || return 1
    "$advance_fn"
}

run_managed_cutover_action() {
    action="$1"
    shift
    cli_policy_context="$1"
    shift

    validate_cutover_state_alignment || return 1
    validate_port_transition_cli_consistency || return 1
    enforce_managed_cutover_cli_policy "$cli_policy_context" || return 1

    "$action" "$@"
}

run_committed_cutover_mode() {
    committed_mode="$1"

    validate_cutover_state_alignment || return 1
    validate_port_transition_cli_consistency || return 1
    enforce_managed_cutover_cli_policy "committed_state" || return 1

    case "$committed_mode" in
    strict_ready_for_finalize)
        say "A committed strict SSH/firewall state is already present. Converging the strict state before finalizing deferred admin cleanup."
        converge_strict_cutover_state || return 1
        finalize_deferred_admin_fallback || return 1
        ;;
    fully_hardened)
        say "A committed strict SSH/firewall state is already present. Reapplying the baseline without staged prompts."
        run_strict_baseline_reapply "no"
        ;;
    *)
        error_msg "Unknown committed cutover mode '$committed_mode'."
        return 1
        ;;
    esac
}

run_strict_baseline_reapply() {
    finalize_admin_fallback="$1"

    clear_immutable_flags
    warn_if_firewall_runtime_absent
    restore_desired_mutable_baseline_settings
    backup_configs
    update_and_install_packages
    configure_password_and_umask
    prepare_ssh_user_access
    configure_google_auth
    configure_ssh_pam
    apply_and_reload_sshd_profile strict || return 1
    if ! { [ -n "${user-}" ] &&
        validate_user "$user" >/dev/null 2>&1 &&
        managed_admin_path_matches_state; }; then
        prepare_sudo_access || return 1
    fi
    assert_admin_access_ready
    configure_fail2ban
    configure_firewall_boot
    secure_syslog_and_tmp
    configure_cron_updates
    configure_securelevel
    harden_ttys
    harden_loader_conf
    harden_sysctl

    if value_is_yes "$finalize_admin_fallback"; then
        finalize_sudo_access
        record_committed_cutover_state "final"
        say "Strict SSH is already live. Deferred admin cleanup has been finalized in this run."
    else
        record_committed_cutover_state
        say "System is already fully hardened. Reapplying the baseline without staged SSH cutover."
    fi

    lock_down_system
}

run_stage_one_port_transition_if_requested() {
    if ssh_port_transition_requested; then
        run_managed_cutover_action "run_port_transition_stage_one" "committed_state"
        return 0
    fi

    return 1
}

handle_pending_cutover() {
    resolve_runtime_defaults
    if [ "${cutover_stage:-}" = "committed_strict_ready" ] &&
        [ "${cutover_stage:-}" != "pending_port_transition_reboot" ] &&
        [ "${cutover_stage:-}" != "pending_port_commit_reboot" ]; then
        validate_cutover_state_alignment || return 1
    fi

    if ssh_port_transition_requested &&
        [ "${cutover_stage:-}" != "pending_port_transition_reboot" ] &&
        [ "${cutover_stage:-}" != "pending_port_commit_reboot" ]; then
        if [ "${cutover_stage:-}" = "committed_strict_ready" ]; then
            say "$committed_ssh_port_transition_mode_message"
        fi
        run_managed_cutover_action "run_port_transition_stage_one" "committed_state"
        return
    fi

    detect_cutover_mode

    case "${cutover_mode:-needs_stage_one}" in
    strict_ready_for_finalize)
        run_committed_cutover_mode "strict_ready_for_finalize"
        ;;
    fully_hardened)
        run_committed_cutover_mode "fully_hardened"
        ;;
    pending_transitional_verify)
        handle_pending_stage \
            "A transitional SSH configuration" \
            "Verify that you can log in through a fresh SSH session, then rerun this script with --confirm-stage-advance yes to enforce strict SSH authentication." \
            "validate_pending_transitional_alignment" \
            "run_stage_two"
        ;;
    pending_strict_verify)
        handle_pending_stage \
            "Strict SSH authentication" \
            "Verify a fresh pubkey+TOTP login, then rerun this script with --confirm-stage-advance yes to finalize the deferred admin fallback policy." \
            "validate_pending_strict_alignment" \
            "advance_pending_strict_stage"
        ;;
    pending_port_transition_reboot)
        handle_pending_stage \
            "A dual-port SSH reboot transition" \
            "$pending_port_reboot_next_step" \
            "validate_pending_port_transition_alignment" \
            "run_port_transition_stage_two"
        ;;
    pending_port_commit_reboot)
        handle_pending_stage \
            "A new-port-only SSH reboot transition" \
            "$pending_port_commit_reboot_next_step" \
            "validate_pending_port_transition_alignment" \
            "advance_pending_port_commit_stage"
        ;;
    *)
        if cutover_defining_cli_requested; then
            enforce_managed_cutover_cli_policy "stale_state" || return 1
        fi
        say "Stored cutover state is stale or incomplete. Clearing it and starting a fresh evaluation."
        clear_cutover_state
        run_without_cutover_state
        ;;
    esac
}

run_without_cutover_state() {
    detect_cutover_mode

    if run_stage_one_port_transition_if_requested; then
        return
    fi

    case "${cutover_mode:-needs_stage_one}" in
    strict_ready_for_finalize)
        run_managed_cutover_action "run_strict_baseline_reapply" "committed_state" "yes"
        return
        ;;
    fully_hardened)
        run_managed_cutover_action "run_strict_baseline_reapply" "committed_state" "no"
        return
        ;;
    esac

    collect_user_input
    detect_cutover_mode

    if run_stage_one_port_transition_if_requested; then
        return
    fi

    case "${cutover_mode:-needs_stage_one}" in
    strict_ready_for_finalize)
        run_managed_cutover_action "run_strict_baseline_reapply" "committed_state" "yes"
        ;;
    fully_hardened)
        run_managed_cutover_action "run_strict_baseline_reapply" "committed_state" "no"
        ;;
    *)
        run_stage_one_after_input
        ;;
    esac
}

###############################################################################
# System Hardening Writers
###############################################################################

# Configure Suricata for IPS mode and include custom config
configure_suricata() {
    say "Configuring Suricata for IPS mode with IPFW..."
    ssh_ports_csv=$(compose_normalized_port_set "$ssh_port" "${port_transition_old_port:-}")
    suricata_yaml_ports=$(suricata_ssh_ports_value "$ssh_ports_csv")
    managed_ssh_rule=$(managed_suricata_ssh_rule "$ssh_ports_csv")
    suricata_rules_tmp=""

    if ! render_template_file "config/suricata-custom.yaml.tmpl" "$suricata_custom_conf_file" \
        "@NAT_INTERFACE@=$nat_if" \
        "@SURICATA_PORT@=$suricata_port"; then
        return 1
    fi

    if ! grep -qE '^[[:space:]]*SSH_PORTS:' "$suricata_conf_file"; then
        error_msg "SSH_PORTS not found in $suricata_conf_file."
        return 1
    fi
    suricata_conf_tmp=$(make_secure_tmp "$(dirname "$suricata_conf_file")")
    if ! run_awk_template "$suricata_conf_file" "$suricata_conf_tmp" "$suricata_conf_file" "awk/suricata_ssh_ports_merge.awk" -v ssh_ports_value="$suricata_yaml_ports"; then
        return 1
    fi
    atomic_replace "$suricata_conf_file" "$suricata_conf_tmp"

    suricata_conf_tmp=$(make_secure_tmp "$(dirname "$suricata_conf_file")")
    if ! run_awk_template "$suricata_conf_file" "$suricata_conf_tmp" "$suricata_conf_file" "awk/suricata_include_merge.awk" -v custom_include="$suricata_custom_conf_file"; then
        return 1
    fi
    atomic_replace "$suricata_conf_file" "$suricata_conf_tmp"
    say "Custom Suricata configuration include normalized."

    [ -f "$suricata_rules_file" ] || : >"$suricata_rules_file"
    suricata_rules_tmp=$(make_secure_tmp "$(dirname "$suricata_rules_file")")
    if ! run_awk_template "$suricata_rules_file" "$suricata_rules_tmp" "$suricata_rules_file" "awk/suricata_rule_merge.awk" -v managed_rule="$managed_ssh_rule"; then
        return 1
    fi
    atomic_replace "$suricata_rules_file" "$suricata_rules_tmp"

    # Test the Suricata configuration
    if ! suricata -T -c "$suricata_conf_file"; then
        say_err "Suricata configuration test failed. Please review the configuration."
        return 1
    fi

    # Enable Suricata at boot
    apply_sysrc_settings_block "$suricata_rc_conf_settings"
    say "Suricata configured to enable at next reboot on interface $nat_if."
}

###############################################################################
# Strict-State Convergence
###############################################################################

converge_strict_cutover_state() {
    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    prepare_ssh_user_access
    configure_google_auth
    configure_ssh_pam
    apply_and_reload_sshd_profile strict || return 1
    if ! { [ -n "${user-}" ] &&
        validate_user "$user" >/dev/null 2>&1 &&
        managed_admin_path_matches_state; }; then
        prepare_sudo_access || return 1
    fi
    assert_admin_access_ready
    configure_firewall_boot || return 1
    reapply_immutable_flags
}

finalize_deferred_admin_fallback() {
    clear_immutable_flags
    assert_admin_access_ready
    finalize_sudo_access
    record_committed_cutover_state "final"
    reapply_immutable_flags
}

###############################################################################
# System Hardening Writers
###############################################################################

# Configure Fail2Ban to protect SSH
configure_fail2ban() {
    say "Configuring Fail2Ban to protect SSH and add manual permanent ban jail..."

    say "Creating Fail2Ban jail.local for SSH and manual bans..."
    if ! render_template_file "config/fail2ban-jail.local.tmpl" "/usr/local/etc/fail2ban/jail.local"; then
        return 1
    fi

    # Enable Fail2Ban service
    say "Enabling Fail2Ban service..."
    apply_sysrc_settings_block "$fail2ban_rc_conf_settings"

    say "Fail2Ban configuration completed. Restart the service to apply changes."
}

# Harden system kernel with sysctl settings
harden_sysctl() {
    say "Applying sysctl hardening..."
    sysctl_conf="/etc/sysctl.conf"
    resolve_runtime_defaults

    multicast_legacy_value=0
    if value_is_yes "$allow_multicast" && value_is_yes "$allow_multicast_legacy"; then
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

        # Some managed sysctls are provided by kernel modules that may only be loaded on reboot.
        if is_deferred_sysctl_key "$key" || sysctl -d "$key" >/dev/null 2>&1; then
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
            warn_msg "sysctl key '${key}' does not exist on this system."
        fi
    done

    say "System kernel hardened with secure sysctl settings."
}

# Harden loader.conf with additional kernel security modules
harden_loader_conf() {
    say "Configuring loader.conf for additional kernel security and microcode..."

    settings=$(freebsd_true_setting "mac_bsdextended_load")
    settings=$(append_line_block "$settings" "$(freebsd_true_setting "mac_portacl_load")")
    settings=$(append_line_block "$settings" "$(freebsd_true_setting "mac_seeotheruids_load")")

    if [ "$cpu_type" != "unknown" ]; then
        if [ "$cpu_type" = "intel" ]; then
            microcode_settings=$(freebsd_true_setting "cpuctl_load")
            microcode_settings=$(append_line_block "$microcode_settings" "$(freebsd_true_setting "cpu_microcode_load")")
            microcode_settings=$(append_line_block "$microcode_settings" "$(freebsd_true_setting "coretemp_load")")
            microcode_settings=$(append_line_block "$microcode_settings" "$(quoted_setting_line "cpu_microcode_name" "/boot/firmware/intel-ucode.bin")")
        elif [ "$cpu_type" = "amd" ]; then
            microcode_settings=$(freebsd_true_setting "cpuctl_load")
            microcode_settings=$(append_line_block "$microcode_settings" "$(freebsd_true_setting "cpu_microcode_load")")
            microcode_settings=$(append_line_block "$microcode_settings" "$(freebsd_true_setting "amdtemp_load")")
            microcode_settings=$(append_line_block "$microcode_settings" "$(quoted_setting_line "cpu_microcode_name" "/boot/firmware/amd-ucode.bin")")
        fi
        settings=$(append_line_block "$settings" "${microcode_settings-}")
    fi

    loader_updates=""
    for setting in $settings; do
        key="${setting%%=*}"

        # Determine if the entry is a loadable module
        case "$key" in
        *_load)
            module="${key%_load}"
            module_path="/boot/kernel/${module}.ko"
            module_alt_path="/boot/modules/${module}.ko"
            ;;
        *)
            module="not_a_module"
            ;;
        esac

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
                    say "Module '${module}' already loaded."
                elif [ "$module" != "ipfw" ] && [ "$module" != "ipfw_nat" ]; then
                    if kldload "$module" 2>/dev/null; then
                        say "Module '${module}' successfully loaded."
                    else
                        warn_msg "Failed to load kernel module '${module}'."
                        continue
                    fi
                fi
            fi

            loader_updates=$(append_line_block "$loader_updates" "$setting")
        else
            warn_msg "Kernel module '${module}' not found in /boot/kernel/ or /boot/modules/"
        fi
    done

    if [ -n "$loader_updates" ]; then
        if ! apply_settings_merge_template "$loader_conf_file" "awk/kv_settings_merge.awk" "$loader_updates" -v append_missing="yes"; then
            return 1
        fi
    fi

    say "loader.conf hardened with additional kernel security modules and microcode settings."
}

configure_firewall_boot() {
    say "Configuring firewall boot handling..."
    firewall_loader_settings=$(build_firewall_loader_settings)

    if ! apply_settings_merge_template "$loader_conf_file" "awk/kv_settings_merge.awk" "$firewall_loader_settings" -v append_missing="yes"; then
        return 1
    fi

    if suricata_requested; then
        configure_suricata || return 1
    fi

    configure_ipfw || return 1
    say "Firewall boot configuration committed. Future reboots will use the managed firewall configuration."
}

# Set securelevel in rc.conf
configure_securelevel() {
    say "Configuring securelevel in rc.conf..."
    apply_sysrc_settings_block "$securelevel_rc_conf_settings"
    say "Securelevel configured in rc.conf."
}

harden_ttys() {
    say "Hardening /etc/ttys for console password requirement and disabling extra VTs..."
    ttys_conf="/etc/ttys"

    if [ ! -f "$ttys_conf" ]; then
        warn_msg "$ttys_conf not found; skipping."
        return 0
    fi
    ttys_tmp=$(make_secure_tmp "$(dirname "$ttys_conf")")

    if ! run_awk_template "$ttys_conf" "$ttys_tmp" "$ttys_conf" "awk/ttys_harden.awk"; then
        return 1
    fi

    if ! awk -f "$(template_path "awk/ttys_validate.awk")" "$ttys_tmp"; then
        error_msg "Validation failed for $ttys_tmp."
        rm "$ttys_tmp"
        return 1
    fi

    atomic_replace "$ttys_conf" "$ttys_tmp"
    say "Hardened /etc/ttys and disabled VTs."
}

# Set Blowfish password hashing, enforce password expiration, and configure umask
configure_password_and_umask() {
    say "Configuring password security with Blowfish encryption and setting a secure umask..."
    login_conf="/etc/login.conf"
    password_expiration_value=$(resolve_password_expiration_value)

    # Check if the 'default' block exists
    if ! grep -q '^default:' "$login_conf"; then
        error_msg "'default:' block not found in $login_conf. Cannot proceed."
        return 1
    fi
    login_conf_tmp=$(make_secure_tmp "$(dirname "$login_conf")")

    # Check if Blowfish hashing is already enabled
    blf_enabled=$(grep -qE '^[[:blank:]]*:passwd_format=blf:' "$login_conf" && printf '1' || printf '0')

    if ! run_awk_template "$login_conf" "$login_conf_tmp" "$login_conf" "awk/login_conf_defaults.awk" -v new_passwd_format="blf" -v new_umask="027" -v password_expiration="$password_expiration_value"; then
        return 1
    fi

    # Replace the login.conf file atomically
    atomic_replace "$login_conf" "$login_conf_tmp"

    # Rebuild login capabilities database
    if ! cap_mkdb "$login_conf"; then
        error_msg "Failed to rebuild the login.conf database."
        return 1
    fi

    # Check if Blowfish hashing needs to be enabled
    if [ "$blf_enabled" -ne 1 ]; then
        # Inform the user about the password reset
        say "Resetting the password for $user and root to ensure Blowfish encryption is applied."

        # Reset the password for the SSH user to apply Blowfish hashing
        if ! passwd "$user"; then
            error_msg "Failed to reset password for $user."
            return 1
        fi

        # Reset the password for the root user to apply Blowfish hashing
        if ! passwd; then
            error_msg "Failed to reset password for root."
            return 1
        fi
    fi

    say "Password security configured with umask 027 and Blowfish encryption for $user."
}

# Configure IPFW firewall with updated rules
configure_ipfw() {
    say "Configuring IPFW firewall with Suricata and Dummynet..."
    ipfw_rules_tmp=""

    settings=$(render_quoted_settings_block "$(settings_block_for_vars "$rendered_firewall_vars")")

    ipfw_rules_tmp=$(make_secure_tmp "$(dirname "$managed_ipfw_rules_file")")
    if ! cp "$source_ipfw_rules_file" "$ipfw_rules_tmp"; then
        rm -f "$ipfw_rules_tmp"
        return 1
    fi

    if ! apply_settings_merge_template "$ipfw_rules_tmp" "awk/kv_settings_merge.awk" "$settings"; then
        rm -f "$ipfw_rules_tmp"
        return 1
    fi

    if ! sh -n "$ipfw_rules_tmp"; then
        error_msg "Rendered IPFW rules failed shell syntax validation."
        rm -f "$ipfw_rules_tmp"
        return 1
    fi

    chmod 640 "$ipfw_rules_tmp"
    atomic_replace "$managed_ipfw_rules_file" "$ipfw_rules_tmp"

    # Set the firewall to load on boot and specify the rules file
    apply_sysrc_settings_block "$managed_firewall_rc_conf_settings"

    say "IPFW firewall with Suricata and Dummynet configured, rules saved to $managed_ipfw_rules_file, and enabled at boot."
}

# Secure syslog and configure /tmp cleanup at startup
secure_syslog_and_tmp() {
    say "Securing syslog and configuring /tmp cleanup at startup..."
    apply_sysrc_settings_block "$syslog_tmp_rc_conf_settings"
    service syslogd restart
    say "Syslog secured and /tmp cleanup configured."
}

# Configure cron jobs for system updates and suricata-update
configure_cron_updates() {
    say "Setting up automatic updates via cron for the root user..."

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
    printf '%s\n' "$current_crontab" >"$temp_crontab"

    # Add Suricata update cron job if applicable
    if suricata_requested && ! printf '%s\n' "$current_crontab" | grep -qF "$suricata_cmd"; then
        printf '%s\n' "$suricata_cron" >>"$temp_crontab"
        say "Added Suricata update cron job."
    else
        say "Suricata update cron job already exists or not applicable. Skipping..."
    fi

    # Add FreeBSD update cron job if not already present
    if value_is_yes "$freebsd_update_supported" && ! printf '%s\n' "$current_crontab" | grep -qF "$freebsd_update_cmd"; then
        printf '%s\n' "$freebsd_update_cron" >>"$temp_crontab"
        say "Added FreeBSD update cron job."
    else
        say "FreeBSD update cron job already exists or not supported. Skipping..."
    fi

    # Add pkg update cron job if not already present
    if ! printf '%s\n' "$current_crontab" | grep -qF "$pkg_update_cmd"; then
        printf '%s\n' "$pkg_update_cron" >>"$temp_crontab"
        say "Added pkg update cron job."
    else
        say "pkg update cron job already exists. Skipping..."
    fi

    # Install the updated crontab
    crontab "$temp_crontab"

    # Clean up the temporary file
    rm "$temp_crontab"

    say "Cron jobs for system and Suricata updates configured for the root user."
}

# Lock down sensitive system files
lock_down_system() {
    say "Locking down critical system files..."
    for file in $service_scheduler_files; do
        printf 'root\n' >"$file"
    done
    for file in $sensitive_files; do
        chmod o= "$file"
    done
    reapply_immutable_flags
    say "System files locked down and cron/at restricted to root only."
}

###############################################################################
# Entry Point
###############################################################################

# Main function to run all steps
main() {
    parse_arguments "$@"
    capture_desired_mutable_baseline_settings
    if [ -f "$cutover_state_file" ]; then
        load_cutover_context
        handle_pending_cutover
    else
        run_without_cutover_state
    fi
}

# Run the main function
main "$@"
