#!/bin/sh

# Exit on errors and undefined variables
set -eu

###############################################################################
# Global Constants And State
###############################################################################

# Immutable file lists and path constants
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
cutover_state_dir="/var/db/securebsd"
cutover_state_file="$cutover_state_dir/admin_cutover.state"
managed_firewall_base_vars="internal_if nat_if tun_if ssh_ipv4 ssh_ipv6 log_ssh_hits log_wan_tcp_hits allow_multicast allow_multicast_legacy suricata_port"
mutable_baseline_override_vars="$managed_firewall_base_vars install_suricata"
managed_firewall_context_vars="$managed_firewall_base_vars"
managed_firewall_rules_state_vars="$managed_firewall_base_vars port_transition_old_port"
managed_ipfw_emit_vars="$managed_firewall_base_vars ssh_port port_transition_old_port"
sudo_policy_line='%sudo ALL=(ALL:ALL) ALL'
strict_ssh_effective_policy_lines='
passwordauthentication no
kbdinteractiveauthentication yes
pubkeyauthentication yes
usepam yes
authenticationmethods publickey,keyboard-interactive
'
managed_firewall_rc_conf_lines='
firewall_enable="YES"
firewall_script="/etc/ipfw.rules"
firewall_logging="YES"
'
sshd_config_file="/etc/ssh/sshd_config"
pam_sshd_config_file="/etc/pam.d/sshd"
loader_conf_file="/boot/loader.conf"
rc_conf_file="/etc/rc.conf"
managed_ipfw_rules_file="/etc/ipfw.rules"
source_ipfw_rules_file="$script_dir/ipfw.rules"
suricata_conf_file="/usr/local/etc/suricata/suricata.yaml"
suricata_custom_conf_file="/usr/local/etc/suricata/suricata-custom.yaml"
suricata_rules_file="/var/lib/suricata/rules/custom.rules"
wheel_sudo_regex='^%wheel[[:blank:]]+ALL=\(ALL(:ALL)?\)[[:blank:]]+(NOPASSWD:[[:blank:]]+)?ALL'

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

# Persisted internal cutover state
internal_cutover_state_defaults="
transitional_ssh_port=
wheel_sudo_finalized=
wheel_membership_finalized=
cutover_boot_marker=
port_transition_old_port=
"

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

set_kv_defaults "$public_cli_config_defaults"
set_kv_defaults "$internal_cutover_state_defaults"

# Captured CLI identity/policy values
cli_user="${user-}"
cli_ssh_port="${ssh_port-}"
cli_disable_wheel="${disable_wheel-}"
cli_remove_wheel_members="${remove_wheel_members-}"

capture_desired_mutable_baseline_settings() {
    for override_var in $mutable_baseline_override_vars; do
        eval "desired_value=\${$override_var-}"
        eval "desired_$override_var=\$desired_value"
    done
}

restore_desired_mutable_baseline_settings() {
    for override_var in $mutable_baseline_override_vars; do
        eval "desired_value=\${desired_$override_var-}"
        if [ -n "$desired_value" ]; then
            eval "$override_var=\$desired_value"
        fi
    done
}

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo or run as root user."
    exit 1
fi

###############################################################################
# Validation Helpers
###############################################################################

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

file_has_exact_line() {
    target_file="$1"
    expected_line="$2"
    [ -f "$target_file" ] && grep -qxF "$expected_line" "$target_file"
}

file_has_all_exact_lines() {
    target_file="$1"
    expected_lines="$2"
    old_ifs=$IFS
    IFS='
'
    for expected_line in $expected_lines; do
        [ -n "$expected_line" ] || continue
        file_has_exact_line "$target_file" "$expected_line" || {
            IFS=$old_ifs
            return 1
        }
    done
    IFS=$old_ifs
}

sudo_policy_is_valid() {
    [ -f /usr/local/etc/sudoers.d/sudo ] &&
        grep -qxF "$sudo_policy_line" /usr/local/etc/sudoers.d/sudo &&
        visudo -c >/dev/null
}

wheel_sudo_is_active() {
    grep -qE "$wheel_sudo_regex" /usr/local/etc/sudoers ||
        { [ -f /usr/local/etc/sudoers.d/wheel ] && [ ! -f /usr/local/etc/sudoers.d/wheel.disabled ]; }
}

non_root_wheel_members_present() {
    getent group wheel | cut -d ':' -f 4 | tr ',' '\n' | grep -qEv '^(|root)$'
}

load_live_managed_firewall_context() {
    [ -f "$managed_ipfw_rules_file" ] || return 0

    for managed_var in $managed_firewall_context_vars; do
        eval "managed_value=\${$managed_var-}"
        if [ -z "$managed_value" ]; then
            managed_value=$(read_simple_assignment_value "$managed_ipfw_rules_file" "$managed_var" 2>/dev/null || printf '')
            if [ -n "$managed_value" ]; then
                eval "$managed_var=\$managed_value"
            fi
        fi
    done

    if [ -z "${install_suricata-}" ]; then
        if [ -n "${suricata_port-}" ] && [ "${suricata_port-}" != "none" ]; then
            install_suricata="yes"
        else
            install_suricata="no"
        fi
    fi
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
    old_ifs=$IFS
    IFS='
'
    for expected_line in $expected_lines; do
        [ -n "$expected_line" ] || continue
        effective_sshd_has_line "$sshd_effective" "$expected_line" || {
            IFS=$old_ifs
            return 1
        }
    done
    IFS=$old_ifs
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
    if [ -n "$extra_port" ] && [ "$extra_port" != "none" ] && [ "$extra_port" != "$primary_port" ]; then
        ports_csv="$extra_port,$primary_port"
    fi

    normalize_csv_set "$ports_csv"
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
    printf 'Error: %s. Deferred admin fallback policy has not been changed.\n' "$1"
}

pending_cutover_message() {
    stage_label="$1"
    next_step="$2"
    printf '%s is pending verification.\n' "$stage_label"
    printf '%s\n' "$next_step"
}

strict_ssh_config_ready() {
    [ -n "${user-}" ] || return 1
    [ -n "${ssh_port-}" ] || return 1

    if ! sshd -t -f "$sshd_config_file" >/dev/null 2>&1; then
        return 1
    fi

    sshd_effective=$(sshd -T -f "$sshd_config_file" 2>/dev/null) || return 1

    effective_sshd_matches_lines "$sshd_effective" "$strict_ssh_effective_policy_lines" &&
        effective_sshd_ports_match "$sshd_effective" "$ssh_port" &&
        effective_sshd_allowusers_includes "$sshd_effective" "$user"
}

transitional_ssh_config_ready() {
    [ -n "${user-}" ] || return 1

    if ! sshd -t -f "$sshd_config_file" >/dev/null 2>&1; then
        return 1
    fi

    sshd_effective=$(sshd -T -f "$sshd_config_file" 2>/dev/null) || return 1

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

    if ! sshd -t -f "$sshd_config_file" >/dev/null 2>&1; then
        return 1
    fi

    sshd_effective=$(sshd -T -f "$sshd_config_file" 2>/dev/null) || return 1

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

cutover_policy_requires_fallback_removal() {
    set_default_if_empty "disable_wheel" "no"
    set_default_if_empty "remove_wheel_members" "no"

    [ "$disable_wheel" = "yes" ] || [ "$remove_wheel_members" = "yes" ]
}

resolved_wheel_sudo_finalized_state() {
    set_default_if_empty "disable_wheel" "no"
    set_default_if_empty "wheel_sudo_finalized" "no"

    if [ "$disable_wheel" != "yes" ] || [ "$wheel_sudo_finalized" = "yes" ]; then
        printf '%s\n' "yes"
    else
        printf '%s\n' "no"
    fi
}

resolved_wheel_membership_finalized_state() {
    set_default_if_empty "remove_wheel_members" "no"
    set_default_if_empty "wheel_membership_finalized" "no"

    if [ "$remove_wheel_members" != "yes" ] || [ "$wheel_membership_finalized" = "yes" ]; then
        printf '%s\n' "yes"
    else
        printf '%s\n' "no"
    fi
}

wheel_policy_fully_finalized() {
    [ "$(resolved_wheel_sudo_finalized_state)" = "yes" ] &&
        [ "$(resolved_wheel_membership_finalized_state)" = "yes" ]
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
        if [ "${disable_wheel:-no}" = "yes" ]; then
            wheel_sudo_finalized="no"
        else
            wheel_sudo_finalized="yes"
        fi
        if [ "${remove_wheel_members:-no}" = "yes" ]; then
            wheel_membership_finalized="no"
        else
            wheel_membership_finalized="yes"
        fi
        ;;
    current)
        wheel_sudo_finalized=$(resolved_wheel_sudo_finalized_state)
        wheel_membership_finalized=$(resolved_wheel_membership_finalized_state)
        ;;
    *)
        echo "Error: Unknown wheel policy state '$wheel_policy_state'."
        return 1
        ;;
    esac

    write_cutover_state "committed_strict_ready" "$wheel_sudo_finalized" "$wheel_membership_finalized"
}

wheel_sudo_matches_saved_policy() {
    set_default_if_empty "disable_wheel" "no"
    set_default_if_empty "wheel_sudo_finalized" "no"

    if [ "$disable_wheel" != "yes" ]; then
        return 0
    fi

    if [ "$wheel_sudo_finalized" = "yes" ]; then
        if wheel_sudo_is_active; then
            return 1
        fi
        return 0
    fi

    wheel_sudo_is_active
}

wheel_membership_matches_saved_policy() {
    set_default_if_empty "remove_wheel_members" "no"
    set_default_if_empty "wheel_membership_finalized" "no"

    if [ "$remove_wheel_members" != "yes" ]; then
        return 0
    fi

    if [ "$wheel_membership_finalized" = "yes" ]; then
        if non_root_wheel_members_present; then
            return 1
        fi
        return 0
    fi

    non_root_wheel_members_present
}

firewall_loader_matches_state() {
    expected_loader_settings=$(build_firewall_loader_settings)
    file_has_all_exact_lines "$loader_conf_file" "$expected_loader_settings"
}

firewall_rc_conf_matches_state() {
    file_has_all_exact_lines "$rc_conf_file" "$managed_firewall_rc_conf_lines"
}

firewall_rules_match_state() {
    [ -f "$managed_ipfw_rules_file" ] || return 1

    for required_var in $managed_firewall_rules_state_vars; do
        expected_value=$(eval "printf '%s' \"\${$required_var-}\"")
        actual_value=$(read_simple_assignment_value "$managed_ipfw_rules_file" "$required_var" 2>/dev/null || printf '')
        [ "$actual_value" = "$expected_value" ] || return 1
    done

    actual_value=$(read_simple_assignment_value "$managed_ipfw_rules_file" "ssh_port" 2>/dev/null || printf '')
    [ "$actual_value" = "$ssh_port" ]
}

firewall_boot_state_matches_state() {
    firewall_loader_matches_state &&
        firewall_rc_conf_matches_state &&
        firewall_rules_match_state &&
        suricata_config_matches_state
}

managed_ssh_ports_for_current_stage() {
    if [ "${cutover_stage:-}" = "pending_port_transition_reboot" ] &&
        [ -n "${port_transition_old_port:-}" ]; then
        compose_normalized_port_set "$ssh_port" "$port_transition_old_port"
        return 0
    fi

    if [ "${cutover_stage:-}" = "pending_port_commit_reboot" ]; then
        compose_normalized_port_set "$ssh_port"
        return 0
    fi

    compose_normalized_port_set "$ssh_port"
}

managed_ssh_ports_for_generated_state() {
    compose_normalized_port_set "$ssh_port" "${port_transition_old_port:-}"
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

suricata_managed_ssh_rule() {
    ssh_ports_csv="$1"
    suricata_rule_ports=$(suricata_ssh_rule_ports_value "$ssh_ports_csv")
    printf '%s\n' "alert tcp any any -> any $suricata_rule_ports (msg:\"Managed SSH connection on staged ports $suricata_rule_ports\"; sid:1000001; rev:2;)"
}

suricata_config_matches_state() {
    ssh_ports_csv=$(managed_ssh_ports_for_current_stage)
    expected_yaml_ports=$(suricata_ssh_ports_value "$ssh_ports_csv")
    expected_rule_ports=$(normalize_csv_set "$ssh_ports_csv")

    if [ "${install_suricata:-no}" != "yes" ] || [ "${suricata_port:-none}" = "none" ]; then
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
        [ -n "${ssh_ipv4:-}" ] && [ "${ssh_ipv4:-}" != "none" ] || return 0
        expected_source="$ssh_ipv4"
        expected_destination="me"
        ;;
    ipv6)
        [ -n "${ssh_ipv6:-}" ] && [ "${ssh_ipv6:-}" != "none" ] || return 0
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

    if [ "${install_suricata:-no}" != "yes" ] || [ "${suricata_port:-none}" = "none" ] || [ "${nat_if:-none}" = "none" ]; then
        return 0
    fi

    expected_rule="divert $suricata_port ip from any to any not proto icmp not proto ipv6-icmp in recv $nat_if"
    printf '%s\n' "$runtime_rules" | grep -Fq "$expected_rule"
}

runtime_has_managed_nat_rule() {
    runtime_rules="$1"

    if [ "${nat_if:-none}" = "none" ]; then
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

    expected_ssh_ports=$(managed_ssh_ports_for_current_stage)
    if ! runtime_has_managed_ssh_rule "$runtime_rules" ipv4 "$expected_ssh_ports" ||
        ! runtime_has_managed_ssh_rule "$runtime_rules" ipv6 "$expected_ssh_ports"; then
        printf '%s\n' "misaligned"
        return 0
    fi

    if ! ipfw table all list >/dev/null 2>&1; then
        printf '%s\n' "misaligned"
        return 0
    fi

    if [ "${nat_if:-none}" != "none" ]; then
        if ! runtime_has_managed_nat_rule "$runtime_rules" || ! ipfw nat show config >/dev/null 2>&1; then
            printf '%s\n' "misaligned"
            return 0
        fi
    fi

    if [ "${install_suricata:-no}" = "yes" ] && [ "${suricata_port:-none}" != "none" ]; then
        if ! runtime_has_managed_suricata_divert_rule "$runtime_rules"; then
            printf '%s\n' "misaligned"
            return 0
        fi
    fi

    printf '%s\n' "aligned"
}

warn_if_firewall_runtime_absent() {
    if [ "${current_firewall_runtime_state:-}" = "absent" ]; then
        echo "Warning: Managed firewall boot state is committed, but runtime ipfw is currently inactive. A future reboot or firewall activation will enforce the managed rules."
    fi
}

validate_pending_port_transition_alignment() {
    active_boot_marker=$(current_boot_marker)
    if [ -n "${cutover_boot_marker:-}" ] && [ -n "$active_boot_marker" ] && [ "$active_boot_marker" = "$cutover_boot_marker" ]; then
        echo "Error: The host has not rebooted since the pending SSH port transition state was written. Reboot and verify login on the new SSH port before advancing this stage."
        return 1
    fi
    validate_stage_alignment_common \
        "saved SSH port transition state" \
        "pending_port_transition_sshd_matches_state" \
        "The live sshd configuration no longer matches the pending SSH port transition state." \
        "The managed SSH public key or Google Authenticator path no longer matches the pending SSH port transition state." \
        "The managed sudo path no longer matches the pending SSH port transition state." \
        "The saved %wheel sudo policy no longer matches the live host during the SSH port transition." \
        "The saved wheel membership policy no longer matches the live host during the SSH port transition." \
        "The managed firewall boot state no longer matches the pending SSH port transition." \
        "The live ipfw runtime state could not be classified during the SSH port transition." \
        "The live ipfw runtime state no longer matches the pending SSH port transition."
}

validate_pending_transitional_alignment() {
    validate_stage_alignment_common \
        "pending transitional SSH verification state" \
        "transitional_ssh_config_ready" \
        "The live sshd configuration no longer matches the pending transitional SSH verification state." \
        "The managed SSH public key or Google Authenticator path no longer matches the pending transitional SSH verification state." \
        "The managed sudo path no longer matches the pending transitional SSH verification state." \
        "The saved %wheel sudo policy no longer matches the live host during pending transitional verification." \
        "The saved wheel membership policy no longer matches the live host during pending transitional verification."
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

    sudo_admin_path_matches_state || {
        cutover_alignment_error="managed sudo policy or sudo group membership is no longer aligned"
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

    current_firewall_runtime_state=$(firewall_runtime_state_class) || {
        cutover_alignment_error="managed firewall runtime state could not be classified"
        return 1
    }
    if [ "$current_firewall_runtime_state" = "misaligned" ]; then
        cutover_alignment_error="managed firewall runtime state is loaded but no longer aligned"
        return 1
    fi
}

managed_ssh_auth_assets_ready() {
    set_user_auth_paths "$user"
    [ -f "$authorized_keys" ] && [ -s "$authorized_keys" ] &&
        [ -f "$ga_config" ] && [ -s "$ga_config" ]
}

validate_stage_alignment_common() {
    stage_identity_context="$1"
    ssh_validator="$2"
    ssh_error_message="$3"
    auth_error_message="$4"
    sudo_error_message="$5"
    wheel_sudo_error_message="$6"
    wheel_members_error_message="$7"
    firewall_boot_error_message="${8:-}"
    firewall_runtime_classify_error_message="${9:-}"
    firewall_runtime_misaligned_error_message="${10:-}"

    if ! cutover_state_matches_live_identity; then
        echo "Error: The managed user identity no longer matches the $stage_identity_context."
        return 1
    fi

    if ! "$ssh_validator"; then
        echo "Error: $ssh_error_message"
        return 1
    fi

    if ! managed_ssh_auth_assets_ready; then
        echo "Error: $auth_error_message"
        return 1
    fi

    if ! sudo_admin_path_matches_state; then
        echo "Error: $sudo_error_message"
        return 1
    fi

    if ! wheel_sudo_matches_saved_policy; then
        echo "Error: $wheel_sudo_error_message"
        return 1
    fi

    if ! wheel_membership_matches_saved_policy; then
        echo "Error: $wheel_members_error_message"
        return 1
    fi

    if [ -n "$firewall_boot_error_message" ]; then
        if ! firewall_boot_state_matches_state; then
            echo "Error: $firewall_boot_error_message"
            return 1
        fi

        current_firewall_runtime_state=$(firewall_runtime_state_class) || {
            echo "Error: $firewall_runtime_classify_error_message"
            return 1
        }
        if [ "$current_firewall_runtime_state" = "misaligned" ]; then
            echo "Error: $firewall_runtime_misaligned_error_message"
            return 1
        fi
    fi
}

validate_cutover_state_alignment() {
    if ! managed_state_is_aligned_with_live_state; then
        echo "Error: Managed cutover state is stale or inconsistent with the live host (${cutover_alignment_error:-unknown mismatch}). Clear the managed cutover state and start a fresh staged cutover."
        return 1
    fi
}

validate_pending_strict_alignment() {
    validate_stage_alignment_common \
        "pending strict SSH verification state" \
        "ssh_admin_path_matches_state" \
        "The managed SSH public key, Google Authenticator, or strict sshd configuration no longer matches the pending strict SSH verification state." \
        "The managed SSH public key, Google Authenticator, or strict sshd configuration no longer matches the pending strict SSH verification state." \
        "The managed sudo path no longer matches the pending strict SSH verification state." \
        "The saved %wheel sudo policy no longer matches the live host during pending strict verification." \
        "The saved wheel membership policy no longer matches the live host during pending strict verification." \
        "The managed firewall boot state no longer matches the pending strict SSH verification state." \
        "The live ipfw runtime state could not be classified during pending strict SSH verification." \
        "The live ipfw runtime state no longer matches the pending strict SSH verification state."
}

cutover_cli_conflict() {
    managed_label="$1"
    managed_value="$2"
    requested_label="$3"
    requested_value="$4"
    resolution_message="$5"
    echo "Error: The managed $managed_label is '$managed_value', but $requested_label requested '$requested_value'. $resolution_message"
}

cutover_identity_conflicts_with_cli() {
    if [ -n "${cli_user-}" ] && [ "$cli_user" != "$user" ]; then
        cutover_cli_conflict "SSH user" "$user" "--user" "$cli_user" "Start a fresh staged cutover after clearing the managed cutover state."
        return 0
    fi

    if [ -n "${cli_ssh_port-}" ] && [ "$cli_ssh_port" != "$ssh_port" ]; then
        cutover_cli_conflict "SSH port" "$ssh_port" "--ssh-port" "$cli_ssh_port" "Changing the SSH port requires the staged SSH port migration flow or a fresh staged cutover."
        return 0
    fi

    if [ -n "${cli_disable_wheel-}" ] && [ -n "${disable_wheel-}" ] && [ "$cli_disable_wheel" != "$disable_wheel" ]; then
        cutover_cli_conflict "%wheel sudo policy disable_wheel" "$disable_wheel" "--disable-wheel" "$cli_disable_wheel" "Start a fresh staged cutover after clearing the managed cutover state."
        return 0
    fi

    if [ -n "${cli_remove_wheel_members-}" ] && [ -n "${remove_wheel_members-}" ] && [ "$cli_remove_wheel_members" != "$remove_wheel_members" ]; then
        cutover_cli_conflict "wheel membership policy remove_wheel_members" "$remove_wheel_members" "--remove-wheel-members" "$cli_remove_wheel_members" "Start a fresh staged cutover after clearing the managed cutover state."
        return 0
    fi

    return 1
}

validate_saved_cutover_cli_consistency() {
    validate_port_transition_cli_consistency || return 1
    if cutover_identity_conflicts_with_cli; then
        return 1
    fi
}

snapshot_public_cutover_fields() {
    saved_public_user="${user-}"
    saved_public_ssh_port="${ssh_port-}"
    saved_public_disable_wheel="${disable_wheel-}"
    saved_public_remove_wheel_members="${remove_wheel_members-}"
}

restore_public_cutover_fields_if_missing() {
    [ -n "${user-}" ] || user="$saved_public_user"
    [ -n "${ssh_port-}" ] || ssh_port="$saved_public_ssh_port"
    [ -n "${disable_wheel-}" ] || disable_wheel="$saved_public_disable_wheel"
    [ -n "${remove_wheel_members-}" ] || remove_wheel_members="$saved_public_remove_wheel_members"
}

admin_access_is_ready() {
    [ -n "${user-}" ] || return 1
    validate_user "$user" >/dev/null 2>&1 || return 1
    set_user_auth_paths "$user"

    sudo_policy_is_valid &&
        user_in_group "$user" "sudo" &&
        [ -f "$authorized_keys" ] &&
        [ -s "$authorized_keys" ] &&
        [ -f "$ga_config" ] &&
        [ -s "$ga_config" ]
}

detect_cutover_mode() {
    cutover_mode="needs_stage_one"

    if managed_state_is_aligned_with_live_state && admin_access_is_ready; then
        if cutover_policy_requires_fallback_removal && ! wheel_policy_fully_finalized; then
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

###############################################################################
# File, Template, And State Persistence Helpers
###############################################################################

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

current_boot_marker() {
    sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9][0-9]*\).*/\1/p'
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
    persisted_transitional_ssh_port=""
    persisted_port_transition_old_port=""

    case "$cutover_stage" in
    pending_transitional_verify)
        persisted_transitional_ssh_port="${transitional_ssh_port:-}"
        ;;
    pending_port_transition_reboot | pending_port_commit_reboot)
        persisted_port_transition_old_port="${port_transition_old_port:-}"
        ;;
    esac

    cutover_user_uid=$(id -u "$user")
    [ -d "$cutover_state_dir" ] || mkdir -p "$cutover_state_dir"
    chmod 700 "$cutover_state_dir"
    tmp_file=$(make_secure_tmp "$cutover_state_dir")
    cat >"$tmp_file" <<EOF
cutover_stage="$cutover_stage"
cutover_boot_marker="${cutover_boot_marker:-}"
user="$user"
cutover_user_uid="$cutover_user_uid"
ssh_port="$ssh_port"
transitional_ssh_port="$persisted_transitional_ssh_port"
disable_wheel="${disable_wheel:-}"
remove_wheel_members="${remove_wheel_members:-}"
wheel_sudo_finalized="${wheel_sudo_finalized_state:-}"
wheel_membership_finalized="${wheel_membership_finalized_state:-}"
port_transition_old_port="$persisted_port_transition_old_port"
EOF
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
    snapshot_public_cutover_fields

    if ! load_cutover_state; then
        return 1
    fi

    restore_public_cutover_fields_if_missing

    for managed_var in $mutable_baseline_override_vars; do
        eval "$managed_var=''"
    done
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

emit_yes_settings() {
    key_list=$1
    old_ifs=$IFS
    IFS=' '
    for key_name in $key_list; do
        [ -n "$key_name" ] || continue
        printf '%s="YES"\n' "$key_name"
    done
    IFS=$old_ifs
}

emit_boolean_setting() {
    key_name="$1"
    key_value="$2"
    printf '%s="%s"\n' "$key_name" "$key_value"
}

append_managed_strict_ssh_settings() {
    settings_block="$1"
    settings_block=$(append_setting_line "$settings_block" 'PasswordAuthentication=no')
    settings_block=$(append_setting_line "$settings_block" 'AuthenticationMethods=publickey,keyboard-interactive')
    settings_block=$(append_setting_line "$settings_block" "AllowUsers=$user")
    printf '%s\n' "$settings_block"
}

build_firewall_loader_settings() {
    set_default_if_empty "install_suricata" "no"

    loader_settings=$(emit_yes_settings "ipfw_load dummynet_load")
    if [ "${nat_if:-none}" != "none" ]; then
        loader_settings=$(append_setting_line "$loader_settings" "$(emit_boolean_setting "ipfw_nat_load" "YES")")
    else
        loader_settings=$(append_setting_line "$loader_settings" "$(emit_boolean_setting "ipfw_nat_load" "NO")")
    fi

    if [ "$install_suricata" = "yes" ] && [ "${suricata_port:-none}" != "none" ]; then
        loader_settings=$(append_setting_line "$loader_settings" "$(emit_boolean_setting "ipdivert_load" "YES")")
    else
        loader_settings=$(append_setting_line "$loader_settings" "$(emit_boolean_setting "ipdivert_load" "NO")")
    fi

    printf '%s\n' "$loader_settings"
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

###############################################################################
# CLI Parsing
###############################################################################

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
    case "$1" in
    user | ssh_port | ssh_ipv4 | ssh_ipv6 | log_ssh_hits | log_wan_tcp_hits | allow_multicast | allow_multicast_legacy | internal_if | nat_if | tun_if | install_auditing | install_microcode | install_suricata | suricata_port | password_exp | disable_wheel | remove_wheel_members | confirm_stage_advance)
        return 0
        ;;
    *)
        return 1
        ;;
    esac
}

set_option_value() {
    option_name=$(normalize_option_name "$1") || return 1
    cli_option_is_supported "$option_name" || return 1
    eval "$option_name=\$2"
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
    allow_multicast_value="${allow_multicast:-no}"
    allow_multicast_legacy_value="${allow_multicast_legacy:-no}"
    if [ "$allow_multicast_legacy_value" = "yes" ] && [ "$allow_multicast_value" != "yes" ]; then
        echo "--allow-multicast-legacy yes requires --allow-multicast yes."
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

###############################################################################
# Mutation Helpers
###############################################################################

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

###############################################################################
# Interactive Input Collection
###############################################################################

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

    prompt_yes_no_default "log_ssh_hits" "Enable SSH SYN count/log rules for firewall debugging?" "no" "--log-ssh-hits" || return 1
    prompt_yes_no_default "log_wan_tcp_hits" "Enable WAN TCP SYN count/log rules for firewall debugging?" "no" "--log-wan-tcp-hits" || return 1
    prompt_yes_no_default "allow_multicast" "Allow modern multicast on the trusted internal bridge path?" "no" "--allow-multicast" || return 1
    if [ "$allow_multicast" = "yes" ]; then
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
    prompt_yes_no_default "install_suricata" "Do you want to install and configure Suricata?" "no" "--install-suricata" || return 1
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

# Prepare SSH key material for the SSH user
prepare_ssh_user_access() {
    echo "Preparing SSH key access for the SSH user..."
    set_user_auth_paths "$user"
    generated_ssh_key="no"

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
        generated_ssh_key="yes"
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

    echo "Public key authentication prepared for $user."

    if [ "$generated_ssh_key" = "yes" ]; then
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
        echo "Press ENTER to confirm you have securely copied the private key and are ready to proceed."
        read -r _dummy_variable
    else
        echo "Existing SSH key access is already present for $user."
    fi
}

###############################################################################
# SSH Profiles And Transition Stages
###############################################################################

build_sshd_settings() {
    ssh_profile="$1"
    sshd_settings='
PermitRootLogin=no
MaxAuthTries=3
KbdInteractiveAuthentication=yes
PubkeyAuthentication=yes
UsePAM=yes
UseDNS=no
ClientAliveInterval=60
ClientAliveCountMax=1
'

    case "$ssh_profile" in
    transitional)
        sshd_settings=$(append_setting_line "$sshd_settings" 'PasswordAuthentication=yes')
        ;;
    port_transition)
        sshd_settings=$(append_managed_strict_ssh_settings "$sshd_settings")
        sshd_settings=$(append_setting_line "$sshd_settings" "Port=$port_transition_old_port")
        sshd_settings=$(append_setting_line "$sshd_settings" "Port=$ssh_port")
        ;;
    strict)
        sshd_settings=$(append_managed_strict_ssh_settings "$sshd_settings")
        sshd_settings=$(append_setting_line "$sshd_settings" "Port=$ssh_port")
        ;;
    *)
        echo "Error: Unknown SSH profile '$ssh_profile'."
        return 1
        ;;
    esac

    emit_field_settings "$sshd_settings"
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

set_port_transition_values() {
    port_transition_old_port="$1"
}

clear_port_transition_values() {
    port_transition_old_port=""
}

write_port_transition_state() {
    transition_stage="$1"
    cutover_boot_marker=$(current_boot_marker)
    wheel_sudo_finalized=$(resolved_wheel_sudo_finalized_state)
    wheel_membership_finalized=$(resolved_wheel_membership_finalized_state)
    write_cutover_state "$transition_stage" "$wheel_sudo_finalized" "$wheel_membership_finalized"
}

validate_port_transition_cli_consistency() {
    if [ -n "${cli_ssh_port-}" ] && [ "$cli_ssh_port" != "$ssh_port" ]; then
        echo "Error: A staged SSH port transition to '$ssh_port' is already pending, but --ssh-port requested '$cli_ssh_port'. Complete or clear the pending port transition first."
        return 1
    fi
}

run_port_transition_stage_one() {
    old_ssh_port="$ssh_port"
    new_ssh_port="$cli_ssh_port"

    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    set_port_transition_values "$old_ssh_port"
    ssh_port="$new_ssh_port"
    configure_firewall_boot || return 1
    if ! apply_sshd_profile port_transition; then
        return 1
    fi
    write_port_transition_state "pending_port_transition_reboot"
    current_firewall_runtime_state=$(firewall_runtime_state_class)
    reapply_immutable_flags
    echo "SSH port transition stage 1 complete. Boot policy now allows both the old port ($old_ssh_port) and the new port ($new_ssh_port)."
    if kldstat -q -m ipfw >/dev/null 2>&1; then
        echo "Runtime ipfw is still enforcing the pre-reboot ruleset on this boot. The dual-port firewall policy will take effect after reboot."
    fi
    warn_if_firewall_runtime_absent
    echo "Reboot the host, verify a fresh login on the new SSH port, then rerun this script with --confirm-stage-advance yes to remove the old SSH port from the managed boot policy."
}

run_port_transition_stage_two() {
    old_ssh_port="$port_transition_old_port"
    new_ssh_port="$ssh_port"

    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    ssh_port="$new_ssh_port"
    clear_port_transition_values
    configure_firewall_boot || return 1
    if ! apply_sshd_profile strict; then
        return 1
    fi
    set_port_transition_values "$old_ssh_port"
    write_port_transition_state "pending_port_commit_reboot"
    current_firewall_runtime_state=$(firewall_runtime_state_class)
    reapply_immutable_flags
    echo "SSH port transition stage 2 complete. Managed boot policy now keeps only the new SSH port ($new_ssh_port)."
    if kldstat -q -m ipfw >/dev/null 2>&1; then
        echo "Runtime ipfw is still enforcing the pre-reboot ruleset on this boot. The new-port-only firewall policy will take effect after reboot."
    fi
    warn_if_firewall_runtime_absent
    echo "Reboot the host, verify a fresh login on the new SSH port again, then rerun this script with --confirm-stage-advance yes to finalize the port migration."
}

run_port_transition_stage_three() {
    new_ssh_port="$ssh_port"

    clear_immutable_flags
    ssh_port="$new_ssh_port"
    transitional_ssh_port=""
    clear_port_transition_values
    record_committed_cutover_state current || return 1
    reapply_immutable_flags
    echo "SSH port migration to $new_ssh_port has been finalized."
}

reload_sshd_safe() {
    if ! sshd -t -f "$sshd_config_file" >/dev/null 2>&1; then
        echo "Error: sshd configuration validation failed."
        return 1
    fi

    if ! service sshd reload >/dev/null 2>&1; then
        echo "Error: Failed to reload sshd."
        return 1
    fi
}

###############################################################################
# Admin Path Preparation And Finalization
###############################################################################

# Configure PAM security settings
configure_ssh_pam() {
    echo "Configuring SSH PAM for Google Authenticator..."
    ga_pam_line="auth requisite pam_google_authenticator.so"

    # Check if pam_google_authenticator.so is already present
    if grep -q "^$ga_pam_line" "$pam_sshd_config_file"; then
        echo "Google Authenticator is already enabled in PAM SSH configuration."
        return
    fi
    pam_sshd_tmp=$(make_secure_tmp "$(dirname "$pam_sshd_config_file")")

    if ! run_awk_template "$pam_sshd_config_file" "$pam_sshd_tmp" "$pam_sshd_config_file" "awk/pam_sshd_google_auth.awk" -v ga_line="$ga_pam_line"; then
        return 1
    fi

    # Replace the sshd config file atomically
    atomic_replace "$pam_sshd_config_file" "$pam_sshd_tmp"

    echo "Google Authenticator added to the auth section of PAM SSH configuration."
    echo "SSH and PAM changes have been written to disk; the staged cutover will validate and reload sshd explicitly."
}

# Configure Google Authenticator TOTP for the SSH user
configure_google_auth() {
    echo "Configuring Google Authenticator TOTP for the SSH user..."

    set_user_auth_paths "$user"

    if [ -f "$ga_config" ] && [ -s "$ga_config" ]; then
        echo "Google Authenticator TOTP is already configured for $user."
        return 0
    fi

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

# Prepare sudo access for the SSH user without changing deferred admin fallback policy yet
prepare_sudo_access() {
    echo "Preparing sudo access for administrative users..."

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
        echo "$sudo_policy_line" >/usr/local/etc/sudoers.d/sudo
        chmod 440 /usr/local/etc/sudoers.d/sudo
    fi

    if ! visudo -c >/dev/null; then
        echo "Error: sudoers validation failed. Wheel access will not be changed."
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

    echo "Sudo access prepared and validated. Deferred admin fallback policy changes will wait until the final admin-path validation passes."
}

# Validate that the replacement admin path exists before any deferred admin fallback policy changes happen
assert_admin_access_ready() {
    set_user_auth_paths "$user"

    if admin_access_is_ready; then
        echo "Final admin-path validation passed. SSH/PAM config is syntax-valid and the replacement sudo path is present."
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

    echo "Final admin-path validation passed. SSH/PAM config is syntax-valid and the replacement sudo path is present."
}

# Finalize sudo hardening only after the replacement admin path has been validated
finalize_sudo_access() {
    echo "Finalizing sudo hardening..."
    set_default_if_empty "disable_wheel" "no"
    set_default_if_empty "remove_wheel_members" "no"

    if [ "$disable_wheel" = "yes" ]; then
        echo "Disabling sudo access for the wheel group..."

        if grep -qE "$wheel_sudo_regex" /usr/local/etc/sudoers; then
            atomic_sed_replace /usr/local/etc/sudoers -E "s/${wheel_sudo_regex}/# &/"
            echo "Commented out %wheel group sudo access in /usr/local/etc/sudoers."
        fi

        if [ -f /usr/local/etc/sudoers.d/wheel ]; then
            mv /usr/local/etc/sudoers.d/wheel /usr/local/etc/sudoers.d/wheel.disabled
            echo "Disabled /usr/local/etc/sudoers.d/wheel."
        fi
    else
        echo "Wheel group sudo access remains enabled."
    fi

    if [ "$remove_wheel_members" = "yes" ]; then
        users_removed=""
        echo "Removing non-root users from the wheel group..."
        for wheel_user in $(getent group wheel | cut -d ':' -f 4 | tr ',' '\n'); do
            if [ "$wheel_user" != "root" ] && [ -n "$wheel_user" ]; then
                pw groupmod wheel -d "$wheel_user"
                users_removed="${users_removed}${wheel_user},"
            fi
        done

        if [ -n "$users_removed" ]; then
            users_removed=$(echo "$users_removed" | sed 's/,$//')
            echo "Users removed from the wheel group: ${users_removed}"
        else
            echo "No users removed from the wheel group."
        fi
    else
        echo "No users removed from the wheel group."
    fi

    echo "Sudo hardening finalized. Log out and log in again before relying on the new sudo group membership."
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
    if ! apply_sshd_profile transitional; then
        return 1
    fi
    if ! reload_sshd_safe; then
        return 1
    fi
    sshd_effective=$(sshd -T -f "$sshd_config_file" 2>/dev/null) || return 1
    transitional_ssh_port=$(effective_sshd_ports_csv "$sshd_effective")
    [ -n "$transitional_ssh_port" ] || {
        echo "Error: Could not determine the transitional SSH port after reloading sshd."
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
    echo "Stage 1 complete. A transitional SSH configuration has been reloaded."
    echo "Verify that you can log in through a fresh SSH session using the new path, then rerun this script with --confirm-stage-advance yes to enforce strict SSH authentication."
    echo "Firewall boot activation is still deferred. Rebooting now will not activate the managed ipfw boot path yet."
}

run_stage_two() {
    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    transitional_ssh_port=""
    if ! apply_sshd_profile strict; then
        return 1
    fi
    if ! reload_sshd_safe; then
        return 1
    fi
    assert_admin_access_ready
    configure_firewall_boot
    wheel_sudo_finalized=$(resolved_wheel_sudo_finalized_state)
    wheel_membership_finalized=$(resolved_wheel_membership_finalized_state)
    write_cutover_state "pending_strict_verify" "$wheel_sudo_finalized" "$wheel_membership_finalized"
    reapply_immutable_flags
    echo "Stage 2 complete. Strict SSH authentication has been reloaded."
    echo "Firewall boot handling has now been committed and future reboots will use the managed firewall configuration."
    echo "Verify a fresh pubkey+TOTP login, then rerun this script with --confirm-stage-advance yes to finalize the deferred admin fallback policy."
}

advance_pending_strict_stage() {
    converge_strict_cutover_state || return 1
    if cutover_policy_requires_fallback_removal && ! wheel_policy_fully_finalized; then
        finalize_deferred_admin_fallback || return 1
        echo "Strict SSH has been externally verified. Deferred admin fallback policy has now been finalized."
    else
        record_committed_cutover_state || return 1
        echo "Strict SSH has been externally verified and committed without deferred admin fallback changes."
    fi
}

advance_pending_port_commit_stage() {
    run_port_transition_stage_three || return 1
    if cutover_policy_requires_fallback_removal && ! wheel_policy_fully_finalized; then
        echo "SSH port migration is complete. Rerun the script to finalize the deferred admin fallback policy."
    fi
}

handle_pending_stage() {
    stage_label="$1"
    next_step="$2"
    validate_fn="$3"
    advance_fn="$4"

    validate_saved_cutover_cli_consistency || return 1
    if [ "$confirm_stage_advance" != "yes" ]; then
        pending_cutover_message "$stage_label" "$next_step"
        return 0
    fi
    "$validate_fn" || return 1
    "$advance_fn"
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
    if ! apply_sshd_profile strict; then
        return 1
    fi
    if ! reload_sshd_safe; then
        return 1
    fi
    if ! admin_access_is_ready; then
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

    if [ "$finalize_admin_fallback" = "yes" ]; then
        finalize_sudo_access
        record_committed_cutover_state "final"
        echo "Strict SSH is already live. Deferred admin cleanup has been finalized in this run."
    else
        record_committed_cutover_state
        echo "System is already fully hardened. Reapplying the baseline without staged SSH cutover."
    fi

    lock_down_system
}

handle_pending_cutover() {
    set_default_if_empty "confirm_stage_advance" "no"
    if [ "${cutover_stage:-}" = "committed_strict_ready" ] &&
        [ "${cutover_stage:-}" != "pending_port_transition_reboot" ] &&
        [ "${cutover_stage:-}" != "pending_port_commit_reboot" ]; then
        validate_cutover_state_alignment || return 1
    fi

    if ssh_port_transition_requested &&
        [ "${cutover_stage:-}" != "pending_port_transition_reboot" ] &&
        [ "${cutover_stage:-}" != "pending_port_commit_reboot" ]; then
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        run_port_transition_stage_one
        return
    fi

    detect_cutover_mode

    case "${cutover_mode:-needs_stage_one}" in
    strict_ready_for_finalize)
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        echo "A committed strict SSH/firewall state is already present. Converging the strict state before finalizing deferred admin cleanup."
        converge_strict_cutover_state || return 1
        finalize_deferred_admin_fallback || return 1
        ;;
    fully_hardened)
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        echo "A committed strict SSH/firewall state is already present. Reapplying the baseline without staged prompts."
        run_strict_baseline_reapply "no"
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
            "Reboot the host, verify a fresh login on the new SSH port, then rerun this script with --confirm-stage-advance yes to remove the old SSH port from the managed boot policy." \
            "validate_pending_port_transition_alignment" \
            "run_port_transition_stage_two"
        ;;
    pending_port_commit_reboot)
        handle_pending_stage \
            "A new-port-only SSH reboot transition" \
            "Reboot the host, verify a fresh login on the new SSH port again, then rerun this script with --confirm-stage-advance yes to finalize the port migration." \
            "validate_pending_port_transition_alignment" \
            "advance_pending_port_commit_stage"
        ;;
    *)
        echo "Stored cutover state is stale or incomplete. Clearing it and starting a fresh evaluation."
        clear_cutover_state
        run_without_cutover_state
        ;;
    esac
}

run_without_cutover_state() {
    detect_cutover_mode

    if ssh_port_transition_requested; then
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        run_port_transition_stage_one
        return
    fi

    case "${cutover_mode:-needs_stage_one}" in
    strict_ready_for_finalize)
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        run_strict_baseline_reapply "yes"
        return
        ;;
    fully_hardened)
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        run_strict_baseline_reapply "no"
        return
        ;;
    esac

    collect_user_input
    detect_cutover_mode

    if ssh_port_transition_requested; then
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        run_port_transition_stage_one
        return
    fi

    case "${cutover_mode:-needs_stage_one}" in
    strict_ready_for_finalize)
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        run_strict_baseline_reapply "yes"
        ;;
    fully_hardened)
        validate_cutover_state_alignment || return 1
        validate_saved_cutover_cli_consistency || return 1
        run_strict_baseline_reapply "no"
        ;;
    *)
        run_stage_one_after_input
        ;;
    esac
}

# Configure Suricata for IPS mode and include custom config
configure_suricata() {
    echo "Configuring Suricata for IPS mode with IPFW..."
    ssh_ports_csv=$(managed_ssh_ports_for_generated_state)
    suricata_yaml_ports=$(suricata_ssh_ports_value "$ssh_ports_csv")
    suricata_rule_ports=$(suricata_ssh_rule_ports_value "$ssh_ports_csv")
    managed_ssh_rule="alert tcp any any -> any $suricata_rule_ports (msg:\"Managed SSH connection on staged ports $suricata_rule_ports\"; sid:1000001; rev:2;)"
    suricata_rules_tmp=""

    if ! render_template_file "config/suricata-custom.yaml.tmpl" "$suricata_custom_conf_file" \
        "@NAT_INTERFACE@=$nat_if" \
        "@SURICATA_PORT@=$suricata_port"; then
        return 1
    fi

    if ! grep -qE '^[[:space:]]*SSH_PORTS:' "$suricata_conf_file"; then
        echo "Error: SSH_PORTS not found in $suricata_conf_file."
        return 1
    fi
    atomic_sed_replace "$suricata_conf_file" -E "s|^([[:space:]]*SSH_PORTS:[[:space:]]*).*$|\\1$suricata_yaml_ports|"

    # Append the custom configuration to the existing suricata.yaml using the `include` directive
    if ! grep -q "^include: $suricata_custom_conf_file" "$suricata_conf_file"; then
        echo "include: $suricata_custom_conf_file" >>"$suricata_conf_file"
        echo "Custom Suricata configuration included."
    else
        echo "Custom Suricata configuration is already included."
    fi

    [ -f "$suricata_rules_file" ] || : >"$suricata_rules_file"
    suricata_rules_tmp=$(make_secure_tmp "$(dirname "$suricata_rules_file")")
    awk -v managed_rule="$managed_ssh_rule" '
        /sid:1000001;/ {
            if (!replaced) {
                print managed_rule
                replaced = 1
            }
            next
        }
        { print }
        END {
            if (!replaced) {
                print managed_rule
            }
        }
    ' "$suricata_rules_file" >"$suricata_rules_tmp" || {
        rm -f "$suricata_rules_tmp"
        return 1
    }
    atomic_replace "$suricata_rules_file" "$suricata_rules_tmp"

    # Test the Suricata configuration
    if ! suricata -T -c "$suricata_conf_file"; then
        echo "Suricata configuration test failed. Please review the configuration."
        return 1
    fi

    # Enable Suricata at boot
    sysrc suricata_enable="YES"
    echo "Suricata configured to enable at next reboot on interface $nat_if."
}

converge_strict_cutover_state() {
    clear_immutable_flags
    restore_desired_mutable_baseline_settings
    prepare_ssh_user_access
    configure_google_auth
    configure_ssh_pam
    if ! apply_sshd_profile strict; then
        return 1
    fi
    if ! reload_sshd_safe; then
        return 1
    fi
    if ! admin_access_is_ready; then
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
    set_default_if_empty "allow_multicast" "no"
    set_default_if_empty "allow_multicast_legacy" "no"

    multicast_legacy_value=0
    if [ "$allow_multicast" = "yes" ] && [ "$allow_multicast_legacy" = "yes" ]; then
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
            echo "Warning: sysctl key '${key}' does not exist on this system."
        fi
    done

    echo "System kernel hardened with secure sysctl settings."
}

# Harden loader.conf with additional kernel security modules
harden_loader_conf() {
    echo "Configuring loader.conf for additional kernel security and microcode..."

    # Define the loader.conf values to be set for security modules
    settings=$(emit_yes_settings "mac_bsdextended_load mac_portacl_load mac_seeotheruids_load")

    # Add CPU microcode settings to loader.conf if detected
    if [ "$cpu_type" != "unknown" ]; then
        microcode_settings=$(emit_yes_settings "cpuctl_load cpu_microcode_load")
        if [ "$cpu_type" = "intel" ]; then
            microcode_settings=$(append_setting_line "$microcode_settings" "$(emit_yes_settings "coretemp_load")")
            microcode_settings=$(append_setting_line "$microcode_settings" 'cpu_microcode_name="/boot/firmware/intel-ucode.bin"')
        elif [ "$cpu_type" = "amd" ]; then
            microcode_settings=$(append_setting_line "$microcode_settings" "$(emit_yes_settings "amdtemp_load")")
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
        if ! apply_settings_merge_template "$loader_conf_file" "awk/kv_settings_merge.awk" "$loader_updates" -v append_missing="yes"; then
            return 1
        fi
    fi

    echo "loader.conf hardened with additional kernel security modules and microcode settings."
}

configure_firewall_boot() {
    echo "Configuring firewall boot handling..."
    firewall_loader_settings=$(build_firewall_loader_settings)

    if ! apply_settings_merge_template "$loader_conf_file" "awk/kv_settings_merge.awk" "$firewall_loader_settings" -v append_missing="yes"; then
        return 1
    fi

    if [ "$install_suricata" = "yes" ]; then
        configure_suricata || return 1
    fi

    configure_ipfw || return 1
    echo "Firewall boot configuration committed. Future reboots will use the managed firewall configuration."
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
    ipfw_rules_tmp=""

    settings=$(emit_kv_settings "$managed_ipfw_emit_vars")

    ipfw_rules_tmp=$(make_secure_tmp "$(dirname "$managed_ipfw_rules_file")")
    if ! cp "$source_ipfw_rules_file" "$ipfw_rules_tmp"; then
        rm -f "$ipfw_rules_tmp"
        return 1
    fi

    if ! apply_settings_merge_template "$ipfw_rules_tmp" "awk/kv_settings_merge.awk" "$settings"; then
        rm -f "$ipfw_rules_tmp"
        return 1
    fi

    chmod 640 "$ipfw_rules_tmp"
    atomic_replace "$managed_ipfw_rules_file" "$ipfw_rules_tmp"

    # Set the firewall to load on boot and specify the rules file
    sysrc firewall_enable="YES"
    sysrc firewall_script="$managed_ipfw_rules_file"
    sysrc firewall_logging="YES"

    echo "IPFW firewall with Suricata and Dummynet configured, rules saved to $managed_ipfw_rules_file, and enabled at boot."
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
