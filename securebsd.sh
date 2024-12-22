#!/bin/sh

# Exit on errors and undefined variables
set -eu

# Define file variables for system hardening (chflags schg)
service_scheduler_files="/var/cron/allow /var/at/at.allow"
full_lockdown_files="$service_scheduler_files /etc/rc.firewall /etc/ipfw.rules /usr/local/etc/sudoers /etc/sysctl.conf /boot/loader.conf /boot/loader.rc /etc/fstab /etc/login.conf /etc/login.access /etc/newsyslog.conf /etc/ssh/sshd_config /etc/pam.d/sshd /etc/hosts /etc/hosts.allow /etc/ttys"

# Combine all sensitive files into one list for restricting "others" permissions (chmod o=)
password_related_files="/etc/master.passwd"
service_related_files="/etc/rc.conf /etc/crontab /usr/local/etc/anacrontab"
audit_log_files="/var/log /var/audit"
other_sensitive_files="/etc/ftpusers"
sensitive_files="$service_scheduler_files $password_related_files $service_related_files $audit_log_files $other_sensitive_files"

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# Validate the existence of a user
validate_user() {
  if ! id "$1" >/dev/null 2>&1; then
    echo "Error: User '$1' does not exist. Please provide a valid username."
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
  if [ "$1" != "disable" ]; then
    if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -le 0 ]; then
      echo "Error: Invalid password expiration '$1'. Must be a positive integer or 'disable'."
      return 1
    fi
  fi
}

# Clear immutable flags on system files for updates
clear_immutable_flags() {
  echo "Clearing immutable flags on system files for updates..."
  for file in $full_lockdown_files $sensitive_files; do
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

  # SSH allowed user input
  echo "Enter a valid username for SSH access and sudo privileges."
  printf "Enter the username to allow for SSH access: "
  read -r allowed_user
  validate_user "$allowed_user"

  # SSH port input
  echo "Choose a custom SSH port (not the default 22)."
  printf "Enter the SSH port to use (default: 2222): "
  read -r admin_ssh_port
  admin_ssh_port="${admin_ssh_port:-2222}"
  validate_port "$admin_ssh_port"

  # Admin IPs input
  echo "Enter a comma-separated list of IPs allowed to SSH into the server, or type 'any' to allow all IPs (not recommended)."
  printf "Enter the admin IPs (comma-separated) for SSH access: "
  read -r admin_ips

  # External network interface input (for IPFW and optionally Suricata)
  printf "Enter the external network interface for IPFW (and Suricata, if installed, e.g., em0, re0): "
  read -r external_interface
  validate_interface "$external_interface"

  # Suricata installation choice
  echo "Do you want to install and configure Suricata (yes/no)?"
  printf "Enter your choice (default: yes): "
  read -r install_suricata
  install_suricata="${install_suricata:-yes}"
  if [ "$install_suricata" != "no" ]; then
    if [ "$install_suricata" != "yes" ]; then
      echo "Invalid input. Please enter 'yes' or 'no'."
      return 1
    fi
  else
    suricata_port="disable"
  fi

  # Password expiration input
  echo "Set the password expiration period in days. Type 'disable' to disable expiration (not recommended)."
  printf "Enter the password expiration period in days (default: 120): "
  read -r password_expiration
  password_expiration="${password_expiration:-120}"
  validate_password_expiration "$password_expiration"
  if [ "$password_expiration" = "disable" ]; then
    password_expiration="no password expiration"
  else
    password_expiration="${password_expiration}d"
  fi
}

# Backup critical system configuration files
backup_configs() {
  echo "Creating backups of critical configuration files..."
  backup_dir="/etc/backup_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$backup_dir"
  for conf_file in /etc/rc.conf /etc/sysctl.conf /etc/login.conf /boot/loader.conf /etc/ssh/sshd_config /etc/pam.d/sshd; do
    cp "$conf_file" "$backup_dir"
  done
  echo "Backup completed. Files saved in $backup_dir."
}

# Update FreeBSD and install necessary packages (sudo, fail2ban, Suricata, Google Authenticator)
update_and_install_packages() {
  echo "Updating FreeBSD and installing necessary packages (sudo, fail2ban, Google Authenticator)..."
  freebsd-update fetch install
  pkg update
  pkg upgrade -y
  pkg install -y sudo py311-fail2ban anacron pam_google_authenticator

  # Install Suricata if the user opted in
  if [ "$install_suricata" = "yes" ]; then
    echo "Installing Suricata..."
    pkg install -y suricata
    suricata-update
    echo "Suricata installed and updated."
  else
    echo "Skipping Suricata installation."
  fi
}

# Configure SSH security settings
configure_ssh() {
  echo "Configuring SSH security with public key and Google Authenticator authentication..."
  sshd_config="/etc/ssh/sshd_config"

  # Apply SSH configuration changes
  sed -i '' -E \
    -e "s/^#?PermitRootLogin .*/PermitRootLogin no/" \
    -e "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" \
    -e "s/^#?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication yes/" \
    -e "s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/" \
    -e "s/^#?UsePAM .*/UsePAM yes/" \
    -e "s/^#?AuthenticationMethods .*/AuthenticationMethods publickey,keyboard-interactive/" \
    -e "s/^#?AllowUsers .*/AllowUsers $allowed_user/" \
    -e "s/^#?Port .*/Port $admin_ssh_port/" \
    -e "s/^#?ClientAliveInterval .*/ClientAliveInterval 60/" \
    -e "s/^#?ClientAliveCountMax .*/ClientAliveCountMax 10/" \
    "$sshd_config"

  # Add necessary directives if not present
  if ! grep -q "^AuthenticationMethods publickey,keyboard-interactive" "$sshd_config"; then
    echo "AuthenticationMethods publickey,keyboard-interactive" | tee -a "$sshd_config" >/dev/null
  fi
  if ! grep -q "^AllowUsers $allowed_user" "$sshd_config"; then
    echo "AllowUsers $allowed_user" | tee -a "$sshd_config" >/dev/null
  fi
  if ! grep -q "^ClientAliveInterval 60" "$sshd_config"; then
    echo "ClientAliveInterval 60" | tee -a "$sshd_config" >/dev/null
  fi
  if ! grep -q "^ClientAliveCountMax 10" "$sshd_config"; then
    echo "ClientAliveCountMax 10" | tee -a "$sshd_config" >/dev/null
  fi

  echo "SSH configured to require public key and Google Authenticator authentication and disconnect inactive sessions."

  # Configure SSH keys for the allowed user
  ssh_key="/home/$allowed_user/.ssh/id_ed25519"

  # Ensure .ssh directory exists with correct permissions
  if [ ! -d "/home/$allowed_user/.ssh" ]; then
    echo "Creating .ssh directory for $allowed_user..."
    mkdir -p /home/"$allowed_user"/.ssh
  fi
  chmod 700 /home/"$allowed_user"/.ssh
  chown "$allowed_user:$allowed_user" /home/"$allowed_user"/.ssh

  # Check if SSH key already exists
  if [ ! -f "$ssh_key" ]; then
    echo "No SSH key found for $allowed_user. Generating a new key pair..."
    su - "$allowed_user" -c "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N '' -q"
  else
    echo "SSH key already exists for $allowed_user: $ssh_key"
  fi

  # Set up authorized_keys
  authorized_keys="/home/$allowed_user/.ssh/authorized_keys"
  if [ ! -f "$authorized_keys" ]; then
    echo "Creating authorized_keys for $allowed_user..."
    tee "$authorized_keys" <"$ssh_key.pub" >/dev/null
  else
    echo "authorized_keys already exists for $allowed_user. Appending key if not present..."
    grep -q -F "$(cat "$ssh_key.pub")" "$authorized_keys" || tee -a "$authorized_keys" <"$ssh_key.pub" >/dev/null
  fi
  chmod 600 "$authorized_keys"
  chown "$allowed_user:$allowed_user" "$authorized_keys"

  echo "Public key authentication enabled for $allowed_user."

  # Provide clear instructions for private key management
  echo ""
  echo "IMPORTANT: You must securely copy the private key to your local machine before rebooting."
  echo "To securely transfer the private key, run the following command on your local machine:"
  echo ""
  echo "scp <username>@<remote_host>:/home/$allowed_user/.ssh/id_ed25519 ~/.ssh/"
  echo ""
  echo "After copying the private key, delete it from the remote server for security:"
  echo "ssh <username>@<remote_host> 'rm /home/$allowed_user/.ssh/id_ed25519'"
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
  ga_pam_line="auth required pam_google_authenticator.so"

  # Check if pam_google_authenticator.so is already present
  if grep -q "^$ga_pam_line" "$pam_sshd_config"; then
    echo "Google Authenticator is already enabled in PAM SSH configuration."
    return
  fi

  # Replace pam_unix.so or insert pam_google_authenticator.so at the correct position
  awk -v ga_line="$ga_pam_line" '
    BEGIN {
      inserted = 0;
    }
    {
      # Remove leading whitespace for easier processing
      line = $0; gsub(/^[ \t]+/, "", line);
    }
    # Detect auth section lines
    /^auth/ {
      if (line ~ /pam_unix\.so/ && !inserted) {
        # Replace pam_unix.so with pam_google_authenticator.so
        print ga_line;
        inserted = 1;
        next;
      }
      if (!inserted && line ~ /(sufficient|requisite|binding)/) {
        # Insert Google Authenticator before terminal rules
        print ga_line;
        inserted = 1;
      }
    }
    # Detect transitions to other sections and insert before them
    /^(account|password|session)/ && !inserted {
      print ga_line;
      inserted = 1;
    }
    # Print the current line
    { print }
    # Append at the end if not yet inserted
    END {
      if (!inserted) print ga_line;
    }
  ' "$pam_sshd_config" | tee "$pam_sshd_config.tmp" >/dev/null && mv "$pam_sshd_config.tmp" "$pam_sshd_config"

  echo "Google Authenticator added to the auth section of PAM SSH configuration."
}

# Configure Google Authenticator TOTP for the allowed user
configure_google_auth() {
  echo "Configuring Google Authenticator TOTP for the allowed user..."

  # Define the configuration file path
  ga_config="/home/$allowed_user/.google_authenticator"

  # Run google-authenticator as the allowed user with secure options
  su - "$allowed_user" -c "google-authenticator -t -d -r 1 -R 30 -W -s '$ga_config'"

  # Secure permissions on the .google_authenticator file
  chmod 600 "$ga_config"
  chown "$allowed_user:$allowed_user" "$ga_config"

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

# Configure sudo for the allowed user
configure_sudo() {
  echo "Configuring sudo for the allowed user..."
  if ! groups "$allowed_user" | grep -q wheel; then
    pw groupmod wheel -m "$allowed_user"
  fi
  if [ ! -f /usr/local/etc/sudoers.d/wheel ]; then
    echo '%wheel ALL=(ALL) ALL' | tee /usr/local/etc/sudoers.d/wheel >/dev/null
  fi
  echo "Sudo configured for the allowed user in the wheel group."
}

# Configure Suricata for IPS mode and include custom config
configure_suricata() {
  echo "Configuring Suricata for IPS mode with IPFW..."

  # Define the configuration file paths as variables
  suricata_conf="/usr/local/etc/suricata/suricata.yaml"
  suricata_custom_conf="/usr/local/etc/suricata/suricata-custom.yaml"
  suricata_rules="/var/lib/suricata/rules/custom.rules"
  suricata_port="8000" # Define the divert port for IPFW to Suricata

  # Create or update the Suricata custom configuration file
  cat <<EOF | tee "$suricata_custom_conf" >/dev/null
%YAML 1.1
---
# Configure Suricata for inline packet processing via IPFW (IPS mode)
ipfw:
  - interface: $external_interface
    divert-port: $suricata_port
    threads: auto
    checksum-checks: no

# Set Suricata to multi-threaded mode (workers) for efficient traffic processing
runmode: workers

# Enable inline stream handling for IPS mode
stream:
  inline: yes

# Define the priority of actions (pass, drop, reject, alert) for Suricata rules in IPS mode
action-order:
  - pass
  - drop
  - reject
  - alert

# Configure Suricata to log events (including dropped packets) to eve.json
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - drop:
            enabled: yes
EOF

  # Update SSH port in suricata.yaml using sed to match single values or lists
  sed -E -i '' "s/(SSH_PORTS: )([0-9]+|\[[0-9, ]+\])/\1$admin_ssh_port/" "$suricata_conf"

  # Append the custom configuration to the existing suricata.yaml using the `include` directive
  if ! grep -q "include: $suricata_custom_conf" "$suricata_conf"; then
    echo "include: $suricata_custom_conf" | tee -a "$suricata_conf" >/dev/null
    echo "Custom Suricata configuration included."
  else
    echo "Custom Suricata configuration is already included."
  fi

  # Add custom Suricata rule for SSH port if not present
  if ! grep -q "port $admin_ssh_port" "$suricata_rules"; then
    echo "alert tcp any any -> any $admin_ssh_port (msg:\"SSH connection on custom port $admin_ssh_port\"; sid:1000001; rev:1;)" | tee -a "$suricata_rules" >/dev/null
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
  echo "Suricata configured to enable at next reboot on interface $external_interface."
}

# Configure Fail2Ban to protect SSH
configure_fail2ban() {
  echo "Configuring Fail2Ban to protect SSH..."
  cat <<EOF | tee /usr/local/etc/fail2ban/jail.local >/dev/null
[sshd]
enabled = true
port = $admin_ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600  # 1 hour ban
findtime = 600  # 10 minutes window to track failed attempts
EOF
  sysrc fail2ban_enable="YES"
  echo "Fail2Ban configured to enable at next reboot."
}

# Harden system kernel with sysctl settings
harden_sysctl() {
  echo "Applying sysctl hardening..."
  sysctl_conf="/etc/sysctl.conf"

  # Define the sysctl values to be set and loop through them
  for setting in \
    "net.inet.icmp.icmplim=50" \
    "net.inet.tcp.blackhole=2" \
    "net.inet.udp.blackhole=1" \
    "net.inet.tcp.syncookies=1" \
    "net.inet.tcp.drop_synfin=1" \
    "net.inet.ip.dummynet.io_fast=1" \
    "kern.coredump=0" \
    "kern.randompid=1" \
    "kern.sugid_coredump=0" \
    "security.bsd.see_other_uids=0" \
    "security.bsd.see_other_gids=0" \
    "security.bsd.see_jail_proc=0" \
    "security.bsd.unprivileged_read_msgbuf=0" \
    "security.bsd.unprivileged_proc_debug=0"; do
    key="${setting%%=*}"
    if grep -q "^${key}" "$sysctl_conf"; then
      sed -i '' "s|^${key}.*|${setting}|" "$sysctl_conf"
    else
      echo "$setting" | tee -a "$sysctl_conf" >/dev/null
    fi
  done

  echo "System kernel hardened with secure sysctl settings."
}

# Harden loader.conf with additional kernel security modules
harden_loader_conf() {
  echo "Configuring loader.conf for additional kernel security..."
  loader_conf="/boot/loader.conf"

  # Define the loader.conf values to be set and loop through them
  for setting in \
    'mac_bsdextended_load="YES"' \
    'mac_partition_load="YES"' \
    'mac_portacl_load="YES"' \
    'mac_seeotheruids_load="YES"' \
    'ipfw_load="YES"' \
    'ipdivert_load="YES"' \
    'dummynet_load="YES"'; do
    key="${setting%%=*}"
    if grep -q "^${key}" "$loader_conf"; then
      sed -i '' "s|^${key}.*|${setting}|" "$loader_conf"
    else
      echo "$setting" | tee -a "$loader_conf" >/dev/null
    fi
  done

  echo "loader.conf hardened with additional kernel security modules."
}

# Set securelevel in rc.conf
configure_securelevel() {
  echo "Configuring securelevel in rc.conf..."
  sysrc kern_securelevel_enable="YES"
  sysrc kern_securelevel="1"
  echo "Securelevel configured in rc.conf."
}

# Set Blowfish password hashing, enforce password expiration, and configure umask
configure_password_and_umask() {
  echo "Configuring password security with Blowfish encryption and setting a secure umask..."

  # Change password hashing to Blowfish
  sed -i '' -E 's/(:passwd_format=)[^:]+(:)/\1blf\2/' /etc/login.conf

  # Check if the 'default' block exists
  if ! grep -q '^default:' /etc/login.conf; then
    echo "Error: 'default:' block not found in /etc/login.conf. Cannot proceed."
    return 1
  fi

  # Configure password expiration if not disabled
  if [ "$password_expiration" != "no password expiration" ]; then
    # Extract the full 'default' block and handle multi-line continuation
    if awk '/^default:/ { flag=1 } flag { print; if (!/\\$/) flag=0 }' /etc/login.conf | grep -q 'passwordtime='; then
      # Update the existing passwordtime value inside the 'default' block
      awk -v new_passwordtime="passwordtime=${password_expiration}:" \
        '/^default:/ { flag=1 }
         flag && /passwordtime=/ { sub(/passwordtime=[0-9]+d:/, new_passwordtime); flag=0 }
         { print; if (!/\\$/) flag=0 }' /etc/login.conf | tee /etc/login.conf.tmp >/dev/null && mv /etc/login.conf.tmp /etc/login.conf
    else
      # Append passwordtime inside the default block
      awk -v new_passwordtime="passwordtime=${password_expiration}:\\" \
        '/^default:/ { print; print "\t:" new_passwordtime; next }1' /etc/login.conf | tee /etc/login.conf.tmp >/dev/null && mv /etc/login.conf.tmp /etc/login.conf
    fi
  fi

  # Set secure umask to 027
  sed -i '' -E 's/(:umask=)022(:)/\1027\2/' /etc/login.conf

  # Rebuild login capabilities database to apply the changes
  if ! cap_mkdb /etc/login.conf; then
    echo "Error: Failed to rebuild the login.conf database."
    return 1
  fi

  # Inform the user about the password reset
  echo "Resetting the password for $allowed_user and root to ensure Blowfish encryption is applied."

  # Reset the password for the allowed user to apply Blowfish hashing
  if ! passwd "$allowed_user"; then
    echo "Error: Failed to reset password for $allowed_user."
    return 1
  fi

  # Reset the password for the root user to apply Blowfish hashing
  if ! passwd; then
    echo "Error: Failed to reset password for root."
    return 1
  fi

  echo "Password security configured with umask 027 and Blowfish encryption for $allowed_user."
}

# Configure IPFW firewall with updated rules
configure_ipfw() {
  echo "Configuring IPFW firewall with Suricata and Dummynet..."

  # Create /etc/ipfw.rules with the necessary firewall rules
  cat <<EOF | tee /etc/ipfw.rules >/dev/null
#!/bin/sh

# Define the firewall command
fwcmd="/sbin/ipfw"

# Define external interface, internal interface, and Suricata divert port
ext_if="$external_interface"  # Adjust as needed for your external interface
int_if="$external_interface"  # Adjust to your internal network interface
divert_port="$suricata_port"  # Suricata divert port
ssh_ips="$admin_ips"          # List of allowed SSH source IPs
ssh_port="$admin_ssh_port"    # SSH port to allow

# Check if IPv6 is available by detecting any IPv6 addresses
ipv6_available=\$(ifconfig | grep -q "inet6" && echo 1 || echo 0)

# Flush existing rules
\${fwcmd} -q -f flush

#################################
# Loopback and IPv6 Traffic
#################################
# Allow all traffic on the loopback interface (lo0)
\${fwcmd} add 100 allow ip from any to any via lo0

# Deny traffic to and from the IPv4 loopback network (127.0.0.0/8)
\${fwcmd} add 200 deny ip from any to 127.0.0.0/8
\${fwcmd} add 300 deny ip from 127.0.0.0/8 to any

# IPv6 loopback and network functionality rules (if IPv6 is available)
if [ \$ipv6_available -eq 1 ]; then
    # Deny traffic to and from the IPv6 loopback address (::1)
    \${fwcmd} add 400 deny ip from any to ::1
    \${fwcmd} add 500 deny ip from ::1 to any

    # Deny routing header type 0 (RH0) to prevent amplification and redirection attacks (RFC5095)
    \${fwcmd} add 600 deny log ip6 from any to any ext6hdr rthdr0

    # Deny fragmented ICMPv6 Neighbor Discovery Protocol (NDP) packets to prevent DoS attacks (RFC6980)
    \${fwcmd} add 700 deny log icmp6 from any to any ext6hdr frag icmp6type 130,131,132,133,134,135,136,143

    # Allow IPv6 Duplicate Address Detection (DAD) packets
    \${fwcmd} add 800 allow icmp6 from :: to ff02::/16

    # Allow ICMPv6 Router Solicitation (RS), Router Advertisement (RA), Neighbor Solicitation (NS), and Neighbor Advertisement (NA) for link-local traffic
    \${fwcmd} add 900 allow icmp6 from fe80::/10 to fe80::/10
    \${fwcmd} add 1000 allow icmp6 from fe80::/10 to ff02::/16

    # Allow ICMPv6 Neighbor Solicitation (NS) and Neighbor Advertisement (NA) for address resolution (unicast, link-local, and multicast)
    \${fwcmd} add 1100 allow icmp6 from any to any icmp6type 135,136
fi

#################################
# Reassemble Fragmented Packets Early
#################################
# Reassemble fragmented packets before further processing
\${fwcmd} add 1200 reass ip from any to any in

#################################
# Anti-Spoofing, Recon Prevention, and Fail2Ban Protection
#################################
# Drop traffic from the Fail2Ban table
\${fwcmd} add 1300 deny log ip from 'table(fail2ban)' to any

# Block packets with IP options to prevent IP spoofing and source routing attacks
\${fwcmd} add 1400 deny log ip from any to any ipoptions ssrr
\${fwcmd} add 1410 deny log ip from any to any ipoptions lsrr
\${fwcmd} add 1420 deny log ip from any to any ipoptions rr
\${fwcmd} add 1430 deny log ip from any to any ipoptions ts

# Anti-spoofing: Deny traffic with invalid source addresses (not verifiable via reverse path)
\${fwcmd} add 1500 deny log ip from any to any not verrevpath in

#################################
# ICMP and ICMPv6 Rules for PMTUD and Network Functionality
#################################
# Allow ICMPv4 Destination Unreachable and Time Exceeded
\${fwcmd} add 1600 allow icmp from any to any icmptypes 3,11 in
\${fwcmd} add 1700 allow icmp from any to any out

# Allow ICMPv6 Destination Unreachable, Packet Too Big, Time Exceeded, and RA
if [ \$ipv6_available -eq 1 ]; then
    \${fwcmd} add 1800 allow icmp6 from any to any icmp6type 1,2,3,133,134 in
    \${fwcmd} add 1900 allow icmp6 from any to any out
fi

#################################
# Flood Protection and Traffic Shaping
#################################
# Dummynet pipe to limit ICMPv4/ICMPv6 bandwidth
\${fwcmd} pipe 1 config bw 100Kbit/s

# Limit ICMPv4 echo requests and replies (ping flood protection)
\${fwcmd} add 2000 pipe 1 icmp from any to any icmptypes 8,0 in

# IPv6 ICMPv6 echo requests and replies (ping flood protection)
if [ \$ipv6_available -eq 1 ]; then
    \${fwcmd} add 2100 pipe 1 icmp6 from any to any icmp6type 128,129 in
fi

#################################
# Suricata Traffic Diversion (If Enabled)
#################################
if [ "\$divert_port" != "disable" ]; then
    # Divert all traffic to Suricata for inline IPS processing
    \${fwcmd} add 2200 divert \$divert_port ip from any to any
fi

#################################
# Stateful Traffic Handling
#################################
# Check the state of all connections to allow established connections
\${fwcmd} add 2300 check-state

#################################
# Inbound Traffic (User-Defined Services)
#################################
# Allow new SSH connections from allowed source IPs to the firewall
\${fwcmd} add 2400 allow tcp from \$ssh_ips to me \$ssh_port setup in limit dst-addr 2

# Allow HTTP/HTTPS connections to the firewall, with source IP limit for DoS mitigation
\${fwcmd} add 2500 allow tcp from any to me 80,443 setup in limit src-addr 100

# IPv6 SSH and HTTP/HTTPS rules (if IPv6 is available)
if [ \$ipv6_available -eq 1 ]; then
    \${fwcmd} add 2600 allow tcp from \$ssh_ips to me6 \$ssh_port setup in limit dst-addr 2
    \${fwcmd} add 2700 allow tcp from any to me6 80,443 setup in limit src-addr 100
fi

# Allow DHCPv4 for WAN and LAN
\${fwcmd} add 2800 allow udp from any 67 to me 68 in recv \$ext_if keep-state
\${fwcmd} add 2900 allow udp from any 67 to any 68 in recv \$int_if keep-state

# Allow DHCPv6 for WAN and LAN (if IPv6 is available)
if [ \$ipv6_available -eq 1 ]; then
    \${fwcmd} add 3000 allow udp from any 547 to me6 546 in recv \$ext_if keep-state
    \${fwcmd} add 3100 allow udp from any 547 to any 546 in recv \$int_if keep-state
fi

#################################
# Outbound Traffic
#################################
# Allow all outbound traffic, with stateful inspection
\${fwcmd} add 3200 allow ip from any to any out keep-state

#################################
# Final Rule: Deny all other traffic
#################################
# Deny any traffic that hasn't been explicitly allowed
\${fwcmd} add 65534 deny log ip from any to any
EOF

  # Set the firewall to load on boot and specify the rules file
  sysrc firewall_enable="YES"
  sysrc firewall_script="/etc/ipfw.rules"
  sysrc firewall_type="custom" # Indicate that this is a custom firewall
  sysrc firewall_logging="YES" # Enable firewall logging

  echo "IPFW firewall with Suricata and Dummynet configured, rules saved to /etc/ipfw.rules, and enabled at boot."
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
  echo "Setting up automatic updates via cron..."
  if [ "$install_suricata" = "yes" ] && ! grep -q "suricata-update" /etc/crontab; then
    echo "0 2 * * 0 root suricata-update" | tee -a /etc/crontab >/dev/null
  fi
  if ! grep -q "freebsd-update cron" /etc/crontab; then
    echo "0 3 * * 0 root PAGER=cat freebsd-update cron" | tee -a /etc/crontab >/dev/null
  fi
  if ! grep -q "pkg update" /etc/crontab; then
    echo "0 4 * * 0 root pkg update" | tee -a /etc/crontab >/dev/null
  fi
  echo "Cron jobs for system and Suricata updates configured."
}

# Lock down sensitive system files
lock_down_system() {
  echo "Locking down critical system files..."
  for file in $service_scheduler_files; do
    echo "root" | tee "$file" >/dev/null
  done
  for file in $sensitive_files; do
    chmod o= "$file"
  done
  reapply_immutable_flags
  echo "System files locked down and cron/at restricted to root only."
}

# Main function to run all steps
main() {
  collect_user_input
  clear_immutable_flags
  backup_configs
  update_and_install_packages
  configure_password_and_umask
  harden_sysctl
  harden_loader_conf
  configure_ssh
  configure_ssh_pam
  configure_google_auth
  configure_sudo
  configure_fail2ban
  if [ "$install_suricata" = "yes" ]; then
    configure_suricata
  fi
  configure_ipfw
  secure_syslog_and_tmp
  configure_cron_updates
  configure_securelevel
  lock_down_system
  echo "Security hardening complete. Please reboot to apply all changes."
}

# Run the main function
main
