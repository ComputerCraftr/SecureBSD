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
other_sensitive_files="/etc/ftpusers"
sensitive_files="$service_scheduler_files $password_related_files $service_related_files $audit_log_files $other_sensitive_files"

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

  # SSH allowed user input
  echo "Enter a valid username for SSH access and sudo privileges."
  printf "Enter the username to allow for SSH access: "
  read -r allowed_user
  if ! validate_user "$allowed_user"; then
    echo "Please provide a valid username."
    return 1
  fi

  # SSH port input
  echo "Choose a custom SSH port (not the default 22)."
  printf "Enter the SSH port to use (default: 2222): "
  read -r admin_ssh_port
  admin_ssh_port="${admin_ssh_port:-2222}"
  validate_port "$admin_ssh_port"

  # Admin IPv4 input
  echo "Enter a comma-separated list of IPv4 addresses allowed to SSH into the server, or type 'any' to allow all IPv4 access (not recommended)."
  printf "Enter the admin IPv4 addresses (comma-separated) for SSH access: "
  read -r admin_ipv4
  if ! echo "$admin_ipv4" | grep -qE '^[0-9.,]+$|^any$'; then
    echo "Invalid input. Please enter comma-separated IPv4 addresses or 'any'."
    return 1
  fi

  # Admin IPv6 input
  echo "Enter a comma-separated list of IPv6 addresses allowed to SSH into the server, or type 'any' to allow all IPv6 access (not recommended)."
  printf "Enter the admin IPv6 addresses (comma-separated) for SSH access: "
  read -r admin_ipv6
  if ! echo "$admin_ipv6" | grep -qE '^[a-fA-F0-9:.,]+$|^any$'; then
    echo "Invalid input. Please enter comma-separated IPv6 addresses or 'any'."
    return 1
  fi

  # External network interface input (for IPFW and optionally Suricata)
  echo "Set the external network interface for IPFW (and Suricata, if installed). Type 'none' if not applicable (default: none)."
  printf "Enter the external network interface (e.g., em0, re0): "
  read -r external_interface
  external_interface="${external_interface:-none}"
  if [ "$external_interface" != "none" ]; then
    validate_interface "$external_interface"
  else
    install_suricata="no"
  fi

  # VPN tunnel network interface input (for IPFW)
  echo "Set the VPN tunnel network interface for IPFW. Type 'none' if not using a VPN (default: none)."
  printf "Enter the VPN tunnel network interface (e.g., tun0): "
  read -r tunnel_interface
  tunnel_interface="${tunnel_interface:-none}"
  if [ "$tunnel_interface" != "none" ]; then
    validate_interface "$tunnel_interface"
  fi

  # Internal network interface input (for IPFW filtering bridge)
  echo "Set the internal network interface for IPFW. Type 'none' if not using a gateway/bridge (default: none)."
  printf "Enter the internal network interface (e.g., bridge0): "
  read -r internal_interface
  internal_interface="${internal_interface:-none}"
  if [ "$internal_interface" != "none" ]; then
    validate_interface "$internal_interface"
  fi

  echo "Do you want to install security auditing tools? (yes/no)"
  printf "Enter your choice (default: yes): "
  read -r install_auditing_tools
  install_auditing_tools="${install_auditing_tools:-yes}"

  echo "Would you like to install CPU microcode for your processor to enhance security? (yes/no)"
  printf "Enter your choice (default: yes): "
  read -r install_microcode
  install_microcode="${install_microcode:-yes}"
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
  #echo "Do you want to install and configure Suricata? (yes/no)"
  #printf "Enter your choice (default: yes): "
  #read -r install_suricata
  install_suricata="no"
  install_suricata="${install_suricata:-yes}"
  if [ "$install_suricata" != "no" ]; then
    if [ "$install_suricata" != "yes" ]; then
      echo "Invalid input. Please enter 'yes' or 'no'."
      return 1
    fi
    suricata_port="${suricata_port:-8000}" # Define the divert port for IPFW to Suricata
    validate_port "$suricata_port"
  else
    suricata_port="none"
  fi

  # Password expiration input
  echo "Set the password expiration period in days. Type 'none' to disable expiration (not recommended)."
  printf "Enter the password expiration period in days (default: 120): "
  read -r password_expiration
  password_expiration="${password_expiration:-120}"
  if [ "$password_expiration" != "none" ]; then
    validate_password_expiration "$password_expiration"
    password_expiration="${password_expiration}d"
  fi
}

# Backup critical system configuration files
backup_configs() {
  echo "Creating backups of critical configuration files..."
  backup_dir="/etc/backup_$(date +%Y%m%d_%H%M%S)"
  backup_files="/etc/rc.conf /etc/sysctl.conf /etc/login.conf /boot/loader.conf /etc/ssh/sshd_config /etc/pam.d/sshd"
  mkdir -p "$backup_dir"
  chmod 750 "$backup_dir"
  for conf_file in $backup_files; do
    cp "$conf_file" "$backup_dir"
  done
  chflags -R schg "$backup_dir"
  echo "Backup completed and made immutable. Files saved in $backup_dir."
}

# Update FreeBSD and install necessary packages (sudo, fail2ban, Suricata, Google Authenticator)
update_and_install_packages() {
  echo "Updating FreeBSD and installing necessary packages (sudo, fail2ban, Google Authenticator)..."
  # FreeBSD update is not supported on all architectures
  freebsd_update_supported="no"
  if freebsd-update fetch install; then
    freebsd_update_supported="yes"
  fi
  pkg upgrade -y
  pkg install -y sudo anacron pam_google_authenticator py311-fail2ban

  # Install security auditing tools if the user opted in
  if [ "$install_auditing_tools" = "yes" ]; then
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
  settings="
PermitRootLogin no
MaxAuthTries 3
PasswordAuthentication no
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
UsePAM yes
UseDNS no
AuthenticationMethods publickey,keyboard-interactive
AllowUsers $allowed_user
Port $admin_ssh_port
ClientAliveInterval 60
ClientAliveCountMax 1
"

  # Loop through each setting safely with line-by-line reading
  echo "$settings" | while IFS= read -r setting; do
    key=$(echo "$setting" | cut -d' ' -f1)
    value=$(echo "$setting" | cut -d' ' -f2-)

    # Check if the setting exists (including commented ones)
    if grep -q "^#\?${key} " "$sshd_config"; then
      if [ "$key" = "AllowUsers" ]; then
        # Ensure we only add user if not already in the list
        if ! grep -qE "^${key}\b.*\b${value}\b" "$sshd_config"; then
          sed -i '' -E "s|^#?${key} (.*)|${setting} \1|" "$sshd_config"
        fi
      else
        # Replace existing setting
        sed -i '' -E "s|^#?${key} .*|${setting}|" "$sshd_config"
      fi
    else
      # Add the setting if it doesn't exist
      echo "$setting" | tee -a "$sshd_config" >/dev/null
    fi
  done

  echo "SSH configured to require public key and Google Authenticator authentication and disconnect inactive sessions."

  # Configure SSH keys for the allowed user
  ssh_dir="/home/$allowed_user/.ssh"
  ssh_key="$ssh_dir/id_ed25519"
  ssh_pub_key="${ssh_key}.pub"
  authorized_keys="$ssh_dir/authorized_keys"

  # Ensure .ssh directory exists with correct permissions
  if [ ! -d "$ssh_dir" ]; then
    echo "Creating .ssh directory for $allowed_user..."
    mkdir -p "$ssh_dir"
  fi

  # Always enforce correct permissions on .ssh directory
  chmod 700 "$ssh_dir"
  chown "$allowed_user:$allowed_user" "$ssh_dir"

  # Check for any existing SSH key pairs in the .ssh directory
  if [ -f "$ssh_key" ] || [ -f "$ssh_pub_key" ]; then
    echo "SSH key pair already exists for $allowed_user."
  else
    echo "No SSH key found for $allowed_user. Generating a new key pair..."
    su - "$allowed_user" -c "ssh-keygen -t ed25519 -f $ssh_key -N '' -q"
  fi

  # Set up authorized_keys
  if [ ! -f "$authorized_keys" ]; then
    echo "Creating authorized_keys for $allowed_user..."
    if [ -f "$ssh_pub_key" ]; then
      tee "$authorized_keys" <"$ssh_pub_key" >/dev/null
    else
      echo "Public key not found. Ensure a key pair exists before running this script."
      return 1
    fi
  else
    echo "authorized_keys already exists for $allowed_user. Checking if the public key is present..."
    # Extract key type and key value from the public key file
    key_type_and_value=$(awk '{print $1, $2}' "$ssh_pub_key")
    if ! grep -qF "$key_type_and_value" "$authorized_keys"; then
      echo "Adding missing public key to authorized_keys."
      tee -a "$authorized_keys" <"$ssh_pub_key" >/dev/null
    else
      echo "Public key already exists in authorized_keys."
    fi
  fi

  # Always enforce correct permissions on authorized_keys
  chmod 600 "$authorized_keys"
  chown "$allowed_user:$allowed_user" "$authorized_keys"

  # Enforce correct permissions on all SSH key files
  if [ -f "$ssh_key" ]; then
    chmod 600 "$ssh_key"
    chown "$allowed_user:$allowed_user" "$ssh_key"
  fi
  if [ -f "$ssh_pub_key" ]; then
    chmod 644 "$ssh_pub_key"
    chown "$allowed_user:$allowed_user" "$ssh_pub_key"
  fi

  echo "Public key authentication enabled for $allowed_user."

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

  # Replace pam_unix.so or insert pam_google_authenticator.so at the correct position
  awk -v ga_line="$ga_pam_line" '
    BEGIN {
      inserted = 0;
    }
    # Detect auth section lines
    /^auth/ {
      if (!inserted && $0 ~ /pam_unix\.so/) {
        # Replace pam_unix.so with pam_google_authenticator.so
        print ga_line;
        inserted = 1;
        next;
      }
      if (!inserted && $0 ~ /(sufficient|requisite|binding)/) {
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
  ' "$pam_sshd_config" | tee "$pam_sshd_config.tmp" >/dev/null

  # Abort if awk produces an empty file
  if [ ! -s "$pam_sshd_config.tmp" ]; then
    echo "Error: Processing $pam_sshd_config failed."
    rm "$pam_sshd_config.tmp"
    return 1
  fi

  # Replace the sshd config file atomically
  chmod 644 "$pam_sshd_config.tmp"
  mv "$pam_sshd_config.tmp" "$pam_sshd_config"

  echo "Google Authenticator added to the auth section of PAM SSH configuration."
}

# Configure Google Authenticator TOTP for the allowed user
configure_google_auth() {
  echo "Configuring Google Authenticator TOTP for the allowed user..."

  # Define the configuration file path
  ga_config="/home/$allowed_user/.google_authenticator"

  # Run google-authenticator as the allowed user with secure options
  su - "$allowed_user" -c "google-authenticator -t -d -r 3 -R 30 -W -s '$ga_config'"

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
  users_to_add="${allowed_user},${users_to_add}"

  if [ -n "$users_to_add" ]; then
    users_added=""
    # Split input into individual usernames
    for user in $(echo "$users_to_add" | tr ',' '\n'); do
      user=$(echo "$user" | xargs) # Trim whitespace
      if validate_user "$user"; then
        pw groupmod sudo -m "$user"
        users_added="${users_added}${user},"
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
    echo '%sudo ALL=(ALL:ALL) ALL' | tee /usr/local/etc/sudoers.d/sudo >/dev/null
    chmod 440 /usr/local/etc/sudoers.d/sudo
  fi

  # Prompt before disabling wheel group sudo access
  echo "Do you want to disable sudo access for the wheel group? (yes/no)"
  printf "Enter your choice (default: yes): "
  read -r disable_wheel
  disable_wheel="${disable_wheel:-yes}"

  if [ "$disable_wheel" = "yes" ]; then
    echo "Disabling sudo access for the wheel group..."

    # Regex to catch all variations of %wheel entries
    WHEEL_REGEX='^%wheel[[:blank:]]+ALL=\(ALL(:ALL)?\)[[:blank:]]+(NOPASSWD:[[:blank:]]+)?ALL'

    if grep -qE "$WHEEL_REGEX" /usr/local/etc/sudoers; then
      sed -i '' -E "s/${WHEEL_REGEX}/# &/" /usr/local/etc/sudoers
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
  echo "Do you want to remove non-root members from the wheel group? (yes/no)"
  printf "Enter your choice (default: yes): "
  read -r remove_wheel_members
  remove_wheel_members="${remove_wheel_members:-yes}"

  if [ "$remove_wheel_members" = "yes" ]; then
    users_removed=""
    echo "Removing non-root users from the wheel group..."
    for user in $(getent group wheel | cut -d ':' -f 4 | tr ',' '\n'); do
      if [ "$user" != "root" ] && [ -n "$user" ]; then
        pw groupmod wheel -d "$user"
        users_removed="${users_removed}${user},"
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
  sed -i '' -E "s/(SSH_PORTS: )([0-9]+|\[[0-9, ]+\])/\1$admin_ssh_port/" "$suricata_conf"

  # Append the custom configuration to the existing suricata.yaml using the `include` directive
  if ! grep -q "^include: $suricata_custom_conf" "$suricata_conf"; then
    echo "include: $suricata_custom_conf" | tee -a "$suricata_conf" >/dev/null
    echo "Custom Suricata configuration included."
  else
    echo "Custom Suricata configuration is already included."
  fi

  # Add custom Suricata rule for SSH port if not present
  if ! grep -qF "port $admin_ssh_port" "$suricata_rules"; then
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
  echo "Configuring Fail2Ban to protect SSH and add manual permanent ban jail..."

  # Configure Fail2Ban jail
  echo "Creating Fail2Ban jail.local for SSH and manual bans..."
  cat <<EOF | tee /usr/local/etc/fail2ban/jail.local >/dev/null
[sshd]
enabled = true
filter = sshd
maxretry = 3
bantime = 3600  # 1 hour ban
findtime = 600  # 10 minutes window to track failed attempts
action = bsd-ipfw[table=fail2ban]

[manualbans]
enabled = true
filter =
bantime = -1  # Permanent ban
action = bsd-ipfw[table=fail2ban]
EOF

  # Enable Fail2Ban service
  echo "Enabling Fail2Ban service..."
  sysrc fail2ban_enable="YES"

  echo "Fail2Ban configuration completed. Restart the service to apply changes."
}

# Harden system kernel with sysctl settings
harden_sysctl() {
  echo "Applying sysctl hardening..."
  sysctl_conf="/etc/sysctl.conf"

  # Define the sysctl values to be set
  settings=$(
    cat <<EOF
net.link.bridge.pfil_bridge=1
net.inet.icmp.bmcastecho=0
net.inet.icmp.drop_redirect=1
net.inet.icmp.icmplim=50
net.inet.igmp.legacysupp=0
net.inet.igmp.v2enable=0
net.inet.igmp.v1enable=0
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
net.inet6.mld.v1enable=0
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
security.mac.portacl.rules=uid:$(id -u "root"):tcp:$admin_ssh_port
security.mac.portacl.port_high=10000
net.inet.ip.portrange.reservedlow=0
net.inet.ip.portrange.reservedhigh=0
hw.ibrs_disable=0
hw.spec_store_bypass_disable=2
hw.mds_disable=3
vm.pmap.allow_2m_x_ept=0
EOF
  )

  for setting in $settings; do
    key="${setting%%=*}"

    # Use sysctl -d to check if the key exists
    if echo "$key" | grep -qF "net.inet.ip.fw." || sysctl -d "$key" >/dev/null 2>&1; then
      # If the current value is different from the desired value, update it
      if ! grep -qE "^${setting}([ \t]+#|:|$)" "$sysctl_conf"; then
        if grep -q "^${key}=" "$sysctl_conf"; then
          sed -i '' "s|^${key}=.*|${setting}|" "$sysctl_conf"
        else
          echo "$setting" | tee -a "$sysctl_conf" >/dev/null
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
  settings=$(
    cat <<EOF
mac_bsdextended_load="YES"
mac_portacl_load="YES"
mac_seeotheruids_load="YES"
ipfw_load="YES"
dummynet_load="YES"
EOF
  )

  # Add CPU microcode settings to loader.conf if detected
  if [ "$cpu_type" != "unknown" ]; then
    microcode_settings=$(
      cat <<EOF
cpuctl_load="YES"
cpu_microcode_load="YES"
EOF
    )
    if [ "$cpu_type" = "intel" ]; then
      microcode_settings=$(
        cat <<EOF
$microcode_settings
coretemp_load="YES"
cpu_microcode_name="/boot/firmware/intel-ucode.bin"
EOF
      )
    elif [ "$cpu_type" = "amd" ]; then
      microcode_settings=$(
        cat <<EOF
$microcode_settings
amdtemp_load="YES"
cpu_microcode_name="/boot/firmware/amd-ucode.bin"
EOF
      )
    fi
    settings=$(
      cat <<EOF
$settings
$microcode_settings
EOF
    )
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
        elif [ "$module" != "ipfw" ]; then
          if kldload "$module" 2>/dev/null; then
            echo "Module '${module}' successfully loaded."
          else
            echo "Warning: Failed to load kernel module '${module}'."
            continue
          fi
        fi
      fi

      # Update or append the loader.conf entry
      if grep -q "^${key}=" "$loader_conf"; then
        sed -i '' "s|^${key}=.*|${setting}|" "$loader_conf"
      else
        echo "$setting" | tee -a "$loader_conf" >/dev/null
      fi
    else
      echo "Warning: Kernel module '${module}' not found in /boot/kernel/ or /boot/modules/"
    fi
  done

  echo "loader.conf hardened with additional kernel security modules and microcode settings."
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

  # Check if the 'default' block exists
  if ! grep -q '^default:' /etc/login.conf; then
    echo "Error: 'default:' block not found in /etc/login.conf. Cannot proceed."
    return 1
  fi

  # Check if Blowfish hashing is already enabled
  blf_enabled=$(grep -qE '^[[:blank:]]*:passwd_format=blf:' /etc/login.conf && echo 1 || echo 0)

  # Set Blowfish password hashing, secure umask, and password expiration in one pass
  awk -v new_passwd_format="blf" -v new_umask="027" -v password_expiration="${password_expiration:-none}" '
    BEGIN { in_default = 0; passwordtime_present = 0 }
    # Start processing the "default" block
    /^default:/ { in_default = 1 }
    in_default {
      # Update passwd_format
      if ($0 ~ /:passwd_format=/) sub(/:passwd_format=[^:]+:/, ":passwd_format=" new_passwd_format ":");
      # Update umask
      if ($0 ~ /:umask=/) sub(/:umask=[0-9]+:/, ":umask=" new_umask ":");
      # Update passwordtime if it exists
      if ($0 ~ /:passwordtime=/) {
        passwordtime_present = 1;
        if (password_expiration != "none") sub(/:passwordtime=[^:]+:/, ":passwordtime=" password_expiration ":");
      }
      # Append passwordtime if missing and the block ends
      if ($0 !~ /:\\$/) {
        in_default = 0;
        if (!passwordtime_present && password_expiration != "none") {
          print "\t:passwordtime=" password_expiration ":\\";
        }
      }
    }
    # Print the current line
    { print }
  ' /etc/login.conf | tee /etc/login.conf.tmp >/dev/null

  # Abort if awk produces an empty file
  if [ ! -s /etc/login.conf.tmp ]; then
    echo "Error: Processing login.conf failed."
    rm /etc/login.conf.tmp
    return 1
  fi

  # Replace the login.conf file atomically
  chmod 644 /etc/login.conf.tmp
  mv /etc/login.conf.tmp /etc/login.conf

  # Rebuild login capabilities database
  if ! cap_mkdb /etc/login.conf; then
    echo "Error: Failed to rebuild the login.conf database."
    return 1
  fi

  # Check if Blowfish hashing needs to be enabled
  if [ "$blf_enabled" -ne 1 ]; then
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
  fi

  echo "Password security configured with umask 027 and Blowfish encryption for $allowed_user."
}

# Configure IPFW firewall with updated rules
configure_ipfw() {
  echo "Configuring IPFW firewall with Suricata and Dummynet..."
  ipfw_rules="/etc/ipfw.rules"
  local_ipfw_rules="./ipfw.rules"

  # Define the ipfw.rules values to be set
  settings=$(
    cat <<EOF
ext_if="$external_interface"
tun_if="$tunnel_interface"
int_if="$internal_interface"
ssh_ip4="$admin_ipv4"
ssh_ip6="$admin_ipv6"
ssh_tcp_port="$admin_ssh_port"
EOF
  )

  # Apply IPFW configuration changes
  if [ -f "$local_ipfw_rules" ]; then
    for setting in $settings; do
      key="${setting%%=*}"

      # Update the ipfw.rules variable
      if grep -q "^${key}=" "$local_ipfw_rules"; then
        sed -i '' "s|^${key}=.*|${setting}|" "$local_ipfw_rules"
      fi
    done
  else
    echo "Error: Local ipfw.rules file not found."
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
  echo "$current_crontab" | tee "$temp_crontab" >/dev/null

  # Add Suricata update cron job if applicable
  if [ "$install_suricata" = "yes" ] && ! echo "$current_crontab" | grep -qF "$suricata_cmd"; then
    echo "$suricata_cron" | tee -a "$temp_crontab" >/dev/null
    echo "Added Suricata update cron job."
  else
    echo "Suricata update cron job already exists or not applicable. Skipping..."
  fi

  # Add FreeBSD update cron job if not already present
  if [ "$freebsd_update_supported" = "yes" ] && ! echo "$current_crontab" | grep -qF "$freebsd_update_cmd"; then
    echo "$freebsd_update_cron" | tee -a "$temp_crontab" >/dev/null
    echo "Added FreeBSD update cron job."
  else
    echo "FreeBSD update cron job already exists or not supported. Skipping..."
  fi

  # Add pkg update cron job if not already present
  if ! echo "$current_crontab" | grep -qF "$pkg_update_cmd"; then
    echo "$pkg_update_cron" | tee -a "$temp_crontab" >/dev/null
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
  harden_loader_conf
  harden_sysctl
  lock_down_system
  echo "Security hardening complete. Please reboot to apply all changes."
}

# Run the main function
main
