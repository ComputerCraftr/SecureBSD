#!/bin/sh

# Exit on errors and undefined variables
set -eu

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# Validate the existence of a user
validate_user() {
  if ! id "$1" >/dev/null 2>&1; then
    echo "Error: User '$1' does not exist. Please provide a valid username."
    exit 1
  fi
}

# Validate SSH port input
validate_port() {
  if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
    echo "Error: Invalid port number '$1'. Port must be an integer between 1 and 65535."
    exit 1
  fi
}

# Validate network interface
validate_interface() {
  if ! ifconfig "$1" >/dev/null 2>&1; then
    echo "Error: Invalid interface '$1'. Please enter a valid network interface."
    exit 1
  fi
}

# Validate password expiration input
validate_password_expiration() {
  if [ "$1" != "disable" ]; then
    if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -le 0 ]; then
      echo "Error: Invalid password expiration '$1'. Must be a positive integer or 'disable'."
      exit 1
    fi
  fi
}

# Clear immutable flags on system files to allow updates
clear_immutable_flags() {
  echo "Clearing immutable flags on system files for updates..."

  # Space-separated list of files to check
  files_to_check="/etc/pf.conf /etc/sysctl.conf /boot/loader.conf /etc/fstab /etc/login.access /etc/newsyslog.conf /etc/ssh/sshd_config /etc/hosts /etc/hosts.allow /etc/pam.d/sshd"

  # Iterate through the list, check if the file exists, and clear the immutable flag
  for file in $files_to_check; do
    if [ ! -f "$file" ]; then
      echo "$file does not exist, creating it."
      touch "$file"
    fi
    chflags noschg "$file" # Clear immutable flag for the file
  done
}

# Reapply immutable flags after updates
reapply_immutable_flags() {
  echo "Reapplying immutable flags on system files..."
  chflags schg /etc/pf.conf /etc/sysctl.conf /boot/loader.conf /etc/fstab /etc/login.access /etc/newsyslog.conf /etc/ssh/sshd_config /etc/hosts /etc/hosts.allow /etc/pam.d/sshd
}

# Collect user input for SSH, IPs, and password expiration settings
collect_user_input() {
  echo "This script will harden your FreeBSD system by securing SSH, enabling firewall rules, configuring automatic updates, and more."

  # SSH allowed user input
  echo "Enter a valid username for SSH access and sudo privileges."
  printf "Enter the username to allow for SSH access: "
  read -r allowed_user
  validate_user "$allowed_user"

  # SSH port input
  echo "Choose a custom SSH port (not the default 22)."
  printf "Enter the SSH port to use: "
  read -r ssh_port
  validate_port "$ssh_port"

  # Admin IPs input
  echo "Enter a comma-separated list of IPs allowed to SSH into the server, or type 'any' to allow all IPs (not recommended)."
  printf "Enter the admin IPs (comma-separated) for SSH access: "
  read -r admin_ips

  # Suricata interface input
  printf "Enter the external network interface for PF and Suricata (e.g., em0, re0): "
  read -r external_interface
  validate_interface "$external_interface"

  # Password expiration input
  echo "Set the password expiration period in days. Type 'disable' to disable expiration (not recommended)."
  printf "Enter the password expiration period in days: "
  read -r password_expiration
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
  for conf_file in /etc/rc.conf /etc/sysctl.conf /etc/login.conf /boot/loader.conf /etc/ssh/sshd_config; do
    cp "$conf_file" "$backup_dir"
  done
  echo "Backup completed. Files saved in $backup_dir."
}

# Update FreeBSD and install necessary packages (sudo, fail2ban, Suricata)
update_and_install_packages() {
  echo "Updating FreeBSD and installing necessary packages (sudo, fail2ban, Suricata)..."
  freebsd-update fetch install
  pkg update
  pkg upgrade -y
  pkg install -y sudo py311-fail2ban suricata
  suricata-update
  echo "System updated and packages installed."
}

# Configure SSH security settings
configure_ssh() {
  echo "Configuring SSH security..."
  sshd_config="/etc/ssh/sshd_config"

  # Apply SSH configuration changes
  sed -i '' "s/^#\?PermitRootLogin .*/PermitRootLogin no/" "$sshd_config"
  sed -i '' "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" "$sshd_config"
  sed -i '' "s/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" "$sshd_config"
  sed -i '' "s/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/" "$sshd_config"
  sed -i '' "s/^#\?UsePAM .*/UsePAM no/" "$sshd_config"
  sed -i '' "s/^#\?Port .*/Port $ssh_port/" "$sshd_config"

  # Ensure allowed user is listed in the config
  if grep -q "^AllowUsers" "$sshd_config"; then
    sed -i '' "s/^AllowUsers .*/AllowUsers $allowed_user/" "$sshd_config"
  else
    echo "AllowUsers $allowed_user" >>"$sshd_config"
  fi

  echo "SSH configured with updated settings."

  # Generate SSH key for user
  if [ ! -f /home/"$allowed_user"/.ssh/id_ed25519 ]; then
    echo "No SSH key found for $allowed_user. Generating new key pair..."
    sudo -u "$allowed_user" ssh-keygen -t ed25519 -f /home/"$allowed_user"/.ssh/id_ed25519 -N ""
  fi

  # Enable public key authentication for user
  sudo -u "$allowed_user" mkdir -p /home/"$allowed_user"/.ssh
  sudo -u "$allowed_user" cat /home/"$allowed_user"/.ssh/id_ed25519.pub | sudo tee -a /home/"$allowed_user"/.ssh/authorized_keys >/dev/null
  chmod 600 /home/"$allowed_user"/.ssh/authorized_keys
  echo "Public key authentication enabled for $allowed_user."
}

# Configure sudo for the allowed user
configure_sudo() {
  echo "Configuring sudo for the allowed user..."
  if ! groups "$allowed_user" | grep -q wheel; then
    pw groupmod wheel -m "$allowed_user"
  fi
  if [ ! -f /usr/local/etc/sudoers.d/wheel ]; then
    echo '%wheel ALL=(ALL) ALL' >/usr/local/etc/sudoers.d/wheel
  fi
  echo "Sudo configured for the allowed user in the wheel group."
}

# Configure Suricata for IPS mode and include custom config
configure_suricata() {
  echo "Configuring Suricata for IPS mode..."

  # Create a custom configuration file for Suricata
  cat <<EOF >/usr/local/etc/suricata/suricata-custom.yaml
%YAML 1.1
---
af-packet:
  - interface: $external_interface
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 4096
    block-size: 65536
    checksum-checks: auto
    copy-mode: ips
    use-emergency-flush: yes

# Enable inline stream handling
stream:
  inline: yes

# Specify the action order for Suricata rules in IPS mode
action-order:
  - pass
  - drop
  - reject
  - alert

outputs:
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json

app-layer:
  protocols:
    ssh:
      enabled: yes

    pgsql:
      enabled: yes
EOF

  # Append the custom configuration to the existing suricata.yaml using the `include` directive
  if ! grep -q "include: /usr/local/etc/suricata/suricata-custom.yaml" /usr/local/etc/suricata/suricata.yaml; then
    echo "include: /usr/local/etc/suricata/suricata-custom.yaml" >>/usr/local/etc/suricata/suricata.yaml
    echo "Custom Suricata configuration included."
  else
    echo "Custom Suricata configuration is already included."
  fi

  # Test the Suricata configuration
  if ! suricata -T -c /usr/local/etc/suricata/suricata.yaml; then
    echo "Suricata configuration test failed. Please review the configuration."
    exit 1
  fi

  # Enable Suricata at boot
  sysrc suricata_enable="YES"
  echo "Suricata configured to enable at next reboot on interface $external_interface."
}

# Configure Fail2Ban to protect SSH
configure_fail2ban() {
  echo "Configuring Fail2Ban to protect SSH..."
  cat <<EOF >/usr/local/etc/fail2ban/jail.local
[sshd]
enabled = true
port = $ssh_port
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
  cat <<EOF >$sysctl_conf
# Limit the number of ICMP redirects and requests
net.inet.icmp.icmplim=50

# Enable TCP and UDP blackhole
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1

# Enable SYN cookies for SYN flood protection
net.inet.tcp.syncookies=1

# Drop SYN+FIN packets to prevent stealth attacks
net.inet.tcp.drop_synfin=1

# Improve BPF performance with zerocopy for Suricata
net.bpf.zerocopy_enable=1

# Disable core dumps to prevent sensitive data exposure
kern.coredump=0

# Enable Address Space Layout Randomization (ASLR) to mitigate certain types of attacks
kern.elf64.aslr.enable=1
kern.elf64.aslr.pie_enable=1

# Randomize PID assignment to make process prediction harder
kern.randompid=1

# Disable core dumps for setuid binaries to prevent exposure of sensitive information
kern.sugid_coredump=0

# Stack gap randomization to protect against stack-based buffer overflow attacks
kern.elf64.stackgap.randomize=1

# Restrict visibility of processes to the owner only
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0

# Restrict jail process visibility
security.jail.hide_jails=1

# Prevent unprivileged processes from reading kernel message buffers
security.bsd.unprivileged_read_msgbuf=0

# Prevent unprivileged processes from debugging other processes
security.bsd.unprivileged_proc_debug=0
EOF
  echo "System kernel hardened with secure sysctl settings."
}

# Harden loader.conf with additional kernel security modules
harden_loader_conf() {
  echo "Configuring loader.conf for additional kernel security..."
  loader_conf="/boot/loader.conf"
  cat <<EOF >$loader_conf
mac_bsdextended_load="YES"
mac_partition_load="YES"
mac_portacl_load="YES"
mac_seeotheruids_load="YES"
mac_veriexec_load="YES"
EOF
  echo "loader.conf hardened with additional kernel security modules."
}

# Set securelevel in rc.conf
configure_securelevel() {
  echo "Configuring securelevel in rc.conf..."
  rc_conf="/etc/rc.conf"

  # Enable securelevel enforcement
  if ! grep -q 'kern_securelevel_enable="YES"' "$rc_conf"; then
    echo 'kern_securelevel_enable="YES"' >>"$rc_conf"
  fi

  # Set securelevel to desired level (e.g., 1)
  if ! grep -q 'kern_securelevel="' "$rc_conf"; then
    echo 'kern_securelevel="1"' >>"$rc_conf"
  else
    # Update existing securelevel if needed
    sed -i '' 's/kern_securelevel="[0-9]*"/kern_securelevel="1"/' "$rc_conf"
  fi

  echo "Securelevel configured in rc.conf."
}

# Set Blowfish password hashing, enforce password expiration, and configure umask
configure_password_and_umask() {
  echo "Configuring password security with Blowfish encryption and setting a secure umask..."
  sed -i '' 's/passwd_format=sha512/passwd_format=blf/' /etc/login.conf
  if [ "$password_expiration" != "no password expiration" ]; then
    sed -i '' "s/^default.*/&\n\t:passwordtime=$password_expiration:\\/" /etc/login.conf
  fi
  sed -i '' 's/umask=022/umask=027/' /etc/login.conf
  cap_mkdb /etc/login.conf
  echo "Password for $allowed_user will be reset for Blowfish encryption."
  passwd "$allowed_user"
}

# Configure PF firewall with updated rules
configure_pf() {
  echo "Configuring PF firewall..."
  cat <<EOF >/etc/pf.conf
# Ignore traffic travelling within loopback (stateless)
set skip on lo0

# Enable anti-spoofing on external interfaces (stateless)
antispoof quick for $external_interface

# Reassemble fragmented packets (stateless, leave DF bit intact to allow PMTUD)
scrub in all fragment reassemble

# Block everything unless told otherwise (silent drop)
block drop

# Define separate flood tables for SYN flood and ICMP flood protection
table <syn_flood_table> persist
table <icmp_flood_table> persist

# SYN flood protection using SYN cookies (stateful, no synproxy)
pass in proto tcp from { $admin_ips } to any port $ssh_port flags S/SAFR keep state (max-src-conn-rate 50/10, overload <syn_flood_table> flush global log)

# ICMPv4 Echo Requests (ping flood protection) + rate limiting (no logging to avoid log exhaustion)
pass in proto icmp all icmp-type echoreq keep state (max 10/second, overload <icmp_flood_table> flush global)

# ICMPv6 Echo Requests (ping flood protection) + rate limiting (no logging to avoid log exhaustion)
pass in inet6 proto ipv6-icmp all icmp6-type echoreq keep state (max 10/second, overload <icmp_flood_table> flush global)

# Allow essential ICMPv6 messages (stateless)
pass in inet6 proto ipv6-icmp icmp6-type 2 no state  # Packet Too Big (PMTUD)
pass in inet6 proto ipv6-icmp icmp6-type 134 no state # Router Advertisement
pass in inet6 proto ipv6-icmp icmp6-type 135 no state # Neighbor Solicitation
pass in inet6 proto ipv6-icmp icmp6-type 136 no state # Neighbor Advertisement

# Allow DHCPv4 (stateful)
pass in inet proto udp from port 67 to port 68 keep state

# Allow DHCPv6 (stateful)
pass in inet6 proto udp from port 547 to port 546 keep state

# Allow outgoing connections initiated from this system (stateful)
pass out keep state
EOF
  sysrc pf_enable="YES"
  echo "PF firewall configured to enable at next reboot."
}

# Secure syslog and configure /tmp cleanup at startup
secure_syslog_and_tmp() {
  echo "Securing syslog and configuring /tmp cleanup at startup..."
  sysrc syslogd_flags="-ss"
  service syslogd restart
  echo 'clear_tmp_enable="YES"' >>/etc/rc.conf
  echo "Syslog secured and /tmp cleanup configured."
}

# Configure cron jobs for system updates and suricata-update
configure_cron_updates() {
  echo "Setting up automatic updates via cron..."
  if ! grep -q "suricata-update" /etc/crontab; then
    echo "0 2 * * 0 root suricata-update" >>/etc/crontab
  fi
  if ! grep -q "freebsd-update cron" /etc/crontab; then
    echo "0 3 * * 0 root PAGER=cat freebsd-update cron" >>/etc/crontab
  fi
  if ! grep -q "pkg update" /etc/crontab; then
    echo "0 4 * * 0 root pkg update" >>/etc/crontab
  fi
  echo "Cron jobs for system and Suricata updates configured."
}

# Lock down sensitive system files
lock_down_system() {
  echo "Locking down critical system files..."
  chmod o= /etc/ftpusers /etc/hosts /etc/login.conf /etc/rc.conf /etc/ssh/sshd_config /etc/sysctl.conf /boot/loader.conf /etc/crontab /usr/bin/at /var/log
  reapply_immutable_flags
  echo "root" | tee /var/cron/allow /var/at/at.allow >/dev/null
  echo "System files locked down and cron/at restricted to root only."
}

# Main function to run all steps
main() {
  collect_user_input
  clear_immutable_flags
  backup_configs
  update_and_install_packages
  configure_ssh
  configure_sudo
  configure_fail2ban
  configure_pf
  configure_suricata
  harden_sysctl
  harden_loader_conf
  configure_securelevel
  configure_password_and_umask
  secure_syslog_and_tmp
  configure_cron_updates
  lock_down_system
  echo "Security hardening complete. Please reboot to apply all changes."
}

# Run the main function
main
