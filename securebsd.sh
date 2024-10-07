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
  printf "Enter the SSH port to use (default: 2222): "
  read -r ssh_port
  ssh_port="${ssh_port:-2222}"
  validate_port "$ssh_port"

  # Admin IPs input
  echo "Enter a comma-separated list of IPs allowed to SSH into the server, or type 'any' to allow all IPs (not recommended)."
  printf "Enter the admin IPs (comma-separated) for SSH access: "
  read -r admin_ips

  # Suricata interface input
  printf "Enter the external network interface for IPFW and Suricata (e.g., em0, re0): "
  read -r external_interface
  validate_interface "$external_interface"

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
  pkg install -y sudo py311-fail2ban suricata anacron
  suricata-update
  echo "System updated and packages installed."
}

# Configure SSH security settings
configure_ssh() {
  echo "Configuring SSH security..."
  sshd_config="/etc/ssh/sshd_config"

  # Apply all SSH configuration changes in a single sed command
  sed -i '' -E \
    -e "s/^#?PermitRootLogin .*/PermitRootLogin no/" \
    -e "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" \
    -e "s/^#?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" \
    -e "s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/" \
    -e "s/^#?UsePAM .*/UsePAM no/" \
    -e "s/^#?Port .*/Port $ssh_port/" "$sshd_config"

  # Ensure allowed user is listed in the config
  if grep -q "^AllowUsers" "$sshd_config"; then
    sed -i '' -E "s/^AllowUsers .*/AllowUsers $allowed_user/" "$sshd_config"
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
  chown -R "$allowed_user:$allowed_user" /home/"$allowed_user"/.ssh
  echo "Public key authentication enabled for $allowed_user."

  # Warning: Copy the private key to your local system before rebooting
  echo "WARNING: You must copy the private key to your local machine before rebooting."
  echo "To securely transfer the private key, use the following command on your local machine:"
  echo "scp <username>@<remote_host>:/home/$allowed_user/.ssh/id_ed25519 ~/.ssh/"
  echo ""
  echo "After copying the private key, delete it from the remote system for security:"
  echo "ssh <username>@<remote_host> 'rm /home/$allowed_user/.ssh/id_ed25519'"
  echo ""
  echo "Ensure the permissions for the private key on your local machine are set correctly with:"
  echo "chmod 600 ~/.ssh/id_ed25519"
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
  echo "Configuring Suricata for IPS mode with IPFW..."

  # Define the configuration file paths as variables
  suricata_conf="/usr/local/etc/suricata/suricata.yaml"
  suricata_custom_conf="/usr/local/etc/suricata/suricata-custom.yaml"
  suricata_rules="/var/lib/suricata/rules/custom.rules"
  suricata_port="8000" # Define the divert port for IPFW to Suricata

  # Create or update the Suricata custom configuration file
  cat <<EOF >"$suricata_custom_conf"
%YAML 1.1
---
ipfw:
  - interface: $external_interface
    divert-port: $suricata_port
    threads: auto
    checksum-checks: auto

# Enable inline stream handling for IPS mode
stream:
  inline: yes

# Specify the action order for Suricata rules in IPS mode
action-order:
  - pass
  - drop
  - reject
  - alert

# Output logs including dropped packets
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
  sed -E -i '' "s/(SSH_PORTS: )([0-9]+|\[[0-9, ]+\])/\1$ssh_port/" "$suricata_conf"

  # Append the custom configuration to the existing suricata.yaml using the `include` directive
  if ! grep -q "include: $suricata_custom_conf" "$suricata_conf"; then
    echo "include: $suricata_custom_conf" >>"$suricata_conf"
    echo "Custom Suricata configuration included."
  else
    echo "Custom Suricata configuration is already included."
  fi

  # Add custom Suricata rule for SSH port if not present
  if ! grep -q "port $ssh_port" "$suricata_rules"; then
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
  sysrc suricata_interface="$external_interface"
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

# Disable core dumps to prevent sensitive data exposure
kern.coredump=0

# Randomize PID assignment to make process prediction harder
kern.randompid=1

# Disable core dumps for setuid binaries to prevent exposure of sensitive information
kern.sugid_coredump=0

# Restrict visibility of processes to the owner only
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0

# Restrict jail process visibility
security.bsd.see_jail_proc=0

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
dummynet_load="YES"
EOF
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
         { print; if (!/\\$/) flag=0 }' /etc/login.conf >/tmp/login.conf && mv /tmp/login.conf /etc/login.conf
    else
      # Append passwordtime inside the default block
      awk -v new_passwordtime="passwordtime=${password_expiration}:\\" \
        '/^default:/ { print; print "\t:" new_passwordtime; next }1' /etc/login.conf >/tmp/login.conf && mv /tmp/login.conf /etc/login.conf
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
  cat <<EOF >/etc/ipfw.rules
#!/bin/sh

# Define the firewall command
fwcmd="/sbin/ipfw"

# Define external interface, internal network, and Suricata divert port
ext_if="$external_interface"  # Adjust as needed for your external interface
int_if="$external_interface"  # Adjust to your internal network interface
int_net="10.0.0.0/8"  # Define the internal network
divert_port="$suricata_port"  # Suricata divert port

# Check if IPv6 is available by detecting any IPv6 addresses
ipv6_available=\$(ifconfig | grep -q "inet6" && echo 1 || echo 0)

# Flush existing rules
\${fwcmd} -q -f flush

# Allow all traffic on the loopback interface (lo0)
\${fwcmd} add 100 allow all from any to any via lo0

# Deny any traffic destined to the IPv4 loopback network (127.0.0.0/8)
\${fwcmd} add 200 deny all from any to 127.0.0.0/8

# Deny any traffic with a source address from the IPv4 loopback network (127.0.0.0/8)
\${fwcmd} add 300 deny ip from 127.0.0.0/8 to any

# If IPv6 is available, configure IPv6 loopback
if [ \$ipv6_available -eq 1 ]; then
    # Deny traffic destined to the IPv6 loopback address (::1)
    \${fwcmd} add 400 deny all from any to ::1

    # Deny traffic with a source address from the IPv6 loopback address (::1)
    \${fwcmd} add 500 deny all from ::1 to any
fi

# Drop traffic from the Fail2Ban table
\${fwcmd} add 600 deny ip from 'table(fail2ban)' to any

# Allow ARP only on internal LAN interface
\${fwcmd} add 700 allow ether from any to any arp via \$int_if

# Block packets with IP options (prevent spoofing, source routing attacks)
\${fwcmd} add 800 deny ip from any to any ipoptions

# Consolidated Anti-spoofing: Block traffic with spoofed IPs on all interfaces (in and out)
\${fwcmd} add 900 deny all from any to any not verrevpath

# Divert established connections to Suricata for analysis
\${fwcmd} add 1000 divert \$divert_port ip from any to any established

# Divert new SSH connections to Suricata for analysis
\${fwcmd} add 1100 divert \$divert_port tcp from $admin_ips to me $ssh_port setup limit dst-addr 10

# Divert new HTTP/HTTPS connections to Suricata for analysis
\${fwcmd} add 1200 divert \$divert_port tcp from any to me 80,443 setup limit src-addr 100

# Create a dummynet pipe to limit total ICMPv4 and ICMPv6 ping bandwidth to 10Kbit/s
\${fwcmd} pipe 1 config bw 10Kbit/s

# Allow ICMPv4 pings (ping requests to firewall itself), limit via dummynet pipe (not diverted to Suricata)
\${fwcmd} add 1300 allow icmp from any to me icmptypes 8
\${fwcmd} add 1310 pipe 1 ip from any to me icmp

# Allow ICMPv6 pings (ping requests to any device on LAN), limit via dummynet pipe (not diverted to Suricata)
\${fwcmd} add 1400 allow ipv6-icmp from any to any icmp6types 128
\${fwcmd} add 1410 pipe 1 ipv6-icmp from any to any

# Combine ICMPv6 Neighbor Discovery, Router Advertisements, and PMTUD inbound
\${fwcmd} add 1500 allow ipv6-icmp from any to any icmp6types 2,133,134,135,136

# Allow DHCPv4 for WAN (firewall receiving dynamic IPv4 from ISP) inbound on WAN
\${fwcmd} add 1600 allow udp from any 67 to me 68 in recv \$ext_if

# Allow DHCPv6 for WAN (firewall receiving dynamic IPv6 from ISP) inbound on WAN
\${fwcmd} add 1610 allow udp from any 547 to me 546 in recv \$ext_if

# Allow DHCPv4 inbound on LAN (for local DHCP server to assign IP addresses to LAN clients)
\${fwcmd} add 1700 allow udp from any 67 to any 68 in recv \$int_if

# Allow DHCPv6 inbound on LAN (for local DHCP server to assign IP addresses to LAN clients)
\${fwcmd} add 1710 allow udp from any 547 to any 546 in recv \$int_if

# Divert all outgoing traffic (including TCP, UDP, ICMP, etc.) from firewall to Suricata
\${fwcmd} add 1800 divert \$divert_port ip from me to any out keep-state

# Divert all outgoing traffic from internal network to Suricata
\${fwcmd} add 1810 divert \$divert_port ip from \$int_net to any out keep-state

# Deny all other traffic (both IP and non-IP)
\${fwcmd} add 65534 deny all from any to any
EOF

  # Set the firewall to load on boot and specify the rules file
  sysrc firewall_enable="YES"
  sysrc firewall_script="/etc/ipfw.rules"
  sysrc firewall_type="custom" # Indicate that this is a custom firewall

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
  harden_sysctl
  harden_loader_conf
  configure_ssh
  configure_sudo
  configure_fail2ban
  configure_suricata
  configure_ipfw
  configure_securelevel
  configure_password_and_umask
  secure_syslog_and_tmp
  configure_cron_updates
  lock_down_system
  echo "Security hardening complete. Please reboot to apply all changes."
}

# Run the main function
main
