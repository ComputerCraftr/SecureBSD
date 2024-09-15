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
  chflags noschg /etc/pf.conf /etc/sysctl.conf /etc/rc.conf /boot/loader.conf /etc/fstab /etc/resolv.conf /etc/login.access /etc/newsyslog.conf
}

# Reapply immutable flags after updates
reapply_immutable_flags() {
  echo "Reapplying immutable flags on system files..."
  chflags schg /etc/pf.conf /etc/sysctl.conf /etc/rc.conf /boot/loader.conf /etc/fstab /etc/resolv.conf /etc/login.access /etc/newsyslog.conf
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

# Update FreeBSD and install necessary packages
update_and_install_packages() {
  echo "Updating FreeBSD and installing necessary packages (sudo, fail2ban)..."
  freebsd-update fetch install
  pkg update
  pkg upgrade -y
  pkg install -y sudo py311-fail2ban
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

# Configure fail2ban for SSH protection
configure_fail2ban() {
  echo "Configuring Fail2Ban to protect SSH from brute-force attacks..."
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
  cat <<EOF >>$sysctl_conf
kern.coredump=0
kern.elf64.aslr.enable=1
kern.elf64.aslr.pie_enable=1
kern.randompid=1
kern.sugid_coredump=0
kern.securelevel=1
kern.elf64.stackgap.randomize=1
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
security.jail.hide_jails=1
security.bsd.unprivileged_read_msgbuf=0
security.bsd.unprivileged_proc_debug=0
EOF
  echo "System kernel hardened with secure sysctl settings."
}

# Harden loader.conf with additional kernel security modules
harden_loader_conf() {
  echo "Configuring loader.conf for additional kernel security..."
  loader_conf="/boot/loader.conf"
  cat <<EOF >>$loader_conf
mac_biba_load="YES"
mac_bsdextended_load="YES"
mac_ifoff_load="YES"
mac_lomac_load="YES"
mac_mls_load="YES"
mac_partition_load="YES"
mac_portacl_load="YES"
mac_seeotheruids_load="YES"
mac_veriexec_load="YES"
kern_securelevel_enable="YES"
EOF
  echo "loader.conf hardened with additional kernel security modules."
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
  pf_rules="pass in proto tcp from { $admin_ips } to any port $ssh_port keep state"
  cat <<EOF >/etc/pf.conf
scrub in all
block in log all
set skip on lo
pass out inet all keep state
pass out inet6 all keep state
$pf_rules
block return in log all
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

# Configure weekly cron jobs for system updates
configure_cron_updates() {
  echo "Setting up weekly automatic updates via cron..."
  if ! grep -q "freebsd-update cron" /etc/crontab; then
    echo "0 3 * * 0 root freebsd-update cron" >>/etc/crontab
  fi
  if ! grep -q "freebsd-update install && pkg update && pkg upgrade -y" /etc/crontab; then
    echo "0 4 * * 0 root freebsd-update install && pkg update && pkg upgrade -y" >>/etc/crontab
  fi
}

# Lock down sensitive system files
lock_down_system() {
  echo "Locking down critical system files..."
  chmod o= /etc/ftpusers /etc/hosts /etc/login.conf /etc/rc.conf /etc/ssh/sshd_config /etc/sysctl.conf /etc/crontab /usr/bin/at /var/log
  reapply_immutable_flags
  echo "root" | tee /var/cron/allow /var/at/at.allow >/dev/null
  echo "System files locked down and cron/at restricted to root only."
}

# Main function to run the full process
main() {
  collect_user_input
  clear_immutable_flags
  backup_configs
  update_and_install_packages
  configure_ssh
  configure_sudo
  configure_fail2ban
  harden_sysctl
  harden_loader_conf
  configure_password_and_umask
  configure_pf
  secure_syslog_and_tmp
  configure_cron_updates
  lock_down_system
  echo "Security hardening complete. Please review configurations and reboot to apply all changes."
}

# Run the main function
main
