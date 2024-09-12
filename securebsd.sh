#!/bin/sh

# Exit on errors and undefined variables
set -eu

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# Function to check if a user exists
validate_user() {
  if ! id "$1" >/dev/null 2>&1; then
    echo "Error: User '$1' does not exist. Please provide a valid username."
    exit 1
  fi
}

# Function to validate port input
validate_port() {
  if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
    echo "Error: Invalid port number '$1'. Port must be an integer between 1 and 65535."
    exit 1
  fi
}

# Function to validate password expiration days or 'disable'
validate_password_expiration() {
  if [ "$1" != "disable" ]; then
    if ! [ "$1" -eq "$1" ] 2>/dev/null || [ "$1" -le 0 ]; then
      echo "Error: Invalid password expiration '$1'. Must be a positive integer or 'disable'."
      exit 1
    fi
  fi
}

# Prompt for necessary variables with clear explanations
echo "This script will harden your FreeBSD system by securing SSH, enabling firewall rules, configuring automatic updates, and more."

# Explanation for allowed_user
echo "You need to specify a user that will be allowed to access the server via SSH and have sudo access."
echo "The user should already exist on the system."
echo "WARNING: The password for this user will be reset to ensure it uses Blowfish encryption."
printf "Enter the username to allow for SSH access: "
read -r allowed_user

# Validate the allowed user
validate_user "$allowed_user"

# Explanation for ssh_port
echo "SSH should not run on the default port (22) for security reasons."
echo "Choose a custom SSH port (e.g., 2222) to reduce exposure to automated attacks."
printf "Enter the SSH port to use: "
read -r ssh_port

# Validate the SSH port
validate_port "$ssh_port"

# Explanation for admin_ips
echo "For security, it's recommended to restrict SSH access to specific IP addresses."
echo "Enter a comma-separated list of admin IP addresses that are allowed to SSH into the server."
echo "If you want to allow SSH from any IP address (not recommended), type 'any'."
printf "Enter the admin IPs (comma-separated) for SSH access: "
read -r admin_ips

# Discouraged option to allow SSH from any IP
if [ "$admin_ips" = "any" ]; then
  echo "Warning: Allowing SSH from any IP is highly discouraged as it exposes your server to brute-force and other attacks."
  echo "It's recommended to restrict SSH access to specific, trusted IP addresses."
fi

# Configurable password expiration
echo "Password expiration helps enforce password rotation for better security."
echo "Enter the number of days after which passwords should expire (e.g., 120 days)."
echo "To disable password expiration (not recommended), type 'disable'."
printf "Enter the password expiration period in days: "
read -r password_expiration

# Validate the password expiration
validate_password_expiration "$password_expiration"

if [ "$password_expiration" = "disable" ]; then
  echo "Warning: Disabling password expiration is discouraged and reduces password security."
  password_expiration="no password expiration"
else
  password_expiration="${password_expiration}d"
fi

# Function to create backup of critical configuration files
backup_configs() {
  echo "Creating backups of critical configuration files before making any changes..."
  backup_dir="/etc/backup_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$backup_dir"
  for conf_file in /etc/rc.conf /etc/sysctl.conf /etc/login.conf /boot/loader.conf /etc/ssh/sshd_config; do
    cp "$conf_file" "$backup_dir"
  done
  echo "Backup completed. Files saved in $backup_dir."
}

# Function to update FreeBSD and install necessary packages (sudo, py311-fail2ban)
update_and_install_packages() {
  echo "Updating FreeBSD and installing necessary packages (sudo, fail2ban)..."

  freebsd-update fetch install
  pkg update
  pkg upgrade -y

  # Install sudo and the correct fail2ban package (py311-fail2ban)
  pkg install -y sudo py311-fail2ban

  echo "System updated and packages installed."
}

# Function to configure SSH security
configure_ssh() {
  echo "Configuring SSH security..."
  echo "Disabling root login, password-based authentication, and enforcing public key authentication."

  sshd_config="/etc/ssh/sshd_config"
  sed -i '' 's/#PermitRootLogin yes/PermitRootLogin no/' "$sshd_config"
  sed -i '' 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$sshd_config"
  sed -i '' 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' "$sshd_config"
  sed -i '' 's/#PubkeyAuthentication no/PubkeyAuthentication yes/' "$sshd_config"

  # Explicitly disable PAM to avoid unintended password authentication
  sed -i '' 's/#UsePAM yes/UsePAM no/' "$sshd_config"

  sed -i '' 's/#Port 22/Port '"$ssh_port"'/' "$sshd_config"
  echo "AllowUsers $allowed_user" >>"$sshd_config"

  echo "SSH key generation and configuration completed. You must manually copy the SSH key to your local machine before restarting SSH."

  # Generate SSH key if not already existing (switch to ed25519 for stronger security)
  if [ ! -f /home/"$allowed_user"/.ssh/id_ed25519 ]; then
    echo "No SSH key found for $allowed_user. Generating a new key pair..."
    sudo -u "$allowed_user" ssh-keygen -t ed25519 -f /home/"$allowed_user"/.ssh/id_ed25519 -N ""
  fi
  echo "SSH key generated for $allowed_user."

  # Ensure public key authentication for the user
  sudo -u "$allowed_user" mkdir -p /home/"$allowed_user"/.ssh
  sudo -u "$allowed_user" cat /home/"$allowed_user"/.ssh/id_ed25519.pub | sudo tee -a /home/"$allowed_user"/.ssh/authorized_keys >/dev/null
  chmod 600 /home/"$allowed_user"/.ssh/authorized_keys
  echo "Public key authentication enabled for $allowed_user."

  echo "You MUST copy the key to your local machine before restarting SSH."
  echo "Do not restart SSH until the key has been securely transferred."
  echo "Once you have copied the key, you can manually restart SSH using: service sshd restart"
}

# Function to configure sudo for wheel group and add the allowed user to the group
configure_sudo() {
  echo "Configuring sudo for the allowed user..."
  pw groupmod wheel -m "$allowed_user"
  echo '%wheel ALL=(ALL) ALL' >/usr/local/etc/sudoers.d/wheel # No passwordless sudo
  echo "Sudo configured for the allowed user in the wheel group."
}

# Function to configure fail2ban for SSH protection
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

  # Enable Fail2ban at next boot
  sysrc fail2ban_enable="YES"
  echo "Fail2Ban configured to enable at next reboot."
}

# Function to harden system kernel with sysctl settings
harden_sysctl() {
  echo "Applying sysctl hardening..."
  sysctl_conf="/etc/sysctl.conf"
  cat <<EOF >>$sysctl_conf
# Disable core dumps to prevent sensitive data exposure
kern.coredump=0

# Enable Address Space Layout Randomization (ASLR) to mitigate certain types of attacks
kern.elf64.aslr.enable=1
kern.elf64.aslr.pie_enable=1

# Randomize PID assignment to make process prediction harder
kern.randompid=1

# Disable core dumps for setuid binaries to prevent exposure of sensitive information
kern.sugid_coredump=0

# Set securelevel to 1 to prevent certain changes to system state after boot
kern.securelevel=1

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

# Function to configure kernel security modules in loader.conf
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

# Function to set Blowfish password hashing, enforce password expiration, and configure umask
configure_password_and_umask() {
  echo "Configuring password security with Blowfish encryption and setting a secure umask..."

  # Configure Blowfish password encryption
  sed -i '' 's/passwd_format=sha512/passwd_format=blf/' /etc/login.conf

  # Configure password expiration if not disabled
  if [ "$password_expiration" != "no password expiration" ]; then
    sed -i '' "s/^default.*/&\n\t:passwordtime=$password_expiration:\\/" /etc/login.conf
  fi

  # Configure umask to 027 (disallow write for group, no permissions for others)
  sed -i '' 's/umask=022/umask=027/' /etc/login.conf

  # Rebuild login capabilities database (run this once after all changes)
  cap_mkdb /etc/login.conf

  # Warn user about the password reset
  echo "WARNING: The password for user $allowed_user will now be reset to ensure Blowfish encryption is applied."
  echo "You will need to enter a new password for $allowed_user."
  passwd "$allowed_user"
  echo "Password for $allowed_user has been reset with Blowfish encryption and the system umask is set to 027."
}

# Function to configure PF firewall for IPv4/IPv6 and SSH restrictions
configure_pf() {
  echo "Configuring the PF firewall to allow SSH access only for the specified IPs..."

  if [ "$admin_ips" = "any" ]; then
    # Allow SSH from any IP (discouraged)
    pf_rules="pass in proto tcp to any port $ssh_port keep state"
  else
    # Allow SSH only from specified admin IPs
    pf_rules="pass in proto tcp from { $admin_ips } to any port $ssh_port keep state"
  fi

  cat <<EOF >/etc/pf.conf
scrub in all
block in log all
set skip on lo
pass out inet all keep state
pass out inet6 all keep state
$pf_rules
block return in log all
EOF

  # Enable PF at next boot to avoid locking out the current SSH session
  sysrc pf_enable="YES"
  echo "PF firewall configured to enable at next reboot."
}

# Function to lock down sensitive files and restrict cron/at to root only
lock_down_system() {
  echo "Locking down critical system files and restricting cron and at jobs to root..."

  # Adjust file permissions first
  chmod o= /etc/ftpusers /etc/group /etc/hosts /etc/login.conf /etc/rc.conf /etc/ssh/sshd_config /etc/sysctl.conf /etc/crontab /usr/bin/at /var/log

  # Apply immutable flag to lock down system files
  chflags schg /etc/passwd /etc/group /etc/hosts /etc/pf.conf /etc/sysctl.conf /etc/rc.conf /boot/loader.conf /etc/fstab /etc/resolv.conf /etc/login.access /etc/newsyslog.conf

  # Restrict cron and at to root only
  echo "root" | tee /var/cron/allow /var/at/at.allow >/dev/null
  echo "System files locked down and cron/at restricted to root only."
}

# Function to automate weekly FreeBSD and pkg updates via cron, avoiding duplicates
configure_cron_updates() {
  echo "Setting up weekly automatic updates via cron..."

  # FreeBSD update cron job
  if ! grep -q "freebsd-update cron" /etc/crontab; then
    echo "0 3 * * 0 root freebsd-update cron" >>/etc/crontab
    echo "Added FreeBSD update cron job."
  else
    echo "FreeBSD update cron job already exists."
  fi

  # FreeBSD update install + pkg update/upgrade cron job
  if ! grep -q "freebsd-update install && pkg update && pkg upgrade -y" /etc/crontab; then
    echo "0 4 * * 0 root freebsd-update install && pkg update && pkg upgrade -y" >>/etc/crontab
    echo "Added FreeBSD update install and pkg upgrade cron job."
  else
    echo "FreeBSD update install and pkg upgrade cron job already exists."
  fi
}

# Function to disable syslogd network socket and clean /tmp on startup
secure_syslog_and_tmp() {
  echo "Securing syslog and configuring /tmp cleanup at startup..."
  sysrc syslogd_flags="-ss"
  service syslogd restart
  echo 'clear_tmp_enable="YES"' >>/etc/rc.conf
  echo "Syslog secured and /tmp will be cleared on startup."
}

# Function to log the hardening process and provide auditing
enable_logging() {
  echo "Logging the hardening process for auditing purposes..."
  exec >/var/log/harden-freebsd.log 2>&1
  echo "Logging enabled. Log file: /var/log/harden-freebsd.log"
}

# Main function to run all steps in order
main() {
  enable_logging
  backup_configs
  update_and_install_packages
  configure_ssh
  configure_sudo
  configure_fail2ban
  harden_sysctl
  harden_loader_conf
  configure_password_and_umask
  configure_pf
  lock_down_system
  configure_cron_updates
  secure_syslog_and_tmp
  echo "Security hardening complete. Please review configurations and reboot to apply all changes."
}

main
