# SecureBSD
FreeBSD security hardening script

## Repository Layout

- `securebsd.sh`: orchestration and system hardening workflow
- `ipfw.rules`: source ruleset that `securebsd.sh` customizes before installation
- `templates/awk/`: source-controlled awk transforms used by `securebsd.sh`
- `templates/config/`: source-controlled config templates rendered by `securebsd.sh`

The files under `templates/` are inputs to the script, not generated artifacts. Review and modify them directly when changing transform logic or generated config content.

## What This Script Does

`securebsd.sh` hardens a FreeBSD host while trying to avoid remote lockout during SSH, sudo, and firewall changes.

At a high level it:

- prepares a replacement admin path based on SSH public keys, TOTP, and `%sudo`
- stages SSH hardening instead of switching everything at once
- manages firewall boot policy through `ipfw`, `rc.conf`, `loader.conf`, and Suricata-related config
- defers risky cleanup such as `%wheel` sudo removal until the replacement admin path has been validated

## Safety Model

The script is intentionally conservative around lockout-sensitive changes.

- it fails closed if saved state, live state, and requested CLI state do not agree
- it does not try to guess a safe live firewall recovery when active `ipfw` state has drifted
- it does not replace the live firewall in-place during SSH port migration
- SSH port changes are slower on purpose because avoiding remote lockout takes priority over doing everything in one run

Boot firewall policy and runtime firewall state are treated separately:

- boot policy is managed and validated even if runtime `ipfw` is currently inactive
- loaded runtime `ipfw` must match the expected managed state or the script blocks fast-path changes

## Typical Workflow

On a first hardening run, the script generally:

1. prepares SSH keys, TOTP, sudo access, and other baseline changes
2. reloads a transitional SSH configuration and asks you to verify a fresh login
3. reloads strict SSH, writes managed firewall boot policy, and asks you to verify a fresh pubkey+TOTP login
4. only after that final validation, removes deferred wheel fallback policy if you requested it

On later reruns, the script can safely reapply baseline settings on an already-committed host. If you request an SSH port change, it uses a slower staged port-migration flow instead of treating it like a normal baseline reapply.

For managed reruns, keep cutover-defining CLI separate from ordinary maintenance:

- ordinary managed baseline reapply should omit `--user`, `--ssh-port`, `--disable-wheel`, and `--remove-wheel-members`
- the one exception is a committed host SSH port change: a changed `--ssh-port` switches the run into staged SSH port migration
- pending managed cutovers do not accept cutover-defining CLI, even if the values match the saved state
- stale or incomplete managed state does not accept cutover-defining CLI in the same run; resolve or intentionally abandon that state first

## Cutover States

Internally, `securebsd.sh` uses an explicit staged cutover model instead of treating all reruns as interchangeable baseline reapply operations.

- `pending_transitional_verify`: transitional SSH profile is live and must be verified through a fresh login before strict SSH is applied
- `pending_strict_verify`: strict SSH and firewall boot policy are written, but the host is not considered committed until a fresh pubkey+TOTP login is externally verified
- `pending_port_transition_reboot`: SSH port migration stage 1 is written; boot policy allows both old and new SSH ports and requires a reboot plus fresh login on the new port
- `pending_port_commit_reboot`: SSH port migration stage 2 is written; boot policy allows only the new SSH port and requires a second reboot plus fresh login
- `committed_strict_ready`: strict SSH/firewall state is externally verified and may still have deferred wheel-policy cleanup pending

The saved cutover state is tracked in `/var/db/securebsd/admin_cutover.state`. The authoritative progress field is `cutover_stage`; older coarse booleans are no longer used.

## SSH And Firewall Policy

The script treats SSH and firewall policy as the main lockout risk.

- `ssh_port` is cutover-defining
- changing `--ssh-port` on a committed host enters a staged port-migration flow instead of a generic fast-path reapply
- matching `--ssh-port` is not used as a harmless no-op on managed reruns; omit it unless you are intentionally starting a committed-host port migration
- SSH port migration is reboot-gated when managed firewall boot policy is involved
- the script does not live-run the flushed `/etc/ipfw.rules` script during SSH port cutover
- runtime `ipfw` may be absent, but if it is loaded it must match the expected staged policy or the script fails closed

During a port migration:

- stage 1 writes dual-port `sshd` and dual-port firewall boot policy
- stage 2 writes new-port-only `sshd` and new-port-only firewall boot policy
- stage 3 finalizes the migration after the second verified reboot/login

The managed `ipfw` template in this repo is treated as a source template. `securebsd.sh` renders and installs `/etc/ipfw.rules`; it does not rewrite the repo copy in place.

## Wheel Policy

The script can temporarily keep wheel-based fallback access in place while it proves the replacement admin path works. It only removes that fallback after final admin-path validation succeeds.

Deferred admin fallback cleanup is tracked explicitly and independently:

- `disable_wheel`: disable `%wheel` sudo access after final admin-path validation
- `remove_wheel_members`: remove non-root wheel members after final admin-path validation

These are persisted separately from their completion state:

- `wheel_sudo_finalized`
- `wheel_membership_finalized`

That means a host can be in a committed strict SSH/firewall state while still intentionally waiting to finalize one or both wheel-policy changes.

## Suricata And `ipfw`

If Suricata is enabled, its SSH awareness is kept aligned with the same staged SSH port set used by `sshd` and `ipfw`.

- `suricata.yaml` `SSH_PORTS`
- the managed custom SSH rule (`sid:1000001`)
- the managed `ipfw` divert rule

On validation, the script checks staged boot policy and active runtime policy separately:

- boot policy must match the managed loader, `rc.conf`, `/etc/ipfw.rules`, and Suricata state
- loaded runtime `ipfw` must match the expected staged SSH and divert/NAT rule shape
- unloaded runtime `ipfw` is not auto-corrected live and does not by itself force a fresh cutover
