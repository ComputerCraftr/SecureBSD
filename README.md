# SecureBSD
FreeBSD security hardening script

## Repository Layout

- `securebsd.sh`: orchestration and system hardening workflow
- `ipfw.rules`: source ruleset that `securebsd.sh` customizes before installation
- `templates/awk/`: source-controlled awk transforms used by `securebsd.sh`
- `templates/config/`: source-controlled config templates rendered by `securebsd.sh`

The files under `templates/` are inputs to the script, not generated artifacts. Review and modify them directly when changing transform logic or generated config content.
