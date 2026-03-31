# CIS Hardening Toolkit

Automated security hardening scripts based on CIS Benchmarks for Linux (Ubuntu/Debian) and Windows Server.

Built for Purple Team workflows — harden first, then validate detection.

---

## Overview

This toolkit automates key CIS Benchmark controls across four domains:

| Domain | Linux | Windows |
|---|---|---|
| SSH Hardening | `linux/ssh_hardening.sh` | N/A (WinRM/RDP policies) |
| Firewall | `linux/firewall_hardening.sh` | `windows/firewall_hardening.ps1` |
| User and Password Policies | `linux/user_policy_hardening.sh` | `windows/user_policy_hardening.ps1` |
| Audit and Logging | `linux/audit_hardening.sh` | `windows/audit_hardening.ps1` |
| Full Audit (check-only) | `linux/cis_audit.sh` | `windows/cis_audit.ps1` |

## Important

- Always test in a lab or staging environment first
- Scripts create backups before making changes (in `/var/backup/cis-hardening/` or `C:\CIS-Backup\`)
- Use `--audit` / `-Audit` mode to check compliance without making changes
- Review generated reports before applying fixes

## Quick Start

### Linux (Ubuntu/Debian)

```bash
git clone https://github.com/thelema-froxward/cis-hardening-toolkit.git
cd cis-hardening-toolkit/linux

sudo bash cis_audit.sh

sudo bash ssh_hardening.sh
sudo bash firewall_hardening.sh
sudo bash user_policy_hardening.sh
sudo bash audit_hardening.sh
```

### Windows Server

```powershell
git clone https://github.com/thelema-froxward/cis-hardening-toolkit.git
cd cis-hardening-toolkit\windows

.\cis_audit.ps1 -Audit

.\firewall_hardening.ps1
.\user_policy_hardening.ps1
.\audit_hardening.ps1
```

## CIS Benchmark Mapping

Each script maps to specific CIS Benchmark sections. Full mapping is documented in [`docs/CIS_MAPPING.md`](docs/CIS_MAPPING.md).

## Integration with Wazuh

These scripts pair with [wazuh-protection-with-telegram-alerts](https://github.com/thelema-froxward/wazuh-protection-with-telegram-alerts) — harden the system, then use Wazuh SCA to continuously monitor compliance.

## Project Structure

```
cis-hardening-toolkit/
├── linux/
│   ├── ssh_hardening.sh
│   ├── firewall_hardening.sh
│   ├── user_policy_hardening.sh
│   ├── audit_hardening.sh
│   └── cis_audit.sh
├── windows/
│   ├── firewall_hardening.ps1
│   ├── user_policy_hardening.ps1
│   ├── audit_hardening.ps1
│   └── cis_audit.ps1
├── docs/
│   ├── CIS_MAPPING.md
│   └── CHANGELOG.md
├── LICENSE
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE) for details.
