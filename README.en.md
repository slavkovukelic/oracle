# Oracle Linux Oracle Setup tool

## Overview

`oracle_setup.py` is a modernized CLI tool designed to prepare Oracle Linux 8 systems for Oracle Database and Fusion Middleware workloads. It allows you to tailor kernel parameters, system users, and directories according to Oracle recommendations. Alongside the adaptive Python workflow that calculates settings based on the current hardware, a "legacy" mode is also available that runs the original `oracle.sh` script for 100% compatible results.

## Installation

1. Install Python 3.10 or newer (the tool also supports Python 3.11+).
2. (Optional) Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies from `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

> Note: On Python versions earlier than 3.11 you need the `tomli` package to load the TOML configuration file.

## Usage

A basic invocation example (dry-run mode that does not apply changes):

```bash
python oracle_setup.py
```

If you want the changes to be applied to the system, add `--apply` and run the script as `root`.

## CLI options

All available CLI options can be combined as needed:

- `--oracle-user <name>` – defaults to `oracle`; the user whose limits and directories are prepared.
- `--apply` – when present, writes the calculated configuration to the system (requires root).
- `--fmw-user <name>` – defaults to `fmw`; an additional Fusion Middleware user.
- `--no-fmw` – disables creating/updating the Fusion Middleware user and directories.
- `--mode {adaptive,legacy}` – choose between the adaptive Python plan or the historical `oracle.sh` script.
- `--inspect` – compares the current system state with the planned configuration and shows mismatches.
- `--verbose` / `-v` – increases logging verbosity (repeat the option to reach debug level).
- `--log-file <path>` – writes logs to the specified file alongside console output.
- `--log-format {text,json}` – log format (defaults to `text`).
- `--output <path>` – stores the calculated plan in a JSON file (useful in dry-run mode).
- `--legacy-script <path>` – manually set the location of the `oracle.sh` script for legacy mode.
- `--config <path>` – read configuration from a TOML document (defaults to `oracle_setup.toml`).
- `--update-existing-users` – align existing system users with the settings from the configuration.
- `--repo-mode {system,local}` – choose whether the tool uses existing internet repositories (`system`) or temporarily replaces them with a local ISO/CD-ROM mirror (`local`).
- `--local-repo-root <path>` – path to the mounted Oracle Linux media when `--repo-mode=local` is active (defaults to `/INSTALL`).

## Example TOML configuration

The following example shows all sections supported by the tool. Each of them is optional except `[paths]`, which must be present:

```toml
[packages]
install = [
  "kmod-oracle",
  "oracle-database-preinstall-19c"
]

[[groups]]
name = "oinstall"
gid = 54321

[[groups]]
name = "dba"

[[users]]
name = "oracle"
primary_group = "oinstall"
supplementary_groups = ["dba"]
home = "/u01/app/oracle"
shell = "/bin/bash"
uid = 54321
create_home = true

[[users]]
name = "fmw"
primary_group = "oinstall"
supplementary_groups = ["dba"]
home = "/u01/app/fmw"
create_home = true

[paths]
data_root = "/u01"
profile_dir = "/etc/profile.d"
ora_inventory = "/u01/app/oraInventory"
oratab = "/etc/oratab"

[database]
target_version = "19c"
```

### Section reference

- `[packages]` – lists additional RPM packages that should be installed; the `install` field is an array of package names.
- `[[groups]]` – each entry defines a system group (name and optional `gid`).
- `[[users]]` – describes users (name, primary group, supplementary groups, home directory, optional `uid`, shell, and whether the home directory is created if missing).
- `[paths]` – defines key locations for Oracle software (`data_root`, `profile_dir`, `ora_inventory`, `oratab`).
- `[database]` – allows documenting the target database version (`target_version`) for inspection purposes.

## Legacy mode

When `--mode legacy` is set, the tool runs the original `oracle.sh` script. This is useful for commands that must replicate existing environments step by step. The script runs non-interactively and requires root privileges if changes are applied.

---

For more information review the `oracle_setup.py` source code and the default `oracle_setup.toml` configuration.
