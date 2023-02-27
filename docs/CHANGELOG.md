## [1.0.3] - Planned

### script net.ssh.backup.py
- backup Eltex MES device option
- (Restricted) marker for Cisco IOS-devices


## [1.0.2]

### module cf.py
- Command set (cset) for remote backup updated. Add different prompts for GaiaOS in regex


## [1.0.1]

### module cf.py
- function "convert_bytes" added
- function "net_backup_ssh_cset" added as universal ssh-cli backup function
- functions net_backup_ssh_cisco, net_backup_ssh_vyos, net_backup_ssh_gaia is deprecated and commented, will be removed in next release

### script net.ssh.backup.py
- size-check added for every backup file. If backup size is less than 512 bytes, backup marks as failed in log


## [1.0.0]

### Changed
- initial release