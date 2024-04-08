## [1.0.4] - Planned

### script net.ssh.backup.py
- Huawei switch backup option
- (Restricted) marker for Cisco IOS-devices
- Zabbix and device info mapping in upper/lower case
- MD5 Hash checkup for backup files
- Single device's Backup File size in lines added as info in Backup Job log output


## [1.0.3] - Ready

### script net.ssh.backup.py
- Eltex MES devices backup option
- Cisco WLC backup option
- Backup file size threshold increased 512B -> 1KB (if backup size <1KB, fail alert will be generated)
- Device type info added in Backup Job log output

### module cf.py
- function "net_backup_ssh_cset" added page support while reading config (w/o pager)

### module cfzbx.py
- function "get_net_in_groups" added Eltex MES devices inventory support


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