% Trickanomicon
% Clemson CCDC 2024

# Competition Information

## Pre-Competition Checklist/General Knowledge Requirements

1.  NMAP installed on your local machine

2.  Minimal understanding of bash

## High-Level First 30 Minutes Plan

1.  Lead captain will do a ping sweep scan to see what's on the
    network + an rdp port scan to figure out which machines are windows.

2.  Machines get assigned to people (and this will be written down on a
    whiteboard that we can all see).

3.  Each person will nmap scan the machine they are assigned and give
    results in the appropriate channel.

    1.  Quick scan and save to a text file
        `a(){nmap -p- -T4 -Av -oN "nmap-$1.txt" $1};a <ip>`

4.  Each person will log into their machine and do user management stuff.

5.  Each person will do system hardening + firewalls for their machine.

6.  Each person will monitor their machine for activity from there on out unless they're helping with an inject.

# Linux

**Do not touch the** `seccdc_black` **account**

## 30 Minute Plan

1.  NMAP Scan Machine in background

2.  Rotate all ssh keys

    1.  Populate the machines with the ssh key from lead linux captain

    2.  Deploy with `ssh-copy-id -i <file> <user@host>`

    3.  Ensure there is only one entry (one line) in `~/.ssh/authorized_keys`. If there are more than one, remove all lines EXCEPT the very last one. After saving, make sure you can still SSH by trying on a NEW terminal.

    4.  Remove all other authorized keys files with
        `find / -name authorized_keys`

3.  Check local accounts and reset password **ASAP** using appropriate one liners from [Duncan's Magic](#dmagic)

4.  Lock unnecessary accounts with `usermod -L <login>` and if nothing goes red, delete account with `userdel <login>`. Or use appropriate one liners from [Duncan's Magic](#dmagic) to lock accounts

    1.  **NOTE**: user home directories were intentionally not deleted with the `userdel` command with the idea of possible needing that data for future injects (you never know).
	If you absolutely need to remove extraneous user home directories, seek approval from the team captain before proceeding with the command `userdel -r <login>`

5.  Find listening services with `ss -tunlp` and investigate strange ones

## Monitoring

1.  View all network connections `ss -tunlp`

2.  View listening programs with `ss -lp`

3.  View only connections with `ss -tu`

4.  View active processes `ps -e`

5.  Continuously see processes with `top`

    1.  Sort by different categories with `<` and
        `>`

    2.  Tree view with `V`

6.  Watch **all** network traffic with the following (this is a fire
    hose)

    1.  Record inbound traffic with
        `iptables -I INPUT -j LOG`

    2.  Record outbound traffic with
        `iptables -I OUTPUT -j LOG`

    3.  Watch logs with
        `journalctl -kf –grep="OUT=.*"`

7.  Watch dbus with `dbus -w`

## System Utilities

1.  Start and stop processes with `systemctl`

    1.  Start service with
        `systemctl start <unit>`

    2.  Stop service with
        `systemctl stop <unit>`

    3.  Restart service with
        `systemctl restart <unit>`

    4.  Enable service with
        `systemctl enable <unit>`

2.  Permit and allow network connections with
    `iptables`

    1.  Default deny with `iptables -P INPUT DROP`

    2.  Allow port access (must choose tcp or udp)
		`iptables -A INPUT -p <tcp|udp> –dport <port> -j ACCEPT`

    4.  Allow all from interface `iptables -A INPUT -i <interface> -j ACCEPT`

3.  Schedule tasks with cron

    1.  View with `crontab -eu <user>`

    2.  Obliterate user's crontab with `crontab -ru <user>`

    3.  See [Duncan's Magic](#dmagic) for a one liner to remove crontabs from a list of users. Don't forget to remove
        the root user's crontab too!

4.  View networking information with `ip`

    1.  View network interfaces with `ip l`

        1.  Interfaces are prefixed with an `en`
            to signify ethernet, `wl` to signify
            wireless, and `v` to signify a
            virtual link

        2.  Virtual links should be investigated, as they are commonly
            used for VPNs, docker, and nonsense

        3.  Virtual servers will still show their main link to the host
            as ethernet

    2.  View IP Addresses with `ip a` and take
        note of additional addresses

## Configurations

1.  SSH Daemon configs are in `/etc/ssh/sshd_config` and should be set as follows
```
PermitRootLogin prohibit-password
UsePAM no
PasswordAuthentication yes
PermitEmptyPasswords no
```

2.  File system configs are in `/etc/fstab`

    1.  Network File Shares are in the form
        `/srv/home hostname1(rw,sync,no_subtree_check)`
        These allow sharing file systems over the network. They must be reviewed to ensure we are not sharing information with attackers

## Hunting

1.  List all files with creation date, most recent first:
    `find /usr /bin /etc \`
    `/var -type f -exec stat -c "%W %n" {} + | sort -r > files`

2.  List all files created after set date, most recent first:
    `find /usr /bin /etc /var -type f -newermt <YYYY-MM-DD> -exec \`
    `stat -c "%W %n" {} + | sort -rn > files`

## Duncan's Magic {#dmagic}

1.  Remove users listed in **./disable.txt**
    `while read user;do sudo usermod -L $user;done<disable.txt`

2.  Generate new passwords for every user in **./users.txt**. Output format and filename as specified by SECCDC-2024 password reset guidelines. Ensure team number is correct and SERVICE is changed to match the corresponding service the passwords are being reset for.
    `s='<service>'; while read u; do u=‘echo $u|tr -d ' '‘; \` 
    `p=‘tr -dc 'A-Za-z0-9!@#$%'</dev/urandom|head -c 24; echo‘; \` 
    `echo $s,$u,$p; done < users.txt > Team25_${s}_PWD.csv`

3.  Actually reset passwords using the generated list from the command immediately preceeding this
    `awk -F, '{print $2":"$3}' <file.csv> | sudo chpasswd`

4.  Find users not in **./known_users.txt** 
    `awk -F: '{if($3>=1000&&$3<=60000){print $1}}' /etc/passwd| \` 
    `sort - known_users.txt | uniq -u > extra_users.txt`

5.  Remove crontabs from list of users in **./users.txt** 
    `while read u; do sudo crontab -u $u -r; done < users.txt`

## Hardening

You should remount /tmp and /var/tmp to be non-executable.

1.  If /tmp and /var/tmp are already mounted, you can simply do: 
    `mount -o remount,nodev,nosuid,noexec /tmp`
    `mount -o remount,nodev,nosuid,noexec /var/tmp `

2.  If they haven't already been mounted, edit /etc/fstab to include: 
    `tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777 0 0`
    `tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777 0 0 `

3.  Once /etc/fstab has been updated, you can run: 
    `mount -o nodev,nosuid,noexec /tmp`
    `mount -o nodev,nosuid,noexec /var/tmp `

## Disaster Recovery

1.  Service goes down

    1.  Determine the service

    2.  Find errors in logs with `sudo journalctl -xe <service>`

    3.  If it is a configuration error, restore previous config or manually reset

    4.  If the service is still down **alert the team**

    5.  Try restarting: `sudo systemctl restart <service>`

2.  Loosing access to a box

    1.  **Alert the team**

    2.  Start nmap scan

    3.  Try verbose ssh `ssh -v <user>@<ip>`

## Logging with auditd

Setup auditd for logging purposes

1.  Make sure auditd daemon is enabled and running

    1.  `sudo systemctl enable –now auditd`

2.  After auditd has been started, add rules to
    `/etc/audit/rules.d/audit.rules`. You will
    need `sudo` permissions to edit this file.

    1.  Visit this masterful auditd github
        repo(https://github.com/Neo23x0/auditd/blob/master/audit.rules)
        for a wide variety of auditd rules to copy / imitate.

3.  Restart auditd to apply these new rules

    1.  `sudo systemctl restart auditd`

Looking at auditd alerts

1.  Logs are stored in `/var/log/audit/audit.log`

    1.  You can use `ausearch` to query this log

    2.  `aureport` can also be used to generate a
        list of events

2.  Important takeaways when analyzing auditd logs

    1.  euid = effective user id. Pay attention if EUID field is 0 as
        this means a file or program was run as root

    2.  exe field indicates which command was run (if one was run at
        all)

    3.  key field stores the name of the alert that was triggered

    4.  pid field stores the process id

3.  Utilize the various fields, timestamps, and
    `ausearch` and
    `aureport` tools to observe, report, and take
    action on suspicious activity

# Windows

**Do not touch the** `seccdc_black` **account.**

## Security Checklist

**NOTE: If you are in an AD environment, see [Active Directory Considerations](#active-directory-considerations)**

1.  Conduct network discovery on machine and note which ports should be accessible.
    1.  If available, run an Nmap scan on your machine.
    2.  If unavailable, you can use `netstat -aonb`.

2. Change your account password to a known password and create an authorized_keys file for your user with the SSH key given to you.

3. Create a new user on the system with a username that mimics a system account (example: "Default").
   Set the password to a known password and create an authorized_keys file for the user with the SSH key given to you.

``` powershell
# creating a local user named Default and adding them to Administrators
new-localuser "Default"
add-localgroupmember -group "Administrators" -Member "Default"

# creating a domain user named Default to the Domain Administrators group
new-aduser "Default"
add-adgroupmember -Identity "Domain Admins" -Members "Default"
```

4. Generate account passwords for authorized users with [one-liner](#windows-one-liners) and store off the machine. **Wait to reset passwords until directed by captain.** 

5. Disable unauthorized user accounts **except your own, seccdc_black, and any needed service accounts** with [one-liner](#windows-one-liners).

6. **FOR PRIMARY DC ONLY** Audit members of `Domain Admins` and `Enterprise Admins` groups with [one-liner](#windows-one-liners).

7. Find and remove authorized SSH keys. Keys are typically stored in `<USERDIR>/.ssh/authorized_keys or C:\ProgramData\ssh\administrators_authorized_keys`.
``` powershell
# search for keys on the entire disk
dir C:\ -Force -Recurse -Filter "*authorized_keys"

# check ssh config in C:\ProgramData\ssh\ and remove any entries for additional key locations
type C:\Program Files\OpenSSH\sshd_config
```

8.  After network discovery completes, configure Firewall.
    **NOTE: Rules SHOULD specify applications AND source/destination IPs.
    Do this via the GUI after rules are made.**

    1.  Export current firewall policy.  
        `netsh advfirewall export "C:\rules.wfw"`

    2.  Disable firewall.  
        `netsh advfirewall set allprofiles state off`

    3.  Flush inbound/outbound rules.  
        `Remove-NetFirewallRule`

    4.  Allow RDP (C:\Windows\System32\svchost.exe 3389 TCP), SSH (C:\<PATH TO SSH DIR>\sshd.exe 22 TCP), and scored service.
``` powershell
$port = <PORT>; New-NetFirewallRule -DisplayName "Inbound $port" `
-Direction Inbound -LocalPort $port -Protocol TCP `
-Action Allow -Program "Path\To\Executable"
```

    5.  Configure outbound rules as needed (DNS: 53 TCP/UDP, HTTP: 80,443 TCP).
``` powershell
$port = <PORT>; New-NetFirewallRule -DisplayName "Outbound $port" `
-Direction Outbound -RemotePort $port -Protocol TCP `
-Action Allow -Program "Path\To\Executable"
```

    6.  Re-enable firewall to block inbound and outbound.
``` powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall set allprofiles state on
```

    7. Enable firewall logging for all profiles:
``` powershell
set allprofiles logging allowedconnections enable
set allprofiles logging droppedconnections enable
```

9. Proceed to [System Hardening](#hardening-1)
   
## Windows One-Liners

1.  Generate CSV file with passwords and send to captain:
``` powershell
$upper = ([char]'A'..[char]'Z');
$lower = ([char]'a'..[char]'z');
$special = ([char]'#'..[char]'&');

function generate-password {
	$secret = -join ($upper + $lower + $special | get-random -Count 24 | foreach {[char]$_});
    return $secret;
}

get-content "users.txt" | foreach {
    do {
        $secret = generate-password;
    } while (($secret.IndexOfAny($upper) -eq -1) -or ($secret.IndexOfAny($lower) -eq -1) -or ($secret.IndexOfAny($special) -eq -1))
	add-content "$(hostname).csv" "$(hostname),$_,$secret"
}
```
2.  Reset Passwords based on generated password CSV file:

Local Machine:
``` powershell
import-csv "$(hostname).csv" -Header "host","user","pass" |
foreach {net user $_.user $_.pass};
del "$(hostname).csv"
```

Domain Controller:
``` powershell
import-csv "$(hostname).csv" -Header "host","user","pass" |
foreach {net user $_.user $_.pass /domain};
del "$(hostname).csv"
```

3.  Audit accounts on system based on list of expected users:

Local Machine (Unauthorized Users):
``` powershell
$expected = get-content "users.txt";
$expected += $env:Username, "seccdc_black"
get-localuser | foreach {
	if ($_.Name -notin $expected) {
		echo $_.Name; add-content "unexpected.txt" $_.Name
	}
}
```

Domain Controller (Unuauthorized Users):
``` powershell
$expected = get-content "users.txt";
$expected += $env:Username, "seccdc_black", "krbtgt"
get-aduser -Filter * | foreach {
	if ($_.Name -notin $expected) {
		echo $_.Name; add-content "unexpected.txt" $_.Name
	}
}

Domain Controller (Unuauthorized Domain Admins):
``` powershell
$expected = get-content "admins.txt";
$admins = get-adgroupmember -filter "Domain Admins" | select-object -expandproperty name;
foreach ($admin in $admins) {
	if ($admin -notin $expected) {
		echo $admin; add-content "unexpected.txt" $admin
	}
}
```

Domain Controller (Unuauthorized Enterprise Admins):
``` powershell
$expected = get-content "admins.txt";
$admins = get-adgroupmember -filter "Enterprise Admins" | select-object -expandproperty name;
foreach ($admin in $admins) {
	if ($admin -notin $expected) {
		echo $admin; add-content "unexpected.txt" $admin
	}
}
```

4.  Disable unauthorized accounts:

Local Machine:
``` powershell
get-content "unexpected.txt" | foreach {net user $_ /active:no}
```

Domain Machine:
``` powershell
get-content "unexpected.txt" | foreach {net user $_ /active:no /domain}
```

## Helpful Utilities

**NOTE** If using powershell to curl, you will need to run the following to enable TLS:  
`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`

1.  For package management (Scoop):
``` powershell
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

## Hardening

1.  Service Management:

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

    4.  Harden the scored service for your machine according to the
        documentation [below](#Services). **If on a DC, skip to Group Policy.**

2.  Group Policy **(done via DC ONLY)**:

    1.  Hardening Policy
        1.  Firewall:
            1.  Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Firewall: Automatic
            2.  Computer Configuration > Policies > Administrative Templates > Network > Network Connections > Windows Defender > Firewall > Domain Profile > Protect all network connections: Enabled
            3.  Computer Configuration > Windows Settings > Security Settings > Windows Firewall with Advanced Security > Firewall State
                1.  Turn on for all profiles and block inbound/outbound traffic.
            4.  Time permitting, create explicit rules to block outbound connections from regsvr32, rundll, cmd, and powershell.
    2.  Audit Policy
        1.  Powershell Block/Module Logging: `Administrative Templates > Windows Components > Windows Powershell`
    3.  After policy has been configured, run `gpupdate /force` to replicate the policy to other machines.
   
3.  ACLs:
   1.  AccessEnum can be used to search for misconfigured ACLs. Check sensitive registry keys/directories.
```
Examples:
C:\Windows\System32
HKLM\SYSTEM\CurrentControlSet\Services
```

## Monitoring

1.  View incoming network connections with `netstat -of`. For a GUI view, use TCPView.

2.  View running processes in the details pane of Task Manager, via Process Explorer, or with `tasklist`. Kill a process with `taskkill /f /pid <PID>`.
    1.  Find information about a running process with `wmic process where '(processid=<PID>)' get 'processid,parentprocessid,executablepath'`.

3.  View all shares with `net share` and connected Named Pipes / Shares with `net use`.

4.  Viewing logons:
    1.  Can view logged on user applications with `get-process -includeusername | ? {$_.ProcessName -like "rdpclip" -or $_.ProcessName -like "sshd"}`
   
5.  View all connected RDP sessions with `qwinsta` and kill sessions with `rwinsta <SESSION ID>`.

## Logging

1.  For more insight into system activity, configure Sysmon with [this config](https://raw.githubusercontent.com/D42H5/cyber_comp_resources/main/sysmonconfig-export-modified-2-2-24.xml).

    1.  To install Sysmon, run `sysmon -i <PATH TO CONFIG FILE>`.

    2.  Logs are sent to Applications and Services Logs > Microsoft > Windows > Sysmon.

    3.  If you want to update your config file, run `sysmon -c <PATH TO NEW CONFIG>`.

2.  You can view system events locally with the Event Viewer or Nirsoft's [EventLogViewer](https://www.nirsoft.net/utils/fulleventlogview-x64.zip).

    1.  You can filter down events to Sysmon*, Powershell*, and Security.

## Persistence

1.  Run a system scan with one of the antivirus solutions listed in [helpful tools](#helpful-tools).

2.  Scheduled Tasks, Services, and registry keys should be checked for persistence. The Autoruns utility can be used to find potential persistence mechanisms.

* Run Keys & Startup Folder
```
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\

\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\ 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\
```

* AppCert DLLs
    - Loaded into any process that calls CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, WinExec
```
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager
```

* AppInit DLLs
    - Loaded by every process that uses user32.dll (almost all). Disabled in Windows 8+ if secure boot is enabled.
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
```

* Component Object Model (COM) Hijacking
    - User objects in this key will override machine objects in HKLM.
```
HKEY_CURRENT_USER\Software\Classes\CLSID\
```

* Netsh Helper DLLs
    - Executes helper DLLs when executed which are registered at this key.
```
HKLM\SOFTWARE\Microsoft\Netsh
```

* Port Monitors
    - Should only contain Appmon, Local Port, Microsoft Shared Fax Monitor, Standard TCP/IP Port, USB Monitor, WSD Port. Can be used to load arbitrary DLLs at startup, will run as SYSTEM.
```
HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors
```

* Screensavers
     - More than just bubbles and ribbons. Check SCRNSAVE.exe, make sure ScreenSaveIsSecure == 1.
```
HKCU\Control Panel\Desktop\
```

* Security Support Provider (SSP) DLLs
    - Loaded into LSA at startup or when AddSecurityPackage is called. Let's red team see plaintext creds.
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
```
On Windows 8.1 & Server 2012R2, change AuditLevel to 8 to to require SSP DLLs to be signed.
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe
```

* Password Filters
    - Used to harvest creds anytime a password is changed. Should only contain sceli & rassfm as notification Packages.
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification 
```

* Winlogon Helper DLL
    - Handles actions at logon/logoff.
```
HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
...\\Winlogon\Notify
...\\Winlogon\Userinit
...\\Winlogon\Shell
```

* Services
    - Service configuration info is stored in keys in this folder. Monitor and inspect as needed.
```
HKLM\SYSTEM\CurrentControlSet\Services
```

* Scheduled Tasks
    - Scheduled task configuration info is stored in keys in these folders. Monitor and inspect as needed.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree\
```

### Common Backdoors
* Sticky keys
* Web shells
* Malicious accounts
* Golden ticket 
* Keylogger
* Packages

### Services
* Look for new services
* Query services not on services.msc
* Stop remote management services

### Accounts, Groups, Permissions
* Accounts in admin groups
* New accounts
* Changing password to existing accounts

### Event Logs
* Sysmon

### Network Connections
* Firewall log in %System32%\LogFiles\Firewall
* Check that firewall config hasn't changed
* netstat -fo to listen for new connections

3. You can scan the system for unsigned dlls with `listdlls -u`

## Active Directory Considerations

### Firewall

The below ports are needed for Active Directory to operate:

```
Domain Controller:
- Inbound:
    53 UDP: DNS
    88 TCP/UDP: Kerberos
    123 TCP: NTP
    135 TCP: NetBIOS
    138,139 TCP/UDP: File Replication
    389,636 TCP: LDAP & LDAPS
    445 TCP: SMB
    464 TCP: Kerberos password change
    49152,49153 TCP: RPC*
    3268,3269 TCP: Global Catalog LDAP & LDAPS
- Outbound:
    445 TCP: SMB
    49152,49153 TCP: RPC*

Domain Member:
- Inbound:
    445 TCP: SMB
- Outbound:
    53 UDP: DNS
    123 TCP: NTP
    135 TCP: NetBIOS
    138,139 TCP/UDP: File Replication
    389,636 TCP: LDAP & LDAPS
    445 TCP: SMB
    49152,49153 TCP: RPC*

*This is assuming you have defined 49152 and 49153 as fixed RPC ports (see below).
```

RPC typically uses a large range of ports to establish ephemeral connections. You can restrict this by using the following one-liners:

``` powershell
# sets RPC to 49152 and 49153; this requires a server restart to take effect
reg add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v "TCP/IP Port" /t REG_DWORD /d 49152

reg add HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v "DCTcpipPort" /t REG_DWORD /d 49153
```

The following script can be used as a guideline to help generate rules for you:

``` powershell
$members = get-adcomputer -filter * -properties IPv4Address | select-object -ExpandProperties IPv4Address;

$tcpports = 53,88,123,135,138,139,389,636,445,464,3268,3269,49152,49153;
foreach ($p in $tcpports) {
    New-NetFirewallRule -DisplayName "DC $p TCP IN" `
    -LocalPort $p -Protocol TCP `
    -Action Allow -Direction Inbound -RemoteAddress $members;
    New-NetFirewallRule -DisplayName "DC $p TCP OUT" `
    -LocalPort $p -Protocol TCP `
    -Action Allow -Direction Outbound -RemoteAddress $members;
}

$udpports = 53,88,139,139;
foreach ($p in $udpports) {
    New-NetFirewallRule -DisplayName "DC $p UDP IN" `
    -LocalPort $p -Protocol UDP `
    -Action Allow -Direction Inbound -RemoteAddress $members;
    New-NetFirewallRule -DisplayName "DC $p UDP OUT" `
    -LocalPort $p -Protocol UDP `
    -Action Allow -Direction Outbound -RemoteAddress $members;
}

```

### Hardening

1.  The krbtgt password should be reset with this [password reset script](https://github.com/microsoft/New-KrbtgtKeys.ps1).

2.  Audit domain groups for odd membership. Machine accounts can be exploited.

3.  You can force a reset of domain group policy with the below commands:
```
dcgpofix /target:both
gpupdate /force
```

## Powershell

### Basic Syntax

for

select-object

where-object {$_}

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

Output event logs for all Domain Admins to a csv file.
```powershell
get-localgroupmember Administrators | foreach {get-eventlog system -username $_.Name | export-csv “logs.csv”}
```

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
