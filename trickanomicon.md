% Trickanomicon
% Clemson CCDC 2024

# Competition Information

## Pre-Competition Checklist/General Knowledge Requirements

1.  NMAP installed on your local machine

2.  Minimal understanding of bash

## High-Level First 30 Minutes Plan

1.  Lead captain will do a ping sweep scan to see what's on the
    network + an rdp port scan to figure out which machines are windows

2.  Machines get assigned to people (and this will be written down on a
    whiteboard that we can all see)

3.  Each person will nmap scan the machine they are assigned and give
    results in the appropriate channel

    1.  [Quick scan and save to a text file]{#nmap} \
        `a(){nmap -p- -T4 -Av -oN "nmap-$1.txt" $1};a <ip>`

4.  Each person will log into their machine and do user management stuff

5.  Each person will do system hardening + firewalls (or let firewall
    guru do their thing) for their machine

6.  Each person will monitor their machine for activity from there on
    out unless they're helping with an inject

# Linux

**Do not touch the** `seccdc_black` **account**

## 30 Minute Plan

1.  [NMAP Scan Machine](#nmap) in background

2.  Rotate all ssh keys

    1.  Populate the machines with the ssh key from lead linux captain

    2.  Deploy with `ssh-copy-id -i <file> <user@host>`

    3.  Ensure there is only one entry (one line) in `~/.ssh/authorized_keys`. If there are more than one, remove all lines EXCEPT the very last one. After saving, make sure you can still SSH by trying on a NEW terminal.

    4.  Remove all other authorized keys files with
        `find / -name authorized_keys`

3.  Check local accounts and reset password **ASAP** using appropriate one liners from [Duncan's Magic](#dmagic)

4.  Lock unnecessary accounts with `usermod -L <login>` and if nothing goes red, delete account with `userdel <login>`. Or use appropriate one liners from [Duncan's Magic](#dmagic) to lock accounts

    1.  **NOTE**: user home directories were intentionally not deleted with the `userdel` command with the idea of possible needing that data for future injects (you never know). \
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

    2.  Allow port access (must choose tcp or udp) \
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

    1.  Network File Shares are in the form \
        `/srv/home hostname1(rw,sync,no_subtree_check)` \
        These allow sharing file systems over the network. They must be reviewed to ensure we are not sharing information with attackers

## Hunting

1.  List all files with creation date, most recent first:
    `find /usr /bin /etc \` \
    `/var -type f -exec stat -c "%W %n" {} + | sort -r > files`

2.  List all files created after set date, most recent first: \
    `find /usr /bin /etc /var -type f -newermt <YYYY-MM-DD> -exec \` \
    `stat -c "%W %n" {} + | sort -rn > files`

## Duncan's Magic {#dmagic}

1.  Remove users listed in **./disable.txt**\
    `while read user;do sudo usermod -L $user;done<disable.txt`

2.  Generate new passwords for every user in **./users.txt**. Output format and filename as specified by SECCDC-2024 password reset guidelines. Ensure team number is correct and SERVICE is changed to match the corresponding service the passwords are being reset for.\
    `s='<service>'; while read u; do u=‘echo $u|tr -d ' '‘; \` \
    `p=‘tr -dc 'A-Za-z0-9!@#$%'</dev/urandom|head -c 24; echo‘; \` \
    `echo $s,$u,$p; done < users.txt > Team25_${s}_PWD.csv`

3.  Actually reset passwords using the generated list from the command immediately preceeding this\
    `awk -F, '{print $2":"$3}' <file.csv> | sudo chpasswd`

4.  Find users not in **./known_users.txt** \
    `awk -F: '{if($3>=1000&&$3<=60000){print $1}}' /etc/passwd| \` \
    `sort - known_users.txt | uniq -u > extra_users.txt`

5.  Remove crontabs from list of users in **./users.txt** \
    `while read u; do sudo crontab -u $u -r; done < users.txt`

## Hardening

You should remount /tmp and /var/tmp to be non-executable.

1.  If /tmp and /var/tmp are already mounted, you can simply do: \
    `mount -o remount,nodev,nosuid,noexec /tmp`\
    `mount -o remount,nodev,nosuid,noexec /var/tmp `

2.  If they haven't already been mounted, edit /etc/fstab to include: \
    `tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777 0 0`\
    `tmpfs /var/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777 0 0 `

3.  Once /etc/fstab has been updated, you can run: \
    `mount -o nodev,nosuid,noexec /tmp`\
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

    2.  [Start nmap scan](#nmap)

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

## 30 Minute Plan

1.  Download Sysinternals
    Suite(https://download.sysinternals.com/files/SysinternalsSuite.zip).

2.  Perform an Nmap scan on machine and note which ports should be
    accessible.

3.  Run/Download the following:\
    `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`

    1.  [Sysinternals
        Suite](https://download.sysinternals.com/files/SysinternalsSuite.zip),
        [Sysmon
        Config](https://raw.githubusercontent.com/D42H5/cyber_comp_resources/main/sysmonconfig-export-modified-2-2-24.xml),
        [EventLogViewer](https://www.nirsoft.net/utils/fulleventlogview-x64.zip)

    2.  [Malwarebytes](https://downloads.malwarebytes.com/file/mb-windows)
        and
        [BLUESPAWN](https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe)

4.  Change authorized account passwords **including your own** with
    [one-liner](#woliner).

5.  Disable unauthorized user accounts **except your own and
    seccdc_black** with [one-liner](#woliner).

6.  Find and remove authorized SSH keys.
    `dir C:\ -Recurse | findstr "authorized_keys"`

7.  Once Nmap scan completes, configure Firewall.\
    **NOTE: Rules SHOULD specify applications AND source/destination
    IPs.\
    Do this via the GUI after rules are made.**

    1.  Export current firewall policy.\
        `netsh advfirewall export "C:\rules.wfw"`

    2.  Disable firewall.\
        `netsh advfirewall set allprofiles state off`

    3.  Flush inbound/outbound rules.\
        `Remove-NetFirewallRule`

    4.  Allow RDP (svchost.exe 3389 TCP), SSH (sshd.exe 22 TCP), and
        scored service.\
        `$port = <PORT>; New-NetFirewallRule -DisplayName "Inbound $port" ‘`\
        `-Direction Inbound -LocalPort $port -Protocol TCP ‘`\
        `-Action Allow -Program "Path\To\Executable"`

    5.  Configure outbound rules as needed (DNS: 53 TCP/UDP, HTTP:
        80,443 TCP).\
        `$port = <PORT>; New-NetFirewallRule -DisplayName "Outbound $port" ‘`\
        `-Direction Outbound -RemotePort $port -Protocol TCP ‘`\
        `-Action Allow -Program "Path\To\Executable"`

    6.  Re-enable firewall to block inbound and outbound (allow outbound
        on AD).\
        `netsh advfirewall set allprofiles firewallpolicy blockinbound blockoutbound`
        `netsh advfirewall set allprofiles state on`

    **NOTE: If you are in an AD environment, see [Active Directory
    Considerations](#adcon).**

## One-Liners {#woliner}

1.  Install Scoop Package Manager (Recommended):\
``` powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser;
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
```
2.  Generate CSV file with Passwords **(NOT NECESSARY FOR QUALIFIERS)**:
``` powershell
get-content "users.txt" | foreach {
	$secret = -join (([char]'A'..[char]'Z' + [char]'#'..[char]'&') |
	get-random -Count 24 | % {[char]$_});
	add-content "Team25_$(hostname)-SSH_PWD.csv" "hostname,$_,$secret"
}
```
3.  Reset Passwords based on generated password CSV file:
``` powershell
import-csv "Team25_$(hostname)-SSH_PWD.csv" -Header "host","user","pass" |
foreach {net user $_.user $_.pass};
del "Team25_$(hostname)-SSH_PWD.csv"
```
4.  Audit accounts on system based on list of expected users:
``` powershell
$expected = get-content "users.txt";
$expected += $env:Username, "seccdc_black"
get-localuser | foreach {
	if ($_.Name -notin $expected) {
		echo $_.Name; add-content "unexpected.txt" $_.Name
	}
}
```

5.  Disable unauthorized accounts:
``` powershell
get-content "unexpected.txt" | foreach {net user $_ /active:no}
```
## Hardening

1.  Configure NLA for RDP (can also be done through Group Policy).

2.  Service Management:

    1.  Look at running services and see if any look malicious. Services
        can be deleted from:
        `HKLM\SYSTEM\CurrentControlSet\Services`

    2.  Disable Print Spooler.\
        `Set-Service -Name "Spooler" -Status stopped -StartupType disabled`

    3.  Disable WinRM.\
        `Disable-PSRemoting -Force`;\
        `Set-Service -Name "WinRM" -Status stopped -StartupType disabled`

    4.  Configure SMB:

        1.  If SMB is unneeded (i.e. not in an AD setting), disable it
            entirely.\
            `Set-Service -Name "LanmanServer" -Status stopped -StartupType disabled`

        2.  If SMB is needed, disable SMBv1.\
            `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`

    5.  Harden the scored service for your machine according to the
        documentation below(#sec:services).

3.  Group Policy:

    1.  Check User Rights Assignment

## Monitoring

1.  View all network connections with `netstat -aonb`. For a live view, use TCPView.

2.  View running processes in the details pane of Task Manager or via Process Explorer.

3.  View all shares with `net share` and connected Named Pipes / Shares with `net use`.

4.  View all connected sessions with `qwinsta`.

5.  To get an insight into Powershell activity, enable Powershell Block Logging/Transcription. \
    `Administrative Templates > Windows Components > Windows Powershell`

6.  For an overview of system activity, configure Sysmon with [this config](https://raw.githubusercontent.com/D42H5/cyber_comp_resources/main/sysmonconfig-export-modified-2-2-24.xml).

    1.  To install Sysmon, run `sysmon -i <PATH TO CONFIG FILE>`.

    2.  Logs are sent to Applications and Services Logs > Microsoft > Windows > Sysmon.

    3.  If you want to update your config file, run `sysmon -c <PATH TO NEW CONFIG>`.

7.  You can view system events with the Event Viewer or Nirsoft's [EventLogViewer](https://www.nirsoft.net/utils/fulleventlogview-x64.zip).

    1.  You can filter down events to Sysmon\*, Powershell\*, and Security.

    2.  Configure additional auditing as needed.

## Response

1.  Kill a connected session with
    `rwinsta <SESSION ID>`.

2.  Kill a process in Task Manager/Process Explorer or with
    `taskkill /f /pid <PID>`.

## Hunting

1.  Install [Malwarebytes](https://downloads.malwarebytes.com/file/mb-windows) and run a system scan. It can be installed silently with: \
    `.\MBSetup.exe /VERYSILENT /NORESTART`

2.  You can scan the system for unsigned dlls with `listdlls -u`

3.  AccessEnum can be used to search for misconfigured ACLs. Check sensitive registry keys/directories.\
    `C:\Windows\System32` \
    `HKLM\SYSTEM\CurrentControlSet\Services`

4.  The Autoruns utility can be used to find potential persistence mechanisms. Task Scheduler and RunKeys should also be checked. \
    `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` \
    `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` \
    `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` \
    `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

5.  You can use BLUESPAWN to aid in hunting, **BUT DO NOT RELY ON IT SOLELY.**

    1.  It can be obtained from [here](https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe).

    2.  Basic usage is as follows:

        1.  BLUESPAWN-client-x64.exe --mitigate compares the system to a
            secure baseline.

        2.  BLUESPAWN-client-x64.exe --hunt does a single-pass scan for
            malicious activity.

        3.  BLUESPAWN-client-x64.exe --monitor is like hunt but alerts
            on new activity.

## Considerations for Active Directory {#adcon}

The below ports are needed for Active Directory to operate:

```
53 TCP/UDP: DNS
88 TCP/UDP: Kerberos
123 TCP: NTP
135 TCP: NetBIOS
138,139 TCP/UDP: File Replication
389,636 TCP: LDAP & LDAPS
445 TCP: SMB
464 TCP: Kerberos password change
3268,3269 TCP: Global Catalog LDAP & LDAPS
```

**These should be allowed inbound and outbound on a DC and outbound on a DM.**

The following template might help with making rules:

``` powershell
$ports = 53,88,123,135,138,139,389,636,445,464,3268,3269;
foreach ($p in $ports) {New-NetFirewallRule -DisplayName "AD $p" `
-[LOCALPORT/REMOTEPORT] $p -Protocol [TCP/UDP] `
-Action Allow -Direction [INBOUND/OUTBOUND]
}
```

1.  Many of the above steps can be done across multiple machines via Group Policy.

2.  The krbtgt password should be reset.

3.  The Domain Administrators group should have minimum membership.

4.  Kerberos authentication attempts should be monitored.

5.  You can force a reset of domain group policy with the below commands:

```
dcgpofix /target:both
gpupdate /force
```

## Installing the ELK Stack

1.  Install the prerequisites using manually or using scoop (see below).\
    [If using scoop, apps are installed in \$HOME/scoop/apps/\<APPNAME\>/current.]{.underline}

    1.  Add the 'extras' repository with `scoop bucket add extras`.

    2.  Add the 'java' repository with `scoop bucket add java`.

    3.  Install elasticsearch and kibana with `scoop install elasticsearch kibana openjdk`.

    4.  Notepad++ (notepadplusplus) is recommended for editing the yml files.

2.  Add the following lines to `<ELASTICSEARCH DIR>/config/elasticsearch.yml`:
``` yaml
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
cluster.initial_master_nodes: "elk"
http.host: [_local_, _site_]
```
3.  Start elasticsearch in a Powershell prompt. It will take a moment to initialize.

4.  Reset passwords for the kibana_system and elastic accounts.

    1.  `<ELASTICSEARCH DIR>/bin/elasticsearch-reset-password -u kibana-system`

    2.  `<ELASTICSEARCH DIR>/bin/elasticsearch-reset-password -u elastic`

    **SAVE THESE PASSWORDS SOMEWHERE.**

5.  Add the following lines to `<KIBANA DIR>/config/kibana.yml`:
``` yaml
server.host: "0.0.0.0"
server.publicBaseUrl: "http://localhost"
elasticsearch.hosts: "http://localhost:9200"
elasticsearch.username: "kibana_system"
elasticsearch.password: "<GENERATED KIBANA-SYSTEM PASSWORD>"
elasticsearch.ssl.verificationMode: none
```
6.  Stop the elasticsearch executable and install it as a service with: \
    `<ELASTICSEARCH DIR>/bin/elasticsearch-service.bat install`

7.  Start the elasticsearch service with `start-service elasticsearch-service-x64`

8.  Start kibana in a Powershell prompt. It will take a moment to initialize.

9.  You may now log into kibana at localhost:5601 with the elastic account.

## Configuring Winlogbeat

1.  You can obtain Winlogbeat from [here](https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.12.0-windows-x86_64.zip).

2.  Extract the Winlogbeat directory to C:\\Program Files.

3.  Edit the winlogbeat.yml file as needed for environment and log forwarding.

4.  Install Winlogbeat as a service with `.\install-service-winlogbeat.ps1`

5.  Load the prebuilt Winlogbeat assets with `.\winlogbeat.exe setup -e`.

6.  Start the Winlogbeat service with `start-service winlogbeat`

# Service Configuration {#sec:services}

## MySQL

1.  Change passwords for any non-scored users. \
``` sql
SELECT User, Host FROM mysql.user; \
ALTER USER '<USERNAME>'@<HOST> IDENTIFIED BY '<NEW PASSWORD>';
```

2.  Drop unauthorized users. \
``` sql
SELECT User, Host FROM mysql.user; \
DROP USER '<USERNAME>'@<HOST>;
```

4.  Prepare a database backup and store somewhere safe **off the system**.

    1.  Backup: `mysqldump -u <USERNAME> -p –all-databses > <BACKUP PATH>`

    2.  Restore: `mysql -u <USERNAME> -p < <BACKUP PATH>`

## FTP

**ANONYMOUS ACCESS CANNOT BE DISABLED.**

1.  On Windows, you will interact with the IIS console to manage FTP.

2.  On Linux, you will interact with /etc/vsftpd.conf (probably).

3.  Manage anonymous permissions to only allow reads (and writes if needed).

4.  Restrict access to non-shared directories from anonymous users.

5.  Prevent executables from running in the shared directory.

## SSH

1.  You can tunnel a port over ssh with the following syntax: \
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

```
# the below needs to be on one line
disable_functions=exec,passthru,shell_exec,system,proc_open,
popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

# disable file uploads if they aren't needed
file_uploads=off
allow_url_fopen=off
allow_url_include=off
```
