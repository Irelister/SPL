<details><summary>Reconnaissance</summary>
  
---

><details><summary>T1595 – Active Scanning</summary>
>
><br>
>
>1. High-volume connection attempts (port scanning)
>```spl
>index=bro sourcetype=corelight_conn
>| stats dc(id.resp_p) as ports_scanned, count by id.orig_h
>| where ports_scanned > 50 AND count > 100
>```
>2. Many TCP SYNs with no responses (S0 state)
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="tcp" AND state="S0"
>| stats count by id.orig_h, id.resp_h
>| where count > 20
>```
>3. Zeek notices for scanning behavior
>```spl
>index=bro sourcetype=corelight_notice
>| search note="SCAN::Port_Scan"
>| stats count by src
>```
></details>
>
><details><summary>T1593 – Search Open Technical Databases (OSINT)</summary>
>
><br>
>
>1. Outbound DNS queries to OSINT sites
>```spl
>index=bro sourcetype=corelight_dns
>| search query IN ("*.whois.com", "*.shodan.io", "*.censys.io")
>| stats count by orig_h, query
>```
>2. HTTP requests to recon tools
>```spl
>index=bro sourcetype=corelight_http
>| search host IN ("shodan.io", "censys.io", "intelx.io")
>| stats count by id.orig_h, host, uri
>```
>3. SSL connections to public certificate search sites
>```spl
>index=bro sourcetype=corelight_ssl
>| search server_name IN ("*.crt.sh", "*.censys.io")
>| stats count by id.orig_h, server_name
>```
></details>
>
><details><summary>T1592 – Gather Victim Host Information</summary>
>
><br>
>
>1. SMB enumeration of shares or host info
>```spl
>index=bro sourcetype=corelight_smb
>| search smb_cmd="SMB::TREE_CONNECT" OR smb_cmd="SMB::QUERY_INFORMATION"
>| stats count by id.orig_h, id.resp_h, smb_cmd
>```
>2. RPC or WMI behavior (port 135)
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND proto="tcp"
>| stats count by id.orig_h, id.resp_h
>```
>3. Kerberos TGS requests to many systems
>```spl
>index=bro sourcetype=corelight_kerberos
>| where request_type="TGS_REQ"
>| stats dc(id.resp_h) as host_count by id.orig_h
>| where host_count > 5
>```
></details>
>
><details><summary>T1598 – Gather Victim Network Information</summary>
>
><br>
>
>1. ICMP echo requests (ping sweep)
>```spl
>index=bro sourcetype=corelight_icmp
>| where icmp_type=8
>| stats count by id.orig_h, id.resp_h
>| where count > 20
>```
>2. Unusual DNS query types (ANY, TXT)
>```spl
>index=bro sourcetype=corelight_dns
>| where qtype_name IN ("TXT", "ANY")
>| stats count by orig_h, query, qtype_name
>```
>3. Access to infrastructure ports (SNMP, Syslog, Telnet)
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p IN (161, 162, 514, 23)
>| stats count by id.orig_h, id.resp_h, id.resp_p
>```
></details>
</details>

<details><summary>Resource Development</summary>
  
---

><details><summary>T1584 - Compromise Infrastructure</summary>
>
><br>
>
>1. Multiple Domains Resolve to the same IP.
>```spl
>index=central_summary source=summary_dns_with_answers 
>| stats dc(query) as domain_count by answer 
>| where domain_count > 10 
>```
>2. Rare JA3 and JA3S TLS Fingerprints
>```spl
>index=central_summary source=summary_ssl 
>| stats count by ja3, ja3s, dest_ip 
>| where count < 5 
>```
>3. Unusual HTTP Hosts or Repeating POSTS Requests
>```spl
>index=bro sourcetype=corelight_http 
>| search method=POST 
>| stats count by src_ip, dest_ip, host_header, uri, user_agent 
>| where count > 20 
>```
>4. High Volume, Long-Lived Peer-to-Peer Connections
>```spl
>index=bro sourcetype=corelight_conn 
>| search duration > 300 
>| stats count by src_ip, dest_ip, duration, service 
>| where count > 20 
>```
></details>
</details>

<details><summary>Initial Access</summary>
  
---

><details><summary><strong>T1190 – Exploit Public-Facing Application</strong></summary>
>
><br>
>
>1. **HTTP 500–599 Errors on External Apps**
>```spl
>index=bro sourcetype=corelight_http
>| where status>=500 AND status<600
>| stats count by id.orig_h, uri, status
>| sort -count
>```
>2. **Suspicious POST Requests to Unknown URIs**
>```spl
>index=bro sourcetype=corelight_http method=POST
>| where uri!="*" AND uri!="/"
>| stats count by id.orig_h, uri
>| where count > 20
>```
>3. **High Data POSTs to External Apps**
>```spl
>index=bro sourcetype=corelight_http method=POST
>| stats sum(resp_body_len) as data_sent count by id.orig_h, uri
>| where data_sent>1000000
>```
></details>
>
><details><summary><strong>T1078 – Valid Accounts</strong></summary>
>
><br>
>
>1. **Successful Logins via RDP**
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 0
>```
>2. **Successful SSH Connections**
>```spl
>index=bro sourcetype=corelight_ssh auth_success=true
>| stats count by id.orig_h, id.resp_h
>```
>3. **SMB Logins Without Failures**
>```spl
>index=bro sourcetype=corelight_smb smb_cmd="SMB::SESSION_SETUP" smb_status="SUCCESS"
>| stats count by id.orig_h, id.resp_h, user
>```
></details>
>
><details><summary><strong>T1566 – Phishing</strong></summary>
>
><br>
>
>1. **HTTP/S Download of Executable Attachments**
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*.exe","*.scr","*.vbs","*.zip")
>| stats count by id.orig_h, uri
>```
>2. **Email Attachment URLs (If SMTP Logging Exists)**
>```spl
>index=bro sourcetype=corelight_smtp
>| search uri IN ("*.exe","*.zip","*.scr")
>| stats count by id.orig_h, uri
>```
>3. **Suspicious HTTP POST to Rare Domains**
>```spl
>index=bro sourcetype=corelight_http method=POST
>| stats dc(uri) as uri_count by id.orig_h, dest
>| where uri_count=1 AND dest!="trusted.domain"
>```
></details>
>
><details><summary><strong>T1199 – Trusted Relationship</strong></summary>
>
><br>
>
>1. **Inbound VPN-Like UDP Traffic**
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="udp" AND id.resp_p IN (1194, 500, 4500)
>| stats sum(orig_bytes) as bytes count by id.orig_h, id.resp_h
>| where count>0
>```
>2. **External TLS Sessions Into Perimeter**
>```spl
>index=bro sourcetype=corelight_ssl
>| where id.orig_h NOT IN ("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
>| stats count by id.orig_h, id.resp_h, server_name
>```
>3. **Inbound RDP From External Networks**
>```spl
>index=bro sourcetype=corelight_conn service="rdp"
>| where id.orig_h NOT IN ("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
>| stats count by id.orig_h, id.resp_h
>```
></details>
>
><details><summary><strong>T1133 – External Remote Services</strong></summary>
>
><br>
>
>1. **Inbound RDP Connections from External IPs**
>```spl
>index=bro sourcetype=corelight_conn
>| where service="rdp" AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
>| stats count by id.orig_h, id.resp_h, duration
>```
>2. **Inbound SSH Sessions from External IPs**
>```spl
>index=bro sourcetype=corelight_conn
>| where service="ssh" AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
>| stats count by id.orig_h, id.resp_h
>```
>3. **External Access to SMB from Outside**
>```spl
>index=bro sourcetype=corelight_conn
>| where service="smb" AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
>| stats count by id.orig_h, id.resp_h
>```
>4. **VPN-Like UDP Traffic (e.g., IPsec 500/4500)**
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="udp" AND id.resp_p IN (500,4500)
>| stats sum(orig_bytes) as total_bytes, count by id.orig_h, id.resp_h
>| where total_bytes > 1000000
>```
>5. **Remote Admin Ports (22,3389,5985,5986) From External**
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p IN (22,3389,5985,5986)
>  AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
>| stats count by id.orig_h, id.resp_h, id.resp_p
>```
>6. **Long-Lived Connections from External**
>```spl
>index=bro sourcetype=corelight_conn
>| where id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
>  AND duration > 600
>| stats duration, orig_bytes, resp_bytes by id.orig_h, id.resp_h, service
>```
></details>
</details>

<details><summary>Execution</summary>
  
---

><details><summary>T1047 - Windows Management Instrumentation</summary>
>  
><br>
>
>- TCP port 135 (RPC/DCOM)
>- High ephemeral port usage after initial bind.
>- Paired host activity (e.g., lateral movement from one internal host to another)
>- Since WMI itself doesn't leave deep footprints in network logs, combining this with host EDR telemetry or Sysmon logs (Event ID 5861) is ideal.
>
>1. Detects RPC/DCOM connections to TCP port 135 — typical of remote WMI execution.
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND proto="tcp"
>| stats count, sum(orig_bytes) as bytes_out, sum(resp_bytes) as bytes_in by id.orig_h, id.resp_h
>| sort -count
>```
>
>2. Looks for excessive RPC endpoint usage, which may indicate scripted or automated WMI use.
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 OR id.resp_p=1024 OR id.resp_p=1025 OR id.resp_p > 1024
>| stats count by id.orig_h, id.resp_h, id.resp_p
>| where count > 20
>```
>
>3. Direct detection of known RPC interfaces associated with WMI — if rpc.log is enabled.
>```spl
>index=bro sourcetype=corelight_rpc
>| search ruid IN ("WINMGMT", "WMI", "epmapper")
>| stats count by id.orig_h, id.resp_h, ruid
>```
>
>4. Looks for short-lived, low-data RPC connections — a pattern typical of remote WMI use.
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND service!="http" AND service!="ftp"
>| stats count by id.orig_h, id.resp_h, duration, orig_bytes, resp_bytes
>| where duration < 10 AND orig_bytes < 1000 AND resp_bytes < 1000
>```
></details>
>
><details><summary>T1059 – Command and Scripting Interpreter</summary>
>
><br>
>
>1. HTTP download of script-based tools
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*.ps1", "*.vbs", "*.sh", "*.py", "*.bat")
>| stats count by id.orig_h, uri
>```
>2. SMB delivery of script files
>```spl
>index=bro sourcetype=corelight_smb_files
>| search filename IN ("*.ps1", "*.vbs", "*.bat", "*.sh", "*.py")
>| stats count by id.orig_h, id.resp_h, filename
>```
>3. Small RPC or DCOM sessions preceding download
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND orig_bytes<2000 AND resp_bytes<2000
>| stats count by id.orig_h, id.resp_h
>```
></details>
>
><details><summary>T1204 – User Execution</summary>
>
><br>
>
>1. HTTP download of executables with no automation indicator
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*.exe", "*.scr", "*.msi")
>| stats count by id.orig_h, uri, user_agent
>| where user_agent!="python*" AND user_agent!="curl*" AND user_agent!="wget*"
>```
>2. SMB transfers of executables
>```spl
>index=bro sourcetype=corelight_smb_files
>| search mime_type="application/x-dosexec"
>| stats count by id.orig_h, id.resp_h, filename
>```
>3. HTTP referrals from email/generic domains
>```spl
>index=bro sourcetype=corelight_http
>| search referer="http://%*"
>| search uri IN ("*.exe","*.zip","*.msi")
>| stats count by id.orig_h, referer, uri
>```
></details>
>
><details><summary>T1106 – Native API</summary>
>
><br>
>
>1. SMB share enumeration of system folders
>```spl
>index=bro sourcetype=corelight_smb
>| search smb_cmd="SMB::TREE_CONNECT" path IN ("C$","ADMIN$")
>| stats count by id.orig_h, id.resp_h, path
>```
>2. Small RPC/COM calls (indicative of native API use)
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND orig_bytes<1500
>| stats count by id.orig_h, id.resp_h
>```
></details>
>
><details><summary>T1053 – Scheduled Task/Job</summary>
>
><br>
>
>1. Download of scheduler-related tools via HTTP/SMB
>```spl
>index=bro sourcetype=corelight_http OR sourcetype=corelight_smb_files
>| search uri IN ("*schtasks*", "*at.exe*", "*taskschd*") OR filename IN ("schtasks.exe","at.exe")
>| stats count by id.orig_h, uri, filename
>```
>2. RPC calls to scheduler services via TCP 135
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND proto="tcp"
>| stats count by id.orig_h, id.resp_h
>```
></details>
>
><details><summary>T1569 – System Services</summary>
>
><br>
>
>1. HTTP/SMB retrieval of service tools (e.g., sc.exe, service.exe)
>```spl
>index=bro sourcetype=corelight_http OR sourcetype=corelight_smb_files
>| search uri IN ("*sc.exe","*service.exe") OR filename IN ("sc.exe","service.exe")
>| stats count by id.orig_h, uri, filename
>```
>2. DCOM/RPC RPC calls to service management via TCP 135
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND proto="tcp"
>| stats count by id.orig_h, id.resp_h
>```
></details>
>
><details><summary>T1055 – Process Injection</summary>
>
><br>
>
>1. HTTP downloads of typical injection tools
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*mimikatz*","*meterpreter*","*powershell*")
>| stats count by id.orig_h, uri
>```
>2. SMB transfers of executables likely used for injection
>```spl
>index=bro sourcetype=corelight_smb_files
>| search mime_type="application/x-dosexec"
>| stats count by id.orig_h, id.resp_h, filename
>```
></details>
>
><details><summary>T1129 – Shared Modules</summary>
>
><br>
>
>1. HTTP download of DLL or shared modules
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*.dll","*.so","*.dylib")
>| stats count by id.orig_h, uri
>```
>2. SMB transfer of shared libraries
>```spl
>index=bro sourcetype=corelight_smb_files
>| search filename IN ("*.dll","*.so","*.dylib")
>| stats count by id.orig_h, id.resp_h, filename
>```
></details>
>
><details><summary>T1203 – Exploitation for Client Execution</summary>
>
><br>
>
>1. HTTP GET of malicious content (exploit patterns)
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*.swf","*.js","*.jar","*.doc","*.pdf")
>| stats count by id.orig_h, uri
>```
>2. SMB transfers of exploit files
>```spl
>index=bro sourcetype=corelight_smb_files
>| search filename IN ("*.doc","*.pdf","*.js")
>| stats count by id.orig_h, id.resp_h, filename
>```
></details>
</details>

<details><summary>Persistence</summary>
  
---

><details><summary>T1136 - Create Account</summary>
>
><br>
>
>1. Kerberos AS-REQ or TGS-REQ from Previously Unknown Username A newly created domain account may trigger initial Kerberos activity.
>```spl
>index=bro sourcetype=corelight_kerberos
>| stats earliest(_time) as first_seen by client
>| where first_seen >= relative_time(now(), "-1d@d")
>```
>2. LDAP Activity Indicating Account Creation.
>```spl
>index=bro sourcetype=corelight_ldap
>| search query IN ("userPrincipalName", "objectClass=user", "sAMAccountName")
>| stats count by id.orig_h, base_dn, query, result, _time
>```
>3. Suspicious File Access to SAM Hive.
>```spl
>index=bro sourcetype=corelight_smb_files
>| search filename="\\windows\\system32\\config\\sam"
>| stats count by id.orig_h, id.resp_h, filename, action, _time
>```
></details>

><details><summary>T1505 - Server Software Component</summary>
>
><br>
>
>1. Web shells often receive commands via POST.
>```spl
>index=bro sourcetype=corelight_http 
>| search method=POST
>| search uri IN ("*.php*", "*.aspx*", "*.jsp*", "*cmd*", "*eval*", "*shell*")
>| stats count by id.orig_h, id.resp_h, uri, user_agent, method, status_code, _time
>```
>2. Look for indicators in query strings or URIs.
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*cmd=*", "*exec*", "*eval*", "*shell*", "*.php", "*.asp", "*.jsp")
>| stats count by id.orig_h, id.resp_h, uri, user_agent, referrer, status_code, _time
>```
>3. Web shells are often uploaded through file upload features.
>```spl
>index=bro sourcetype=corelight_http 
>| search method=POST uri IN ("*/upload*", "*/admin*", "*/file*", "*.php*", "*.asp*")
>| stats count by id.orig_h, id.resp_h, uri, user_agent, status_code, content_type, _time
>```
>4. Newly Seen Files in Webroot (e.g., .php or .jsp)
>```spl
>index=bro sourcetype=corelight_files 
>| search filename IN ("*.php", "*.jsp", "*.asp", "*.aspx")
>| stats count by id.orig_h, id.resp_h, filename, mime_type, seen_bytes, _time
>```
>5. SMB File Writes to Webroot (If logs available)
>```spl
>index=bro sourcetype=corelight_smb_files 
>| search filename IN ("*.php", "*.asp", "*.jsp") AND action="WRITE"
>| stats count by id.orig_h, id.resp_h, filename, action, _time
>```
>6. Large response sizes from small POSTs (Shell response)
>```spl
>index=bro sourcetype=corelight_http
>| eval ratio=response_body_len/request_body_len 
>| where method="POST" AND ratio > 10
>| stats count by id.orig_h, id.resp_h, uri, user_agent, ratio, _time
>```
></details>
</details>

<details><summary>Privilege Escalation</summary>
  
---

><details><summary>T1548 – Abuse Elevation Control Mechanism</summary>
>
><br>
>
>1. RPC or DCOM traffic over privileged admin ports
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p IN (135, 445, 5985, 5986)
>| stats count by id.orig_h, id.resp_h, id.resp_p
>| where count > 10
>```
>2. RDP sessions combined with admin share access
>```spl
>index=bro sourcetype=corelight_conn OR sourcetype=corelight_smb
>| eval rdp=service="rdp", admin_access=(path IN ("ADMIN$", "C$"))
>| stats count by id.orig_h, rdp, admin_access
>| where rdp=1 AND admin_access=1
>```
>3. WMI queries to admin shares or privileged hosts
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 OR service="smb"
>| stats count by id.orig_h, id.resp_h, service
>| where count > 5
>```
></details>
>
><details><summary>T1055 – Process Injection</summary>
>
>*(Note: network detection here is indirect—watch for tool downloads or RPC commands)*
>
><br>
>
>1. Tools commonly used for process injection downloaded over HTTP
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*mimikatz*","*powersploit*","*meterpreter*")
>| stats count by id.orig_h, uri
>```
>2. Executable transfers via SMB
>```spl
>index=bro sourcetype=corelight_files
>| search filename IN ("*.exe","*.dll","*.sys")
>| stats count by id.orig_h, id.resp_h, filename
>```
>3. DCOM/RPC sessions with small data transfers (possible remote execution)
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND orig_bytes<1000 AND resp_bytes<1000
>| stats count by id.orig_h, id.resp_h
>```
></details>
>
><details><summary>T1134 – Access Token Manipulation</summary>
>
>*(Host-level mostly, but monitor network behavior with impersonated sessions)*
>
><br>
>
>1. New SMB sessions with different user context
>```spl
>index=bro sourcetype=corelight_smb
>| stats dc(user) as distinct_users by id.orig_h, id.resp_h
>| where distinct_users > 1
>```
>2. RDP sessions switching user accounts
>```spl
>index=bro sourcetype=corelight_rdp
>| stats dc(user) as distinct_users by id.orig_h, id.resp_h
>| where distinct_users > 1
>```
>3. Multiple Kerberos ticket requests across services
>```spl
>index=bro sourcetype=corelight_kerberos
>| stats dc(request_type) as ticket_types by id.orig_h
>| where ticket_types > 1
>```
></details>
>
><details><summary>T1548.002 – Bypass User Account Control</summary>
>
>*(Network artifacts are weak, but you can monitor related behaviors)*
>
><br>
>
>1. Download of UAC bypass tools
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*uacme*","*tater*","*elevator*")
>| stats count by id.orig_h, uri
>```
>2. DCOM/RPC with frequent callbacks
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND duration < 10
>| stats count by id.orig_h, id.resp_h
>```
>3. SMB access to system folders or admin shares
>```spl
>index=bro sourcetype=corelight_smb
>| search path IN ("C$","ADMIN$")
>| stats count by id.orig_h, path
>```
></details>
</details>

<details><summary>Defense Evasion</summary>
  
---

><details><summary>T1070 - Indicator Removal</summary>
>  
><br>
>
>1. Look for file deletion or renaming over SMB shares.
>```spl
>index=bro sourcetype=corelight_files OR sourcetype=corelight_smb_files
>| where action IN ("SMB::DELETE", "SMB::RENAME") OR (seen="F" AND fuid!="-" AND is_orig=true)
>| stats count by id.orig_h, id.resp_h, name, action
>```
>2. Look for connections to admin SMB shares, common when scripts or remote access tools are used for cleanup.
>```spl
>index=bro sourcetype=corelight_smb
>| search path IN ("ADMIN$", "C$", "D$", "IPC$")
>| stats count by id.orig_h, id.resp_h, path, user
>```
>3. Look for short duration RDP connections. Short bursts of RDP can indicate someone quickly connecting just to clean up.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 3 AND avg_duration < 60
>```
>4. Detect the downloads of cleanup tools (sdelete, wevtutil, etc.)
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*sdelete*", "*wevtutil*", "*clear_event*", "*wipe*", "*rm.exe*", "*del.exe*")
>| stats count by uri, id.orig_h, id.resp_h, user_agent
>```
>5. Detect suspicious SMB file transfers including executables.
>```spl
>index=bro sourcetype=corelight_files
>| where mime_type="application/x-dosexec"
>| stats count by id.orig_h, id.resp_h, filename, fuid
>```
>6. Find bulk SMB file transfers followed by deletions.
>```spl
>index=bro sourcetype=corelight_smb_files
>| stats count(eval(action="SMB::WRITE")) as writes, count(eval(action="SMB::DELETE")) as deletes by id.orig_h, id.resp_h
>| where writes > 10 AND deletes > 5
>```
></details>
>
><details><summary>T1564 - Hide Artifacts</summary>
>  
><br>
>  
>1. Detect unusual Port Usage for Known Protocols.
>```spl
>index=bro sourcetype=corelight_conn
>| eval unusual_port=( (service="http" AND id.resp_p!=80) OR (service="https" AND id.resp_p!=443) )
>| where unusual_port
>| stats count by id.orig_h, id.resp_h, service, id.resp_p
>```
>2. Detect suspicious TLS Without SNI (Server Name Indication)
>```spl
>index=bro sourcetype=corelight_ssl
>| where isnull(server_name)
>| stats count by id.orig_h, id.resp_h
>```
>3. Detect HTTP with Suspicious User-Agents or Missing Headers
>```spl
>index=bro sourcetype=corelight_http
>| search user_agent="-" OR user_agent="curl*" OR user_agent="python*" OR user_agent="powershell*"
>| stats count by id.orig_h, id.resp_h, user_agent
>```
>4. Detect abnormal File Transfers in HTTP with Mismatched MIME Types.
>```spl
>index=bro sourcetype=corelight_http
>| where mime_type!="application/octet-stream" AND uri matches ".exe|.zip|.bin|.dll"
>| stats count by id.orig_h, uri, mime_type
>```
>5. Detect covert Channels in DNS (e.g., Data Hidden in Queries).
>```spl
>index=bro sourcetype=corelight_dns
>| where length(query) > 100 OR query matches ".*[0-9a-f]{30,}.*"
>| stats count by id.orig_h, query
>```
>6. Detect large Amounts of Encrypted Data Sent Outbound.
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="tcp" AND service IN ("ssl", "https")
>| stats sum(orig_bytes) as sent_bytes by id.orig_h, id.resp_h
>| where sent_bytes > 500000
>```
></details>
</details>

<details><summary>Credential Access</summary>
  
---

><details><summary>T1003 - OS Credential Dumping</summary>
>  
><br>
>
>- Most of these will require host logs for verification.
>1. Detects direct or indirect download of known credential dumping tools via HTTP.
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*mimikatz*", "*procdump*", "*lsass*", "*pwdump*", "*.ps1")
>| stats count by id.orig_h, id.resp_h, uri, user_agent
>```
>2. Detect suspicious files transfered via SMB or HTTP. Credential dump files often have .dmp, .bin, or are zipped/encoded.
>```spl
>index=bro sourcetype=corelight_files
>| search filename IN ("*lsass*", "*dump*", "*.dmp", "*.zip", "*.ps1", "*.bin")
>| stats count by id.orig_h, id.resp_h, filename, mime_type
>```
>3. Detect dump files being copied or staged for exfil — over 10MB is a red flag.
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::WRITE"
>| stats sum(size) as total_bytes, count by id.orig_h, id.resp_h, name
>| where total_bytes > 10000000
>| sort -total_bytes
>```
>4. Short, frequent RDP sessions — may be used to quickly run tools like Mimikatz.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 3 AND avg_duration < 60
>```
>5. Detect dumping SAM/SYSTEM/SECURITY hives remotely may be visible as file access.
>```spl
>index=bro sourcetype=corelight_smb_files
>| search name IN ("*\\system32\\config\\sam", "*\\system32\\config\\system", "*\\config\\security")
>| stats count by id.orig_h, id.resp_h, name
>```
></details>
>
><details><summary>T1110 - Brute Force</summary>
>  
><br>
>  
>1. Detects repeated failed authentication attempts over SMB.
>```spl
>index=bro sourcetype=corelight_smb
>| where smb_cmd="SMB::SESSION_SETUP" AND smb_status!="SUCCESS"
>| stats count by id.orig_h, id.resp_h, user
>| where count > 10
>| sort -count
>```
>2. Excessive RDP attempts with short duration may indicate brute-force behavior.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) by id.orig_h, id.resp_h
>| where count > 10 AND avg(duration) < 10
>| sort -count
>```
>3. Looks for excessive failed SSH logins — common in brute-force scenarios.
>```spl
>index=bro sourcetype=corelight_ssh
>| stats count by id.orig_h, id.resp_h, auth_success
>| where auth_success=false AND count > 10
>```
>4. If Corelight's notice.log is enabled, this flags any password guessing or brute-force detections.
>```spl
>index=bro sourcetype=corelight_notice
>| search note IN ("SSH::Password_Guessing", "SMB::Brute_Force", "RDP::Brute_Force")
>| stats count by src, dst, note
>| where count > 5
>```
>5. Identifies a source trying many different hosts — indicative of broad brute-force scanning.
>```spl
>index=bro sourcetype=corelight_conn
>| where service IN ("ssh", "rdp", "smb")
>| stats dc(id.resp_h) as unique_targets, count by id.orig_h
>| where unique_targets > 5 AND count > 20
>```
>6. FTP brute-force is less common today, but still worth monitoring.
>```spl
>index=bro sourcetype=corelight_ftp
>| where reply_code >= 400
>| stats count by id.orig_h, id.resp_h, user
>| where count > 10
>```
></details>
</details>

<details><summary>Discovery</summary>
  
---

><details><summary>T1033 - System Owner & User Discovery</summary>
>
><br>
>
>1. Detect access to SMB IPC$ and ADMIN$ shares (User/Session Probing).
>```spl
>index=bro sourcetype=corelight_smb
>| search path IN ("IPC$", "ADMIN$")
>| stats count by id.orig_h, id.resp_h, path, user
>```
>2. WMI queries over RPC (TCP 135) often used to gather system and user info.
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND proto="tcp"
>| stats count by id.orig_h, id.resp_h
>| where count > 5
>```
>3. Brief RDP logins could be used just to list users/sessions.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 3 AND avg_duration < 60
>```
>4. Detect kerberos AS-REQ without TGT request (User Probing). Indicates probing for users without actually requesting tickets (Kerberoasting-related discovery).
>```spl
>index=bro sourcetype=corelight_kerberos
>| where request_type="AS_REQ" AND isnull(ticket_id)
>| stats count by id.orig_h, id.resp_h, client, service
>```
>5. A single host reaching many others over user-relevant services — may indicate discovery activity.
>```spl
>index=bro sourcetype=corelight_conn
>| where service IN ("smb", "rdp", "rpc")
>| stats dc(id.resp_h) as unique_targets by id.orig_h
>| where unique_targets > 5
>```
></details>
>
><details><summary>T1069 - Permission Groups Discovery</summary>
>
><br>
>
>1. 
>```spl
>index=bro sourcetype=corelight_ldap
>| search base_dn="CN=Users*" OR base_dn="CN=Groups*" OR query IN ("memberOf", "primaryGroupID")
>| stats count by id.orig_h, base_dn, query, result, _time
>```
>2. Suspicious enumeration may cause high volumes of TGS-REQ to services like ldap, cifs, krbtgt, etc.
>```spl
>index=bro sourcetype=corelight_kerberos
>| search service IN ("ldap", "krbtgt", "cifs")
>| stats count by id.orig_h, id.resp_h, client, service, request_type, _time
>```
>3. Common during domain reconnaissance
>```spl
>index=bro sourcetype=corelight_dns 
>| search query IN ("_ldap._tcp.*", "_kerberos._tcp.*", "*dc._msdcs*")
>| stats count by id.orig_h, query, qtype_name, _time
>```
>4. These shares are often accessed during domain enumeration or GPO gathering.
>```spl
>index=bro sourcetype=corelight_smb_mapping
>| search path IN ("\\*\\SYSVOL", "\\*\\NETLOGON")
>| stats count by id.orig_h, id.resp_h, path, share_type, _time
>```
>5. Look for one IP performing a lot of queries.
>```spl
>index=bro sourcetype=corelight_ldap OR sourcetype=corelight_kerberos
>| stats count by id.orig_h, sourcetype, _time
>| where count > 100
>```
>6. Movement of Suspicious Files via SMB
>```spl
>index=zeek sourcetype=zeek_smb_files
>| search filename IN ("\\windows\\system32\\config\\sam", "\\windows\\system32\\config\\system")
>| stats count by id.orig_h, id.resp_h, filename, action, _time
>```
>7. Find High Volume SMB Mapping Commands
>```spl
>index=zeek sourcetype=zeek_smb_mapping
>| stats count by id.orig_h, id.resp_h, path, share_type, _time
>```
></details>
>
><details><summary>T1082 - System Information Discovery</summary>
>  
><br>
>  
>1. 
>```spl
>
>```
>
>2. 
>```spl
>
>```
>
>3. 
>```spl
>
>```
>
>4. 
>```spl
>
>```
></details>
</details>

<details><summary>Lateral Movement</summary>
  
---

><details><summary>T1021 – Remote Services</summary>
>
><br>
>
>1. SMB session access across internal hosts
>```spl
>index=bro sourcetype=corelight_smb
>| stats count by id.orig_h, id.resp_h, user
>| where count > 5
>```
>2. RDP sessions with multiple internal destinations
>```spl
>index=bro sourcetype=corelight_rdp
>| stats dc(id.resp_h) as targets, count by id.orig_h
>| where targets > 1 AND count > 5
>```
>3. SSH connections between internal systems
>```spl
>index=bro sourcetype=corelight_ssh auth_success=true
>| stats count by id.orig_h, id.resp_h
>| where count > 3
>```
></details>
>
><details><summary>T1021.001 – Remote Services: SMB/Windows Admin Shares</summary>
>
><br>
>
>1. Writes to admin shares on multiple hosts
>```spl
>index=bro sourcetype=corelight_smb_files
>| stats count(eval(action="SMB::WRITE")) as writes by id.orig_h, id.resp_h
>| where writes > 10
>```
>2. SMB TREE\_CONNECT followed by WRITE or DELETE
>```spl
>index=bro sourcetype=corelight_smb
>| stats count(eval(smb_cmd="SMB::TREE_CONNECT")) as connects, count(eval(action="SMB::WRITE")) as writes by id.orig_h, id.resp_h
>| where connects > 1 AND writes > 1
>```
></details>
>
><details><summary>T1021.002 – Remote Services: SMB/Windows Admin Shares</summary>
>
><br>
>
>1. SMB DELETE actions across multiple hosts
>```spl
>index=bro sourcetype=corelight_smb_files
>| stats count(eval(action="SMB::DELETE")) as deletes by id.orig_h, id.resp_h
>| where deletes > 5
>```
>2. Enumeration of ADMIN\$, C\$, IPC\$ shares across hosts
>```spl
>index=bro sourcetype=corelight_smb
>| search path IN ("ADMIN$","C$","IPC$")
>| stats dc(id.resp_h) as hosts_accessed by id.orig_h
>| where hosts_accessed > 1
>```
></details>
>
><details><summary>T1021.004 – Remote Services: SSH</summary>
>
><br>
>
>1. Successful SSH connections to multiple hosts
>```spl
>index=bro sourcetype=corelight_ssh auth_success=true
>| stats dc(id.resp_h) as targets by id.orig_h
>| where targets > 2
>```
>2. Frequent short SSH sessions between internal systems
>```spl
>index=bro sourcetype=corelight_ssh
>| stats count(avg(duration)) as avg_duration by id.orig_h, id.resp_h
>| where count > 5 AND avg_duration < 30
>```
></details>
>
><details><summary>T1021.005 – Remote Services: VNC</summary>
>
><br>
>
>1. VNC sessions detected (usually TCP ports 5900–5902)
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p IN (5900,5901,5902)
>| stats count by id.orig_h, id.resp_h, id.resp_p
>```
>2. Multiple VNC connections from same origin
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p IN (5900,5901,5902)
>| stats dc(id.resp_h) as targets by id.orig_h
>| where targets > 1
>```
></details>
>
><details><summary>T1021.006 – Remote Services: RDP</summary>
>
><br>
>
>1. RDP sessions to various internal hosts
>```spl
>index=bro sourcetype=corelight_rdp
>| stats dc(id.resp_h) as hosts_accessed by id.orig_h
>| where hosts_accessed > 1
>```
>2. RDP sessions with rapid logins (suspicious)
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 5 AND avg_duration < 30
>```
></details>
>
><details><summary>T1570 – Lateral Tool Transfer</summary>
>
><br>
>
>1. Transfers of executables via SMB
>```spl
>index=bro sourcetype=corelight_smb_files
>| search mime_type="application/x-dosexec"
>| stats count by id.orig_h, id.resp_h, filename
>```
>2. Downloads of tools (e.g., psexec) via HTTP
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*psexec*","*winexe*","*plink*")
>| stats count by id.orig_h, uri
>```
></details>
</details>

<details><summary>Collection</summary>
  
---

><details><summary>T1005 – Data from Local System</summary>
>
><br>
>
>1. Read of large files over SMB (possible data gathering)
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::READ"
>| stats sum(size) as total_read, count by id.orig_h, id.resp_h, name
>| where total_read > 100000000
>```
>2. Multiple read actions on same host
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::READ"
>| stats count by id.orig_h, id.resp_h
>| where count > 50
>```
></details>
>
><details><summary>T1074 – Data Staged</summary>
>
><br>
>
>1. Large SMB file writes to internal storage
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::WRITE"
>| stats sum(size) as total_bytes, count by id.orig_h, id.resp_h
>| where total_bytes > 10000000
>```
>2. Repeated write bursts to staging hosts
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::WRITE"
>| stats count by id.orig_h, id.resp_h
>| where count > 20
>```
></details>
>
><details><summary>T1123 – Audio Capture</summary>
>
><br>
>
>*(Network detection for purely host-based audio capture is not available; monitor exfil after capture)*
>
></details>
>
><details><summary>T1113 – Screen Capture</summary>
>
><br>
>
>*(Network detection for screen capture is not available; look outbound for large image uploads)*
>
></details>
>
><details><summary>T1132 – Data Encoding</summary>
>
><br>
>
>1. DNS queries with encoded payloads
>```spl
>index=bro sourcetype=corelight_dns
>| where len(query) > 100
>| stats count by orig_h, query
>| where count > 20
>```
>2. Frequent DNS TXT requests (encoding channel)
>```spl
>index=bro sourcetype=corelight_dns
>| where qtype_name="TXT"
>| stats count by orig_h, query
>| where count > 50
>```
></details>
</details>

<details><summary>Command and Control</summary>
  
---

><details><summary>T1071 – Application Layer Protocol</summary>
>
><br>
>
>1. HTTP POST traffic to uncommon domains
>```spl
>index=bro sourcetype=corelight_http method=POST
>| stats count sum(resp_body_len) as total_bytes by id.orig_h, dest
>| where count > 10 AND total_bytes > 100000
>```
>2. HTTPS connections with large data exchanges
>```spl
>index=bro sourcetype=corelight_ssl
>| stats sum(orig_bytes) as sent sum(resp_bytes) as received count by id.orig_h, id.resp_h, server_name
>| where sent > 500000
>```
>3. Custom protocols on high-numbered TCP ports
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p > 1024 AND service="unknown"
>| stats count,sum(orig_bytes) by id.orig_h, id.resp_h, id.resp_p
>| where count > 5
>```
></details>
>
><details><summary>T1071.001 – Web Protocols (HTTP/S)</summary>
>
><br>
>
>1. Frequent POSTs to rare URIs
>```spl
>index=bro sourcetype=corelight_http method=POST
>| stats dc(uri) as uri_count by id.orig_h, dest
>| where uri_count > 5
>```
>2. Low-traffic HTTPS sessions (likely beacons)
>```spl
>index=bro sourcetype=corelight_ssl
>| stats count avg(orig_bytes) by id.orig_h, id.resp_h
>| where count > 20 AND avg(orig_bytes) < 1000
>```
>3. HTTP User-Agent anomalies
>```spl
>index=bro sourcetype=corelight_http
>| where user_agent IN ("python*", "curl*", "wget*")
>| stats count by id.orig_h, user_agent, uri
>```
></details>
>
><details><summary>T1071.002 – File Transfer Protocols (FTP, SFTP)</summary>
>
><br>
>
>1. FTP transfers with uncommon credentials
>```spl
>index=bro sourcetype=corelight_ftp
>| stats count by id.orig_h, id.resp_h, user
>| where count > 5
>```
>2. SFTP usage on non-standard ports
>```spl
>index=bro sourcetype=corelight_conn
>| where service="sftp" AND id.resp_p!=22
>| stats count by id.orig_h, id.resp_h, id.resp_p
>```
>3. FTP sessions with significant file size
>```spl
>index=bro sourcetype=corelight_ftp
>| stats sum(bytes) as total_bytes by id.orig_h, id.resp_h
>| where total_bytes > 1000000
>```
></details>
>
><details><summary>T1071.003 – Mail Protocols</summary>
>
><br>
>
>1. Outgoing SMTP with large attachments
>```spl
>index=bro sourcetype=corelight_smtp
>| stats sum(bytes) as total_bytes count by id.orig_h, rcpt
>| where total_bytes > 500000
>```
>2. SMTP to rare external domains
>```spl
>index=bro sourcetype=corelight_smtp
>| stats count by id.orig_h, dest_domain
>| where dest_domain NOT IN ("trusted.com","myorg.com")
>```
></details>
>
><details><summary>T1071.004 – DNS</summary>
>
><br>
>
>1. DNS queries with unusually long subdomains
>```spl
>index=bro sourcetype=corelight_dns
>| where len(query)>100
>| stats count by orig_h, query
>```
>2. High-frequency DNS lookups to same domain
>```spl
>index=bro sourcetype=corelight_dns
>| stats count by orig_h, query
>| where count > 50
>```
>3. TXT DNS responses with large payloads
>```spl
>index=bro sourcetype=corelight_dns
>| where qtype_name="TXT" AND response_length>200
>| stats count by orig_h, query
>```
></details>
>
><details><summary>T1071.005 – Protocol Tunneling</summary>
>
><br>
>
>1. High-volume traffic on uncommon TCP ports
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p>2000 AND service="unknown"
>| stats sum(orig_bytes) as bytes count by id.orig_h, id.resp_h, id.resp_p
>| where bytes>1000000
>```
>2. UDP tunneling patterns (constant large datagrams)
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="udp"
>| stats avg(orig_bytes) as avg_out, count by id.orig_h, id.resp_h, id.resp_p
>| where avg_out>1000 AND count>100
>```
></details>
>
><details><summary>T1572 – Protocol Impersonation</summary>
>
><br>
>
>1. HTTPS on non-standard ports
>```spl
>index=bro sourcetype=corelight_ssl
>| where id.resp_p NOT IN (443, 8443)
>| stats count by id.orig_h, id.resp_h, id.resp_p
>```
>2. HTTP traffic on ports other than 80 or 8080
>```spl
>index=bro sourcetype=corelight_http
>| where id.resp_p NOT IN (80,8080)
>| stats count by id.orig_h, id.resp_h, id.resp_p
>```
>3. TLS sessions with missing SNI
>```spl
>index=bro sourcetype=corelight_ssl
>| where isnull(server_name)
>| stats count by id.orig_h, id.resp_h
>```
></details>
</details>

<details><summary>Exfiltration</summary>
  
---

><details><summary>T1041 - Exfiltration Over C2</summary>
>
><br>
>
>- T1041 often looks like normal traffic—combine these queries with known threat intel or baseline analysis.
>- Look for patterns like regular beacons, unusual data sizes, or traffic to newly registered domains.
>
><br>
>
>1. Detects DNS queries with unusually long domain names, which may be used for exfiltration.
>```spl
>index=bro sourcetype=corelight_dns
>| where length(query) > 100
>| stats count avg(length(query)) by query, orig_h, resp_h
>| where count > 10
>| sort -count
>```
>2. Flags hosts repeatedly querying the same domain, which might be tunneling data.
>```spl
>index=bro sourcetype=corelight_dns
>| stats count by orig_h, resp_h, query
>| where count > 100
>| sort -count
>```
>3. Detects excessive outbound HTTP POST traffic, which can indicate exfiltration via web.
>```spl
>index=bro sourcetype=corelight_http method=POST
>| stats count avg(resp_body_len) sum(resp_body_len) by orig_h, uri
>| where sum(resp_body_len) > 100000
>| sort -sum(resp_body_len)
>```
>4. Finds sessions that last too long and transfer large amounts of data.
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="tcp" AND duration > 300
>| stats count sum(orig_bytes) sum(resp_bytes) by orig_h, resp_h, service
>| where sum(orig_bytes) > 1000000
>| sort -sum(orig_bytes)
>```
>5. Detect SSL/TLS Sessions With Anomalous Data Volumes.
>```spl
>index=bro sourcetype=corelight_ssl
>| stats count sum(orig_bytes) sum(resp_bytes) by id.orig_h, id.resp_h, server_name
>| where sum(orig_bytes) > 500000
>| sort -sum(orig_bytes)
>```
></details>
>
><details><summary>T1041 – Exfiltration Over Command and Control Channel</summary>
>
><br>
>
>1. HTTP POST to external domains with large data volumes
>```spl
>index=bro sourcetype=corelight_http method=POST
>| stats count sum(resp_body_len) as total_bytes by id.orig_h, dest
>| where total_bytes > 1000000
>```
>2. HTTPS sessions with significant outbound traffic
>```spl
>index=bro sourcetype=corelight_ssl
>| stats sum(orig_bytes) as sent sum(resp_bytes) as received count by id.orig_h, id.resp_h, server_name
>| where sent > 500000
>```
>3. DNS queries with long subdomains (potential DNS tunneling)
>```spl
>index=bro sourcetype=corelight_dns
>| where len(query) > 100
>| stats count by orig_h, query
>| where count > 20
>```
>4. Frequent small DNS TXT queries (data encoding)
>```spl
>index=bro sourcetype=corelight_dns
>| where qtype_name="TXT"
>| stats count by orig_h, query
>| where count > 50
>```
></details>
>
><details><summary>T1020 – Automated Exfiltration</summary>
>
><br>
>
>1. Scheduled large file transfers via SMB
>```spl
>index=bro sourcetype=corelight_smb_files action="SMB::WRITE"
>| stats sum(size) as total_bytes by id.orig_h, id.resp_h, date_mday
>| where total_bytes > 100000000
>```
>2. Repeated daily SMB write patterns
>```spl
>index=bro sourcetype=corelight_smb_files action="SMB::WRITE"
>| timechart span=1d sum(size) as daily_bytes by id.orig_h
>| where daily_bytes > 50000000
>```
>3. Multiple FTP sessions with high data volume
>```spl
>index=bro sourcetype=corelight_ftp
>| stats sum(bytes) as total_bytes, count by id.orig_h, id.resp_h
>| where total_bytes > 5000000
>```
></details>
>
><details><summary>T1537 – Transfer Data to Cloud Account (Commonly Web Services)</summary>
>
><br>
>
>1. HTTPS uploads to unknown cloud endpoints
>```spl
>index=bro sourcetype=corelight_http method=POST
>| where dest NOT IN ("trusted-cloud1.com","trusted-cloud2.com")
>| stats sum(resp_body_len) as total_bytes by id.orig_h, dest
>| where total_bytes > 500000
>```
>2. SSL sessions to AWS, Azure, or GCP subdomains
>```spl
>index=bro sourcetype=corelight_ssl
>| search server_name IN ("*.amazonaws.com","*.blob.core.windows.net","*.cloud.google.com")
>| stats count sum(orig_bytes) as sent by id.orig_h, server_name
>```
>3. Frequent TLS connections to S3 or storage endpoints
>```spl
>index=bro sourcetype=corelight_ssl
>| search server_name IN ("*.s3.amazonaws.com","*.storage.googleapis.com")
>| stats count by id.orig_h, server_name
>| where count > 5
>```
></details>
</details>

<details><summary>Impact</summary>
  
---

><details><summary>T1486 – Data Encrypted for Impact</summary>
>
><br>
>
>1. Sudden spike in SMB write and delete actions
>```spl
>index=bro sourcetype=corelight_smb_files
>| stats count(eval(action="SMB::WRITE")) as writes, count(eval(action="SMB::DELETE")) as deletes by id.orig_h, id.resp_h
>| where writes > 100 AND deletes > 50
>```
>2. SMB writes followed by file renames or unusual extensions
>```spl
>index=bro sourcetype=corelight_smb_files
>| where filename IN ("*.locked", "*.encrypted", "*.crypt", "*.enc")
>| stats count by id.orig_h, id.resp_h, filename
>```
>3. Sharp increase in file modification across shares
>```spl
>index=bro sourcetype=corelight_smb_files
>| timechart span=10m count by id.orig_h
>```
></details>
>
><details><summary>T1490 – Inhibit System Recovery</summary>
>
><br>
>
>1. File deletes in recovery or backup directories via SMB
>```spl
>index=bro sourcetype=corelight_smb_files
>| search action="SMB::DELETE"
>| where path IN ("*/System Volume Information/*", "*/backup/*", "*/Recovery/*")
>| stats count by id.orig_h, id.resp_h, path
>```
>2. Delete or access to shadow copies over SMB
>```spl
>index=bro sourcetype=corelight_smb_files
>| search filename IN ("vssadmin.exe", "wbadmin.exe", "*shadow*")
>| stats count by id.orig_h, filename
>```
></details>
>
><details><summary>T1485 – Data Destruction</summary>
>
><br>
>
>1. High-volume file deletions via SMB
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::DELETE"
>| stats count by id.orig_h, id.resp_h
>| where count > 100
>```
>2. Deletion of specific file types (e.g., .doc, .xls)
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::DELETE" AND filename IN ("*.doc", "*.xls", "*.pdf")
>| stats count by id.orig_h, filename
>```
>3. Pattern of write → delete to same path
>```spl
>index=bro sourcetype=corelight_smb_files
>| stats count(eval(action="SMB::WRITE")) as writes, count(eval(action="SMB::DELETE")) as deletes by id.orig_h, id.resp_h
>| where writes > 0 AND deletes > 0
>```
></details>
>
><details><summary>T1491 – Defacement</summary>
>
><br>
>
>1. Web server uploads to index or homepage files
>```spl
>index=bro sourcetype=corelight_http method=POST
>| search uri IN ("/index.html", "/index.php", "/home.html")
>| stats count by id.orig_h, uri
>```
>2. HTTP POST to web directories with script extensions
>```spl
>index=bro sourcetype=corelight_http method=POST
>| where uri IN ("*.php", "*.jsp", "*.aspx")
>| stats count by id.orig_h, uri
>```
>3. Web shell or script file written via SMB
>```spl
>index=bro sourcetype=corelight_smb_files
>| where filename IN ("*.php", "*.asp", "*.jsp")
>| stats count by id.orig_h, id.resp_h, filename
>```
></details>
>
><details><summary>T1499 – Endpoint Denial of Service</summary>
>
><br>
>
>1. Repeated SMB sessions with maxed-out connections
>```spl
>index=bro sourcetype=corelight_conn
>| where service="smb"
>| stats count by id.orig_h, id.resp_h
>| where count > 100
>```
>2. Large-volume UDP floods (e.g., DNS, NTP, SSDP)
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="udp" AND id.resp_p IN (53, 123, 1900)
>| stats sum(orig_bytes) as total_bytes by id.orig_h, id.resp_h
>| where total_bytes > 10000000
>```
>3. TCP SYN floods without handshake completion
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="tcp" AND state="S0"
>| stats count by id.orig_h, id.resp_h
>| where count > 100
>```
></details>
>
><details><summary>T1498 – Network Denial of Service</summary>
>
><br>
>
>1. ICMP floods to internal infrastructure
>```spl
>index=bro sourcetype=corelight_icmp
>| where icmp_type=8
>| stats count by id.orig_h, id.resp_h
>| where count > 100
>```
>2. High-rate TCP SYNs to specific service
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="tcp" AND state="S0"
>| stats count by id.orig_h, id.resp_h, id.resp_p
>| where count > 200
>```
>3. Large bandwidth UDP flows to single target
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="udp"
>| stats sum(orig_bytes) as bytes_sent by id.orig_h, id.resp_h
>| where bytes_sent > 10000000
>```
></details>
</details>
