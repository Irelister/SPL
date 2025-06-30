<details><summary>Reconnaissance</summary>
  
---

<details><summary>T1595 – Active Scanning</summary>

<br>

1. High-volume connection attempts (port scanning)

```spl
index=bro sourcetype=corelight_conn
| stats dc(id.resp_p) as ports_scanned, count by id.orig_h
| where ports_scanned > 50 AND count > 100
```

2. Many TCP SYNs with no responses (S0 state)

```spl
index=bro sourcetype=corelight_conn
| where proto="tcp" AND state="S0"
| stats count by id.orig_h, id.resp_h
| where count > 20
```

3. Zeek notices for scanning behavior

```spl
index=bro sourcetype=corelight_notice
| search note="SCAN::Port_Scan"
| stats count by src
```

</details>

<details><summary>T1593 – Search Open Technical Databases (OSINT)</summary>

<br>

1. Outbound DNS queries to OSINT sites

```spl
index=bro sourcetype=corelight_dns
| search query IN ("*.whois.com", "*.shodan.io", "*.censys.io")
| stats count by orig_h, query
```

2. HTTP requests to recon tools

```spl
index=bro sourcetype=corelight_http
| search host IN ("shodan.io", "censys.io", "intelx.io")
| stats count by id.orig_h, host, uri
```

3. SSL connections to public certificate search sites

```spl
index=bro sourcetype=corelight_ssl
| search server_name IN ("*.crt.sh", "*.censys.io")
| stats count by id.orig_h, server_name
```

</details>

<details><summary>T1592 – Gather Victim Host Information</summary>

<br>

1. SMB enumeration of shares or host info

```spl
index=bro sourcetype=corelight_smb
| search smb_cmd="SMB::TREE_CONNECT" OR smb_cmd="SMB::QUERY_INFORMATION"
| stats count by id.orig_h, id.resp_h, smb_cmd
```

2. RPC or WMI behavior (port 135)

```spl
index=bro sourcetype=corelight_conn
| where id.resp_p=135 AND proto="tcp"
| stats count by id.orig_h, id.resp_h
```

3. Kerberos TGS requests to many systems

```spl
index=bro sourcetype=corelight_kerberos
| where request_type="TGS_REQ"
| stats dc(id.resp_h) as host_count by id.orig_h
| where host_count > 5
```

</details>

<details><summary>T1598 – Gather Victim Network Information</summary>

<br>

1. ICMP echo requests (ping sweep)

```spl
index=bro sourcetype=corelight_icmp
| where icmp_type=8
| stats count by id.orig_h, id.resp_h
| where count > 20
```

2. Unusual DNS query types (ANY, TXT)

```spl
index=bro sourcetype=corelight_dns
| where qtype_name IN ("TXT", "ANY")
| stats count by orig_h, query, qtype_name
```

3. Access to infrastructure ports (SNMP, Syslog, Telnet)

```spl
index=bro sourcetype=corelight_conn
| where id.resp_p IN (161, 162, 514, 23)
| stats count by id.orig_h, id.resp_h, id.resp_p
```
</details>
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

<details><summary><strong>T1190 – Exploit Public-Facing Application</strong></summary>

<br>

1. **HTTP 500–599 Errors on External Apps**

```spl
index=bro sourcetype=corelight_http
| where status>=500 AND status<600
| stats count by id.orig_h, uri, status
| sort -count
```

2. **Suspicious POST Requests to Unknown URIs**

```spl
index=bro sourcetype=corelight_http method=POST
| where uri!="*" AND uri!="/"
| stats count by id.orig_h, uri
| where count > 20
```

3. **High Data POSTs to External Apps**

```spl
index=bro sourcetype=corelight_http method=POST
| stats sum(resp_body_len) as data_sent count by id.orig_h, uri
| where data_sent>1000000
```
</details>

<details><summary><strong>T1078 – Valid Accounts</strong></summary>

<br>

1. **Successful Logins via RDP**

```spl
index=bro sourcetype=corelight_rdp
| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
| where count > 0
```

2. **Successful SSH Connections**

```spl
index=bro sourcetype=corelight_ssh auth_success=true
| stats count by id.orig_h, id.resp_h
```

3. **SMB Logins Without Failures**

```spl
index=bro sourcetype=corelight_smb smb_cmd="SMB::SESSION_SETUP" smb_status="SUCCESS"
| stats count by id.orig_h, id.resp_h, user
```
</details>

<details><summary><strong>T1566 – Phishing</strong></summary>

<br>

1. **HTTP/S Download of Executable Attachments**

```spl
index=bro sourcetype=corelight_http
| search uri IN ("*.exe","*.scr","*.vbs","*.zip")
| stats count by id.orig_h, uri
```

2. **Email Attachment URLs (If SMTP Logging Exists)**

```spl
index=bro sourcetype=corelight_smtp
| search uri IN ("*.exe","*.zip","*.scr")
| stats count by id.orig_h, uri
```

3. **Suspicious HTTP POST to Rare Domains**

```spl
index=bro sourcetype=corelight_http method=POST
| stats dc(uri) as uri_count by id.orig_h, dest
| where uri_count=1 AND dest!="trusted.domain"
```
</details>

<details><summary><strong>T1199 – Trusted Relationship</strong></summary>

<br>

1. **Inbound VPN-Like UDP Traffic**

```spl
index=bro sourcetype=corelight_conn
| where proto="udp" AND id.resp_p IN (1194, 500, 4500)
| stats sum(orig_bytes) as bytes count by id.orig_h, id.resp_h
| where count>0
```

2. **External TLS Sessions Into Perimeter**

```spl
index=bro sourcetype=corelight_ssl
| where id.orig_h NOT IN ("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| stats count by id.orig_h, id.resp_h, server_name
```

3. **Inbound RDP From External Networks**

```spl
index=bro sourcetype=corelight_conn service="rdp"
| where id.orig_h NOT IN ("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")
| stats count by id.orig_h, id.resp_h
```
</details>

<details><summary><strong>T1133 – External Remote Services</strong></summary>

<br>

1. **Inbound RDP Connections from External IPs**

```spl
index=bro sourcetype=corelight_conn
| where service="rdp" AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
| stats count by id.orig_h, id.resp_h, duration
```

2. **Inbound SSH Sessions from External IPs**

```spl
index=bro sourcetype=corelight_conn
| where service="ssh" AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
| stats count by id.orig_h, id.resp_h
```

3. **External Access to SMB from Outside**

```spl
index=bro sourcetype=corelight_conn
| where service="smb" AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
| stats count by id.orig_h, id.resp_h
```

4. **VPN-Like UDP Traffic (e.g., IPsec 500/4500)**

```spl
index=bro sourcetype=corelight_conn
| where proto="udp" AND id.resp_p IN (500,4500)
| stats sum(orig_bytes) as total_bytes, count by id.orig_h, id.resp_h
| where total_bytes > 1000000
```
5. **Remote Admin Ports (22,3389,5985,5986) From External**
```spl
index=bro sourcetype=corelight_conn
| where id.resp_p IN (22,3389,5985,5986)
  AND id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
| stats count by id.orig_h, id.resp_h, id.resp_p
```
6. **Long-Lived Connections from External**
```spl
index=bro sourcetype=corelight_conn
| where id.orig_h NOT IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12")
  AND duration > 600
| stats duration, orig_bytes, resp_bytes by id.orig_h, id.resp_h, service
```
</details>
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
>
>2. Look for connections to admin SMB shares, common when scripts or remote access tools are used for cleanup.
>```spl
>index=bro sourcetype=corelight_smb
>| search path IN ("ADMIN$", "C$", "D$", "IPC$")
>| stats count by id.orig_h, id.resp_h, path, user
>```
>
>3. Look for short duration RDP connections. Short bursts of RDP can indicate someone quickly connecting just to clean up.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 3 AND avg_duration < 60
>```
>
>4. Detect the downloads of cleanup tools (sdelete, wevtutil, etc.)
>```spl
>index=bro sourcetype=corelight_http
>| search uri IN ("*sdelete*", "*wevtutil*", "*clear_event*", "*wipe*", "*rm.exe*", "*del.exe*")
>| stats count by uri, id.orig_h, id.resp_h, user_agent
>```
>
>5. Detect suspicious SMB file transfers including executables.
>
>```spl
>index=bro sourcetype=corelight_files
>| where mime_type="application/x-dosexec"
>| stats count by id.orig_h, id.resp_h, filename, fuid
>```
>
>6. Find bulk SMB file transfers followed by deletions.
>
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
>
>2. Detect suspicious TLS Without SNI (Server Name Indication)
>```spl
>index=bro sourcetype=corelight_ssl
>| where isnull(server_name)
>| stats count by id.orig_h, id.resp_h
>```
>
>3. Detect HTTP with Suspicious User-Agents or Missing Headers
>```spl
>index=bro sourcetype=corelight_http
>| search user_agent="-" OR user_agent="curl*" OR user_agent="python*" OR user_agent="powershell*"
>| stats count by id.orig_h, id.resp_h, user_agent
>```
>
>4. Detect abnormal File Transfers in HTTP with Mismatched MIME Types.
>```spl
>index=bro sourcetype=corelight_http
>| where mime_type!="application/octet-stream" AND uri matches ".exe|.zip|.bin|.dll"
>| stats count by id.orig_h, uri, mime_type
>```
>
>5. Detect covert Channels in DNS (e.g., Data Hidden in Queries).
>```spl
>index=bro sourcetype=corelight_dns
>| where length(query) > 100 OR query matches ".*[0-9a-f]{30,}.*"
>| stats count by id.orig_h, query
>```
>
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
>
>2. Detect suspicious files transfered via SMB or HTTP. Credential dump files often have .dmp, .bin, or are zipped/encoded.
>```spl
>index=bro sourcetype=corelight_files
>| search filename IN ("*lsass*", "*dump*", "*.dmp", "*.zip", "*.ps1", "*.bin")
>| stats count by id.orig_h, id.resp_h, filename, mime_type
>```
>
>3. Detect dump files being copied or staged for exfil — over 10MB is a red flag.
>```spl
>index=bro sourcetype=corelight_smb_files
>| where action="SMB::WRITE"
>| stats sum(size) as total_bytes, count by id.orig_h, id.resp_h, name
>| where total_bytes > 10000000
>| sort -total_bytes
>```
>
>4. Short, frequent RDP sessions — may be used to quickly run tools like Mimikatz.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 3 AND avg_duration < 60
>```
>
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
>
>2. Excessive RDP attempts with short duration may indicate brute-force behavior.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) by id.orig_h, id.resp_h
>| where count > 10 AND avg(duration) < 10
>| sort -count
>```
>
>3. Looks for excessive failed SSH logins — common in brute-force scenarios.
>```spl
>index=bro sourcetype=corelight_ssh
>| stats count by id.orig_h, id.resp_h, auth_success
>| where auth_success=false AND count > 10
>```
>
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
>
>2. WMI queries over RPC (TCP 135) often used to gather system and user info.
>```spl
>index=bro sourcetype=corelight_conn
>| where id.resp_p=135 AND proto="tcp"
>| stats count by id.orig_h, id.resp_h
>| where count > 5
>```
>
>3. Brief RDP logins could be used just to list users/sessions.
>```spl
>index=bro sourcetype=corelight_rdp
>| stats count, avg(duration) as avg_duration by id.orig_h, id.resp_h
>| where count > 3 AND avg_duration < 60
>```
>
>4. Detect kerberos AS-REQ without TGT request (User Probing). Indicates probing for users without actually requesting tickets (Kerberoasting-related discovery).
>```spl
>index=bro sourcetype=corelight_kerberos
>| where request_type="AS_REQ" AND isnull(ticket_id)
>| stats count by id.orig_h, id.resp_h, client, service
>```
>
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

</details>

<details><summary>Collection</summary>
  
---

><details><summary>T1560 - Archive Collected Data</summary>
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

<details><summary>Command and Control</summary>
  
---

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
>
>2. Flags hosts repeatedly querying the same domain, which might be tunneling data.
>```spl
>index=bro sourcetype=corelight_dns
>| stats count by orig_h, resp_h, query
>| where count > 100
>| sort -count
>```
>
>3. Detects excessive outbound HTTP POST traffic, which can indicate exfiltration via web.
>```spl
>index=bro sourcetype=corelight_http method=POST
>| stats count avg(resp_body_len) sum(resp_body_len) by orig_h, uri
>| where sum(resp_body_len) > 100000
>| sort -sum(resp_body_len)
>```
>
>4. Finds sessions that last too long and transfer large amounts of data.
>```spl
>index=bro sourcetype=corelight_conn
>| where proto="tcp" AND duration > 300
>| stats count sum(orig_bytes) sum(resp_bytes) by orig_h, resp_h, service
>| where sum(orig_bytes) > 1000000
>| sort -sum(orig_bytes)
>```
>
>5. Detect SSL/TLS Sessions With Anomalous Data Volumes.
>```spl
>index=bro sourcetype=corelight_ssl
>| stats count sum(orig_bytes) sum(resp_bytes) by id.orig_h, id.resp_h, server_name
>| where sum(orig_bytes) > 500000
>| sort -sum(orig_bytes)
>```
></details>
</details>

<details><summary>Impact</summary>
  
---

</details>
