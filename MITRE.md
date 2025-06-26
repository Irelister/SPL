<details><summary>Reconnaissance</summary>
  
---

</details>

<details><summary>Resource Development</summary>
  
---

<details><summary>T1584 - Compromise Infrastructure</summary>

<br>

1. Multiple Domains Resolve to the same IP.
```spl
index=central_summary source=summary_dns_with_answers 
| stats dc(query) as domain_count by answer 
| where domain_count > 10 
```
2. Rare JA3 and JA3S TLS Fingerprints
```spl
index=central_summary source=summary_ssl 
| stats count by ja3, ja3s, dest_ip 
| where count < 5 
```
3. Unusual HTTP Hosts or Repeating POSTS Requests
```spl
index=bro sourcetype=corelight_http 
| search method=POST 
| stats count by src_ip, dest_ip, host_header, uri, user_agent 
| where count > 20 
```
4. High Volume, Long-Lived Peer-to-Peer Connections
```spl
index=bro sourcetype=corelight_conn 
| search duration > 300 
| stats count by src_ip, dest_ip, duration, service 
| where count > 20 
```
</details>
</details>

<details><summary>Initial Access</summary>
  
---

</details>

<details><summary>Execution</summary>
  
---

</details>

<details><summary>Persistence</summary>
  
---

<details><summary>T1136 - Create Account</summary>

<br>

1. Kerberos AS-REQ or TGS-REQ from Previously Unknown Username A newly created domain account may trigger initial Kerberos activity.
```spl
index=bro sourcetype=corelight_kerberos
| stats earliest(_time) as first_seen by client
| where first_seen >= relative_time(now(), "-1d@d")
```
2. LDAP Activity Indicating Account Creation.
```spl
index=bro sourcetype=corelight_ldap
| search query IN ("userPrincipalName", "objectClass=user", "sAMAccountName")
| stats count by id.orig_h, base_dn, query, result, _time
```
3. Suspicious File Access to SAM Hive.
```spl
index=bro sourcetype=corelight_smb_files
| search filename="\\windows\\system32\\config\\sam"
| stats count by id.orig_h, id.resp_h, filename, action, _time
```
</details>

<details><summary>T1505 - Server Software Component</summary>

<br>

1. Web shells often receive commands via POST.
```spl
index=bro sourcetype=corelight_http 
| search method=POST
| search uri IN ("*.php*", "*.aspx*", "*.jsp*", "*cmd*", "*eval*", "*shell*")
| stats count by id.orig_h, id.resp_h, uri, user_agent, method, status_code, _time
```
2. Look for indicators in query strings or URIs.
```spl
index=bro sourcetype=corelight_http
| search uri IN ("*cmd=*", "*exec*", "*eval*", "*shell*", "*.php", "*.asp", "*.jsp")
| stats count by id.orig_h, id.resp_h, uri, user_agent, referrer, status_code, _time
```
3. Web shells are often uploaded through file upload features.
```spl
index=bro sourcetype=corelight_http 
| search method=POST uri IN ("*/upload*", "*/admin*", "*/file*", "*.php*", "*.asp*")
| stats count by id.orig_h, id.resp_h, uri, user_agent, status_code, content_type, _time
```
4. Newly Seen Files in Webroot (e.g., .php or .jsp)
```spl
index=bro sourcetype=corelight_files 
| search filename IN ("*.php", "*.jsp", "*.asp", "*.aspx")
| stats count by id.orig_h, id.resp_h, filename, mime_type, seen_bytes, _time
```
5. SMB File Writes to Webroot (If logs available)
```spl
index=bro sourcetype=corelight_smb_files 
| search filename IN ("*.php", "*.asp", "*.jsp") AND action="WRITE"
| stats count by id.orig_h, id.resp_h, filename, action, _time
```
6. Large response sizes from small POSTs (Shell response)
```spl
index=bro sourcetype=corelight_http
| eval ratio=response_body_len/request_body_len 
| where method="POST" AND ratio > 10
| stats count by id.orig_h, id.resp_h, uri, user_agent, ratio, _time
```
</details>
</details>

<details><summary>Privilege Escalation</summary>
  
---

</details>

<details><summary>Defense Evasion</summary>
  
---

  <details><summary>T1564 - Hide Artifacts</summary>
  
  <br>
  
  1. 
  ```spl
  
  ```
  </details>
</details>

<details><summary>Credential Access</summary>
  
---

</details>

<details><summary>Discovery</summary>
  
---

><details><summary>T1033 - System Owner & User Discovery</summary>
>
><br>
>
>1. 
>```spl
>
>```
></details>

<details><summary>T1069 - Permission Groups Discovery</summary>

<br>

1. 
```spl
index=bro sourcetype=corelight_ldap
| search base_dn="CN=Users*" OR base_dn="CN=Groups*" OR query IN ("memberOf", "primaryGroupID")
| stats count by id.orig_h, base_dn, query, result, _time
```
2. Suspicious enumeration may cause high volumes of TGS-REQ to services like ldap, cifs, krbtgt, etc.
```spl
index=bro sourcetype=corelight_kerberos
| search service IN ("ldap", "krbtgt", "cifs")
| stats count by id.orig_h, id.resp_h, client, service, request_type, _time
```
3. Common during domain reconnaissance
```spl
index=bro sourcetype=corelight_dns 
| search query IN ("_ldap._tcp.*", "_kerberos._tcp.*", "*dc._msdcs*")
| stats count by id.orig_h, query, qtype_name, _time
```
4. These shares are often accessed during domain enumeration or GPO gathering.
```spl
index=bro sourcetype=corelight_smb_mapping
| search path IN ("\\*\\SYSVOL", "\\*\\NETLOGON")
| stats count by id.orig_h, id.resp_h, path, share_type, _time
```
5. Look for one IP performing a lot of queries.
```spl
index=bro sourcetype=corelight_ldap OR sourcetype=corelight_kerberos
| stats count by id.orig_h, sourcetype, _time
| where count > 100
```
6. Movement of Suspicious Files via SMB
```spl
index=zeek sourcetype=zeek_smb_files
| search filename IN ("\\windows\\system32\\config\\sam", "\\windows\\system32\\config\\system")
| stats count by id.orig_h, id.resp_h, filename, action, _time
```
7. Find High Volume SMB Mapping Commands
```spl
index=zeek sourcetype=zeek_smb_mapping
| stats count by id.orig_h, id.resp_h, path, share_type, _time
```
</details>
</details>

<details><summary>Lateral Movement</summary>
  
---

</details>

<details><summary>Collection</summary>
  
---

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

<details><summary>Suspicious File Transfers Over SMB</summary>
  
```spl
index=central_summary source=summary_smb_files filename_with_extension IN ("lsass.dmp" *.dmp "procdump.exe") 
| stats count by src_ip, dest_ip, filename_with_extension, action 
```
</details>

<details><summary>Execution or Transfer of Credential Dumping Tools</summary>
  
```spl
index=central_summary source=summary_http_address uri IN (*procdump* *mimikatz* *lsass* *comsvcs*) 
| stats count by src_ip, dest_ip, uri 

Index=bro sourcetype=corelight_http uri IN (*procdump* *mimikatz* *lsass* *comsvcs*) 
| stats count by src_ip, dest_ip, uri, user_agent 
```
</details>

<details><summary>Remote Access to LSASS via RPC or SAMR</summary>
  
```spl
index=bro sourcetype=corelight_rpc 
| search program IN ("samr", "lsarpc") 
| stats count by src_ip, dest_ip, call 
```
</details>

<details><summary>Suspicious SMB Uploads from Admin Workstations</summary>
  
```spl
index=bro sourcetype=corelight_smb_cmd command="WRITE"
| stats count by src_ip, dest_ip, command 
```
</details>

<details><summary>Dump Files Exfiltrated Over HTTP</summary>
  
```spl
index=central_summary source=summary_http_address uri IN (*.dmp *.zip) 
| stats count by src_ip, dest_ip, uri 
```
</details>

##T1564 Hide Artifacts

<details><summary>Detect File Transfers with Suspicious or Hidden Filenames</summary>
  
```spl
index=zeek sourcetype=zeek:files 
| where isnull(extracted) AND (filename LIKE ".%" OR filename IN ("thumbs.db", "desktop.ini")) 
| eval risk="Possible hidden file transfer"
| table _time, uid, source, destination, filename, mime_type, risk
```
</details>

<details><summary>Detect Executable Files from Suspicious Directories via SMB</summary>
  
```spl
index=zeek sourcetype=zeek:smb_files 
| where filename LIKE "%.exe" AND (filename LIKE "%\\$Recycle.Bin\\%" OR filename LIKE "%\\Temp\\%") 
| eval risk="Executable file in suspicious hidden folder"
| table _time, id_orig_h, id_resp_h, filename, action, seen_bytes, risk
```
</details>

<details><summary>Detect Long SSH Sessions</summary>
  
```spl
index=zeek sourcetype=zeek:ssh 
| search auth_success=true 
| join type=inner uid [ search index=zeek sourcetype=zeek:conn ] 
| where service=="ssh" AND duration>300 
| eval risk="Long SSH session; check for hidden or file manipulation"
| table _time, id_orig_h, id_resp_h, duration, auth_success, risk
```
</details>

<details><summary>Detect Archive Files with Suspicious Naming or Locations</summary>
  
```spl
index=zeek sourcetype=zeek:files 
| where mime_type IN ("application/zip", "application/x-rar-compressed") AND filename LIKE "%.%" 
| search filename=".%" OR filename LIKE "%\\Temp\\%" 
| eval risk="Possible hidden archive"
| table _time, id_orig_h, id_resp_h, filename, mime_type, risk
```
</details>

<details><summary>Look for Uncommon File Extensions Used Over HTTP or SMB</summary>
  
```spl
index=zeek sourcetype=zeek:files 
| where mime_type="application/octet-stream" AND NOT filename LIKE "%.exe" AND NOT filename LIKE "%.dll" 
| eval risk="Unusual binary transfer - possible renamed executable or payload"
| table _time, filename, mime_type, id_orig_h, id_resp_h, risk
```
</details>
