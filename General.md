<details><summary>Bro Query</summary>
  
```spl
index=bro sourcetype=corelight_conn earliest= latest=now()
```
</details>

<details><summary>Summary Index Query</summary>
  
```spl
index=central_summary source=summary_conn_dest earliest= latest=now()
```
</details>

<details><summary>List all Indexes</summary>
  
```spl
| eventcount summarize=false index=* | dedup index | fields index
```
</details>

<details><summary>List Index Sources/Types w/ Timestamps</summary>
  
```spl
| metadata type="sourcetypes" index="bro"
| fieldformat firstTime=strftime(firstTime, "%m/%d/%y %H:%M:%S")
| fieldformat lastTime=strftime(lastTime, "%m/%d/%y %H:%M:%S")
```
</details>

<details><summary>List Fields for a Source/type</summary>
  
```plaintext
index="bro" sourcetype="corelight_bacnet"
| fieldsummary
| fields field

index="asset_summary" source="summary_conn_allowed"
| fieldsummary
| fields field
```
</details>

<details><summary>All Conns for an IP</summary>
  
```plaintext
index="bro" sourcetype="corelight_conn" dest_ip=<IP> OR src_ip=<IP> earliest=<first_seen> latest=<last_seen>
| table src_ip, src_port, orig_bytes, dest_ip, dest_port, dest_bytes
```
</details>

<details><summary>Domain Controllers</summary>
  
```plaintext
index=bro sourcetype=corelight_kerberos request_type=AS success=true
| table app, dest_ip 
| dedup app, dest_ip
```
</details>

<details><summary>Hostname via DNS</summary>
  
```plaintext
index=bro sourcetype=corelight_dns answer=<ip>
| table query, answer
| head 15
```
</details>

<details><summary>Internal Web Servers</summary>
  
```plaintext
index=bro sourcetype IN (corelight_http, corelight_ssl) is_dest_internal_ip=true
| dedup dest_port
| table dest_ip, dest_port, sum(bytes_out), url_domain, server_name, ja4s
```
</details>

<details><summary>Network DHCP Info</summary>
  
```plaintext
index=bro sourcetype=corelight_dhcp
| rename client_fqdn as dhcp_server
| rename dest_dns as assigned_dns
| table assigned_addr, dest_mac, lease_time, domain, dhcp_server, assigned_dns
```
</details>