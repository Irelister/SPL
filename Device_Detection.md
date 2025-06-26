<details><summary>Detect ASA device by known SSL certificate common names or issuers</summary>
  
```plaintext
index=bro sourcetype=corelight_ssl
| search subject="*ASA*" OR issuer="*Cisco*" OR subject="*cisco*" OR issuer="*ASA*"
| stats count by src_ip, dest_ip, subject, issuer
```
</details>

<details><summary>Detecting a Cisco ASA</summary>
  
```plaintext
index=bro sourcetype=corelight_notice OR sourcetype=corelight_http
| search notice.msg="*ASA*" OR uri="*/admin/*" OR uri="*/asdm/*"
| stats count by id.resp_h, uri

index=bro sourcetype=corelight_conn
| where id.resp_p IN (443, 8443, 4444)
| stats avg(duration) as avg_dur, count by id.resp_h, id.resp_p
| where avg_dur < 2

index=bro sourcetype=corelight_ssl
| search ja3="*cisco_known_ja3_hash*"
| stats count by id.resp_h, ja3
```
</details>