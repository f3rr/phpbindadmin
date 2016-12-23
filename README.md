# phpbindadmin
It's a one file nsupdate based PHP BIND9 Admin site

## Requirenments
* Webserver
* php with ldap module
* nsupdate
* dig

## Features
* Can add DNS record via nsupdate
* Can delete DNS record via nsupdate
* Check A Record for PTR Entry
* Check CNAME for valid destination IP at the end of the chain.
* Checks PTR for the corresponding A Record.

## Configuration
The head of index.php is the configuration part:

```
$zones = ['example.com', '10.10.10.in-addr.arpa']; // or place to zones.txt, new line/zone.
$types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV']; // PTR Automatically added for rev zones.
$server = "127.0.0.1";
$keystring = "web-nsupdate a3t7gPAt3r6osCX7d4rW1k==";
$default_ttl = "3600";  // Default TTL for new records
$manage_reverse = true;  // Manage PTR with A, if we manage Reverse Zone.
$logging = true;  // Enable auditing (true/false)
$auditlog = "bindadmin.log"; // Logfile
// Ldap
$ldap_enforce_login = true;  // Enable ldap (true/false), if false anyone can change dns.
$ldap_server = "127.0.0.1"; // ldap ip/host
$ldap_bind_dn = "CN=LOGIN,OU=Example,OU=User,DC=example,DC=com"; // Bind DN, "LOGIN" will be replaced with user login
$ldap_base = "DC=example,DC=com";
$ldap_filter = '(&(objectClass=user)(cn=LOGIN))'; // Filter for users. LOGIN will be replaced with user login
```

## Todo
* Add user group support
* Better Access restrictions
* Add Modify record Form
