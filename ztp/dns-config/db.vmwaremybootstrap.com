$ORIGIN .
$TTL 10	; 10 seconds
vmwaremybootstrap.com	IN SOA	ns1.vmwaremybootstrap.com. hostmaster.vmwaremybootstrap.com. (
				2018080152 ; serial
				120        ; refresh (2 minutes)
				120        ; retry (2 minutes)
				2419200    ; expire (4 weeks)
				120        ; minimum (2 minutes)
				)
			NS	ns1.vmwaremybootstrap.com.
$ORIGIN vmwaremybootstrap.com.
$TTL 30	; 30 seconds
ipv4			A	192.168.254.244
ipv4v6			A	192.168.254.244
ns1			A	192.168.254.244
$ORIGIN sub.vmwaremybootstrap.com.
$TTL 60	; 1 minute
5aa4a687-b8a6-1700-849c-b8aeedec1090 A 10.10.10.1
$TTL 86400	; 1 day