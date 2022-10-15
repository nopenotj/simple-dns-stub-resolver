# simple dns stub resolver

Just a simple implementation of a stub resolver implemented according to the DNS protocol (refer to [rfc1035](https://datatracker.ietf.org/doc/html/rfc1035))


To run `./dns.py <domain name>`

Example
```bash
> ./dns.py google.com

google.com. 74.125.24.139
google.com. 74.125.24.101
google.com. 74.125.24.113
google.com. 74.125.24.100
google.com. 74.125.24.102
google.com. 74.125.24.138
```