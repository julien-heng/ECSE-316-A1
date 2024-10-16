# Network Programming and DNS 
ECSE 316 | Assignment 1 | Julien Heng, Sophia Li

## Run the Program
This program was written and tested with Python version 3.9.6.

### How to Run

The program should be invoked at the command line. The command is structured as follows:
```
python3 dnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name
```
- `timeout (optional)` gives how long to wait, in seconds, before retransmitting an unanswered query. Default value: 5.
- `max-retries (optional)` is the maximum number of times to retransmit an unanswered query before giving up. Default value: 3.
- `port (optional)` is the UDP port number of the DNS server. Default value: 53.
- `-mx or -ns flags (optional)` indicate whether to send a MX (mail server) or NS (name
server) query. At most one of these can be given, and if neither is given then the client should
send a type A (IP address) query.
- `server (required)` is the IPv4 address of the DNS server, in a.b.c.d. format.
- `name (required)` is the domain name to query for.

### Sample Commands

Query for www.mcgill.ca IP address using the McGill DNS server:
```
python3 dnsClient.py @132.206.85.18 www.mcgill.ca
```
Query for the mcgill.ca mail server using Google’s public DNS server with a timeout of 10 seconds and at most 2 retries:
```
python3 dnsClient.py -t 10 -r 2 -mx @8.8.8.8 mcgill.ca
```

