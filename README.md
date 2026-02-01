# Sniffer IP Header Decode

A simple raw socket based IP header sniffer written in Python.  
This tool captures incoming packets and decodes essential parts of the IP header, such as protocol type, source address, and destination address.

## Features
- Uses raw sockets to sniff network packets
- Extracts and parses IP header fields
- Maps protocol numbers to human-readable protocol names
- Works on Linux and Windows (with small differences in socket behavior)

## Requirements
- Python 3.x
- Root privileges (required for raw sockets)
- Linux or Windows environment

## Usage
1. Update the `host` variable with the IP address of the interface you want to listen on.
2. Run the script:

```bash
sudo python3 sniffer_ip_header_decode.py
```
3. The script will print detected network packets in the following format:
Protocol: <protocol> <source_ip> -> <destination_ip>



## Disclaimer

This project is intended for educational and testing purposes only.
Do not use packet sniffing tools on networks you do not own or administer.
License

# MIT License
