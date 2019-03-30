# arp-scanner
A multi-threaded and lightweight C# ARP scanner to identify live hosts in your LAN. 
The ARP scanner has been originally develop as a very portable Powershell script [ActiveARP.ps1](https://github.com/giuliocomi/posh-discovery/blob/master/cmdlets/ActiveARP.ps1).

This standalone solution might be useful for quickly discover hosts in the subnet when ICMP requests are filtered by the live hosts.

## Features
1) Multi threaded scanner
2) Essentiality and portability
3) Discover live hosts on your LAN despite of filtered ICMP packets 
4) Identify the manufacturer details of the interface by resolving the MAC

## Notes
The [maclist.txt](https://github.com/giuliocomi/arp-scanner/blob/master/maclist.txt) file must be downloaded to be able to resolve the MAC.
The input file with the target IP addresses can be easily generated with the Powershell script [CalculateRange.ps1](https://github.com/giuliocomi/posh-discovery/blob/master/cmdlets/CalculateRange.ps1).
A timeout (in ms) can be set through command line. 

## Examples

![Output Example](https://user-images.githubusercontent.com/26773527/55280325-73e7a600-5324-11e9-85cb-491a1a429c95.png)

## Issues
Spot a bug? Please create an issue here on GitHub (https://github.com/giuliocomi/arp-scanner/issues)

## License
This project is licensed under the  GNU general public license Version 3.
