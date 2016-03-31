# CSEC Alarm

This is a small program that monitors wireless packets for any access points that don't belong and creates an alert when it occurs.

Protecting a large WLAN network is an issue for network administrators as attackers can setup their own wireless access point with the same SSID as your network's and analyse the traffic as unsuspecting users connect and use the attacker's wireless access point.

This program serves as a way of detecting those attackers by passively listening to the wireless access points broadcasting their presence. Using a known whitelist of access points that belong to your network, this tool compares all access points that it detects with the whitelist. If any access points have the same SSID, but aren't a part of the whitelist, an alert is issued to notify a network administrator of the rogue access point.

## Requirements
Before running this software, a few dependencies are needed.

 - A system able to passively listen to network traffic
 - Java 1.7 or greater
 - Maven 3
 - The following tools installed on the system and given sudo access:
     - airmon-ng
     - start
     - stop
     - nmcli
     - pkill
     - service
     - iwconfig


## Running
Execute ```script/run``` from the root of the project directory.
