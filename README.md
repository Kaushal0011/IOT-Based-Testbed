This project is funded by IIT Kanpur in collaboration with IIITA, under the guidance of Dr. S. Venkatesan, A web interface tool focuses on automating network-level attacks on IoT (Internet of Things) devices. The objective is to highlight vulnerabilities by performing SSH downgrade, ARP poisoning, and Deauth attacks. Scripts are written to first gather details such as the OS version, MAC address, and certificate validity of IoT devices, followed by the execution of these attacks while it is necessary that the attacker and adversary is in the same network and IP address of targeted address should be known.
The growing deployment of IoT devices in everyday life presents unique security challenges. These devices often have limited security mechanisms, making them prime targets for attacks, especially when they operate on the same local network as the attacker.
Initial Phase: Gathering Device Information
OS Version Detection:
Purpose: Identifying the operating system version allows attackers to check if the device is running vulnerable or outdated software.
Method: Tools such as nmap can be used to scan the device and gather OS details. A script can automate this process to detect multiple devices on the same network.
Example: Running nmap -O <target_IP> provides the OS version of the IoT device, revealing potential downgrade vulnerabilities.
MAC Address Identification:
Purpose: The MAC address uniquely identifies devices on the local network. Attackers need this information to perform ARP spoofing or deauthentication attacks.
Method: Network scanning tools such as arp-scan. A script could automate the capture of ARP packets to extract this information.
Certificate Validity Check:
Purpose: IoT devices often rely on SSL/TLS or SSH certificates for secure communication. Checking for expired or misconfigured certificates helps identify weaknesses in the encryption.
Method: A script can analyze SSL/TLS certificates or SSH details to determine if the certificates are expired or not properly configured.
After gathering this information, the attacker can proceed with the specific attacks that are most suitable based on the vulnerabilities identified.

1. SSH Downgrade Attack on IoT Devices
Overview
An SSH downgrade attack involves forcing an SSH connection to downgrade to an older version of the protocol, such as SSHv1, which has known vulnerabilities. This attack weakens the encryption strength of the communication, allowing an attacker to intercept and decrypt sensitive data alongside with already used attack scripts and methods of known vulnerabilities.
Attack Execution in IoT Context
Prerequisites: The attacker must know the IP address of the IoT device and be on the same network to intercept the SSH connection.
Script Process:
Intercept SSH Handshake: The script intercepts the initial handshake between the IoT device and its SSH management server.
Downgrade the Protocol: By modifying the handshake, the attacker forces the device to use a weaker protocol version (e.g., SSHv1 instead of SSHv2).
Exploit Weak Encryption: With the downgraded protocol, the attacker can decrypt traffic, steal credentials, or even gain unauthorized access to the device.
Tools and Scripting
A Python script using paramiko or low-level packet manipulation with scapy can automate this process by tampering with the handshake protocol negotiation.
Example: An IoT smart camera uses SSH for remote management. The attacker downgrades the SSH connection to a vulnerable version and intercepts credentials, gaining control of the camera feed.
2. ARP Poisoning Attack on IoT Devices
Overview
ARP poisoning, or ARP spoofing, is a man-in-the-middle attack that allows an attacker to associate their MAC address with the IP address of another device, generally the network's default gateway. By doing this, the attacker can intercept, modify, or block traffic between the IoT device and the rest of the network.This can be critical if attacker can perform this attack Since, IoT devices communication is not very securely encrypted or it is feasible to break.
Attack Execution in IoT Context
Prerequisites: The attacker must be on the same local network and have identified the target IoT device’s IP and MAC address.
Script Process:
Send Spoofed ARP Responses: The script sends false ARP replies to the target IoT device and the gateway, associating the attacker’s MAC address with the IP address of the gateway.
Intercept Traffic: Traffic meant for the gateway is now redirected through the attacker’s machine, where it can be analyzed or altered.
Manipulate or Block Traffic: The attacker can modify or completely block traffic from the IoT device, disrupting its operations.
Tools and Scripting
Tools like arpspoof or bettercap are commonly used for ARP poisoning, but custom scripts using the scapy library can also be created for sending and receiving ARP packets.
A script can automate ARP spoofing by continuously sending malicious ARP replies to maintain the poisoned ARP cache of the target device.
Example: An attacker uses ARP spoofing to intercept and manipulate traffic from a smart door lock on the same network, allowing unauthorized control of the lock.
3. Deauthentication (Deauth) Attack on IoT Devices
Overview
A deauthentication attack (often referred to as a Deauth attack) involves sending fake deauthentication frames to a wireless device, causing it to disconnect from its access point. This attack exploits the lack of authentication for deauth frames in older Wi-Fi protocols. IoT devices connected to wireless networks are particularly vulnerable to deauth attacks, as they rely on constant connectivity for proper functioning.
Attack Execution in IoT Context
Prerequisites: The attacker must be on the same Wi-Fi network as the IoT device and know the device’s MAC address.
Script Process:
Send Fake Deauth Frames: The script sends continuous deauth frames to the target IoT device, which forces the device to disconnect from the network.
Disrupt Service: The IoT device continuously attempts to reconnect, but the attacker keeps sending deauth frames to prevent it from re-establishing a connection.
Service Disruption: The attacker effectively blocks the IoT device from functioning by preventing its network access.
Tools and Scripting
Tools like aireplay-ng from the Aircrack-ng suite can perform deauth attacks by flooding the target with deauth packets.
A Python script using scapy can also be written to send custom deauthentication frames to the device's wireless interface.
Example: An attacker sends deauth frames to a smart home hub, disconnecting it from the router. This results in other connected devices, such as lights and cameras, becoming unresponsive.
My Contribution:
IoT based testbed includes many functionality other than this like network graph visualization, apk scanning etc.In a group of two including we are assigned to work on  gathering device information and automating this attack while scripts are written but not properly functioning. So, we wrote a functionable script and showed necessary detail and result of the attack in the UI part of the Project alongside with some other already working script results that should be reflected in the tool .


