# Triage Notes

## Capture details
- File: 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap.
- Total frames: 26,644.
- Capture window: 2021-05-26 20:23:18 UTC to 21:43:28 UTC.
- Duration: 4,809.707 seconds.

## Protocol hierarchy
- IPv4: 23,859 packets.
- TCP: 21,901 packets.
- ARP: 2,785 packets.
- NetBIOS Session Service: 2,659 packets.
- SMB: 1,907 packets.
- UDP: 1,810 packets.
- TLS: 1,222 packets.
- SMB2: 752 packets.
- HTTP: 289 packets.
- LDAP: 274 packets.

## Endpoints and conversations
- Notable internal hosts: 10.5.26.132 and 10.5.26.4.
- Notable external IPs: 37.228.70.134, 36.95.27.243, 103.102.220.50, 5.199.162.3.
- TCP conversations show repeated outbound sessions to a small number of external IPs and later SMB activity between workstation and DC.

## Top talkers
- The workstation 10.5.26.132 is the main initiator early in the capture.
- The DC 10.5.26.4 becomes active later and begins posting outbound traffic.
- External services used include ipify/ipinfo-style lookups and repeated C2 endpoints.

## Time bounds and bursts
- Early burst window: 300 to 900 seconds.
- The burst aligns with payload download, beaconing, and later lateral movement.
- C2 beaconing becomes periodic at roughly 200-second intervals.

## Notes for reviewers
- This document is intentionally concise and maps directly to the Kavach triage requirements.
- Use the associated hypotheses and IOC files for the reasoning and indicator detail.
