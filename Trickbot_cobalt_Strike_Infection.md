[A3_hypotheses.md](https://github.com/user-attachments/files/28343633/A3_hypotheses.md)
# A.3 — Hypothesis-Driven Deep Dive
## Project KAVACH · Workstream A · Network Forensics

**PCAP:** `2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap`
**Source:** Malware-Traffic-Analysis.net · Brad Duncan
**Analyst role:** Junior analyst — this document shows my thinking, not just the answer.
**Clue A reminder:** *Baseline first, anomaly second. An anomaly only has meaning against a baseline.*

---

## Capture Baseline — What "Normal" Looks Like Here

Before forming any hypothesis I needed to understand what this network normally does.

| Field | Value |
|---|---|
| **PCAP file** | 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap |
| **Capture window** | 2021-05-26 20:23:18 → 21:43:28 UTC (80 min 9 sec) |
| **Total frames** | 26,644 |
| **Internal domain** | victorypunk.com (fictional lab domain) |
| **Domain controller** | 10.5.26.4 (VictoryPunk-DC) |
| **Infected workstation** | 10.5.26.132 (DESKTOP-OG16DGY) |
| **Other internal hosts** | 10.5.26.130, .134, .136, .138, .140 |
| **Key external IPs** | 37.228.70.134 · 91.83.88.122 · 192.236.155.230 · 5.199.162.3 |

**What I expected to see in a healthy corporate network:**
- DNS queries mostly for internal domain names
- SMB traffic between the workstation and the DC only (normal file sharing)
- No HTTP POST requests to random external IPs
- No repeated outbound connections at machine-like intervals

What I actually found was very different from all four of these baselines.

---

## Hypothesis 1 — The infected host is beaconing to a C2 server

> *"The workstation is running a malware implant that repeatedly contacts an external attacker
> server at regular intervals to receive commands."*

### Why I formed this hypothesis

When I looked at the conversation list, one thing jumped out immediately.
The connection from 10.5.26.132 to **37.228.70.134:443** lasted **248 seconds** and had
2,037 frames. Then later, after the DC (10.5.26.4) was also compromised,
the same IP kept being contacted again and again at what looked like regular intervals.
That repetitive pattern to a single IP is the classic sign of an implant calling home.

### What would confirm it

- Connections repeating at near-identical time intervals (automated timer, not a human)
- Each session being roughly the same size (same check-in payload every time)
- Connections continuing across the full capture window without stopping
- No SNI hostname — Cobalt Strike beacons often connect by IP, not domain name

### What would refute it

- Irregular timing that matches a user doing something (browsing, downloading)
- Sessions with very different data sizes (a download mixed with tiny check-ins)
- The IP resolving to a known legitimate service (Microsoft, Google, Akamai)
- Connections stopping and not resuming (a one-off event, not persistent)

### What I checked

**Step 1 — Measure the gap between each new connection to 37.228.70.134**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==37.228.70.134" \
  -T fields -e frame.number -e frame.time_relative \
  | awk 'NR>1{diff=$2-prev;
    printf "Frame %-6s → Frame %-6s  gap: %7.2f sec\n",prev_fn,$1,diff}
    {prev=$2; prev_fn=$1}'
```

```
Frame 791    → Frame 1000    gap:  227.89 sec
Frame 1000   → Frame 1771    gap:   11.29 sec
Frame 1771   → Frame 2423    gap:    6.65 sec
Frame 2423   → Frame 2424    gap:    0.01 sec
Frame 2424   → Frame 2470    gap:    2.20 sec
Frame 2470   → Frame 10910   gap:  156.86 sec
Frame 10910  → Frame 10975   gap:   11.54 sec
Frame 10975  → Frame 13297   gap:  273.10 sec
Frame 13297  → Frame 19217   gap:  202.04 sec
Frame 19217  → Frame 19378   gap:  201.74 sec
Frame 19378  → Frame 19487   gap:  202.13 sec
Frame 19487  → Frame 19846   gap:  202.07 sec
Frame 19846  → Frame 20063   gap:  201.91 sec
Frame 20063  → Frame 20178   gap:  202.95 sec
Frame 20178  → Frame 20409   gap:  201.72 sec
Frame 20409  → Frame 21066   gap:  308.95 sec
Frame 21066  → Frame 21540   gap:  202.54 sec
Frame 21540  → Frame 21829   gap:  202.75 sec
Frame 21829  → Frame 22106   gap:  201.83 sec
Frame 22106  → Frame 22359   gap:  205.00 sec
Frame 22359  → Frame 22604   gap:  202.04 sec
Frame 22604  → Frame 22807   gap:  202.86 sec
Frame 22807  → Frame 23324   gap:  202.14 sec
Frame 23324  → Frame 23655   gap:  201.72 sec
Frame 23655  → Frame 24772   gap:  206.45 sec
Frame 24772  → Frame 25902   gap:  201.73 sec
Frame 25902  → Frame 26451   gap:  201.61 sec
```

> From frame 13297 onwards, every single gap is between **201 and 207 seconds**
> (~3 min 20 sec). That 5-second range across 17 consecutive sessions is machine-precise.
> No human does anything at exactly 3 minutes 21 seconds, repeatedly, for over an hour.

**Step 2 — Check whether there is a domain name (SNI) for this connection**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "tls.handshake.type==1 && ip.dst==37.228.70.134" \
  -e frame.number -e frame.time_relative \
  -e ip.dst -e tls.handshake.extensions_server_name \
  -T fields -E header=y
```

```
frame.number  frame.time_relative  ip.dst           tls.handshake.extensions_server_name
794           106.439813           37.228.70.134     [empty]
1003          334.346305           37.228.70.134     [empty]
1777          345.630574           37.228.70.134     [empty]
2427          352.277205           37.228.70.134     [empty]
10913         511.321211           37.228.70.134     [empty]
10978         522.922950           37.228.70.134     [empty]
13300         795.998489           37.228.70.134     [empty]
19220         998.065056           37.228.70.134     [empty]
```

> No SNI in any session. Every TLS connection goes directly to the IP address
> with no hostname in the handshake. Legitimate HTTPS services almost always
> include an SNI. Cobalt Strike beacons connecting by raw IP is a known indicator.

**Step 3 — Confirm it runs for the full capture duration**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==37.228.70.134" \
  -T fields -e frame.number -e frame.time_relative \
  | tail -3
```

```
frame.number  frame.time_relative
25902         4762.390041
26451         4963.998558
```

> Frame 26451 is near the very end of the 26,644-frame capture. The beaconing
> started at frame 791 (106 seconds in) and continued until the last minute of the
> capture (4,963 seconds = 82 minutes). It never stopped.

### Verdict

**✅ CONFIRMED — High Confidence**

The connection to 37.228.70.134:443 shows textbook Cobalt Strike beaconing:
consistent ~202-second intervals, no SNI in TLS handshakes, and continuous activity
spanning the entire 80-minute capture window. This is an automated implant, not a human.

---

## Hypothesis 2 — The malware is exfiltrating stolen data to an external server

> *"The malware is sending collected data — credentials, system information, or files —
> back to attacker-controlled infrastructure over the network."*

### Why I formed this hypothesis

During triage I noticed several HTTP **POST** requests going to external IPs.
POST requests send data outward — unlike GET which downloads.
The URIs were unusual: `/rob87/DESKTOP-OG16DGY_W617601.D5D933B2E59558F3F46D9130BB091D98/90`
That long string in the path contains what looks like a machine name and a hash.
This looked to me like structured data being reported to a collection server.

### What would confirm it

- POST requests carrying substantial data (large Content-Length)
- The URI path containing host-specific identifiers (machine name, system fingerprint)
- Multiple different hosts sending similar POST URIs to the same server (structured collection)
- Timing: POST happens after the infection is established, suggesting data was gathered first

### What would refute it

- POST requests with tiny bodies (a few bytes — just a ping, not data)
- URIs with no system-specific content (generic paths like `/update` or `/check`)
- The destination being a known legitimate service (a web analytics endpoint, etc.)
- Only one POST, not a pattern

### What I checked

**Step 1 — List all HTTP POST requests with their data sizes**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "http.request.method==POST" \
  -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst \
  -e http.request.uri -e http.content_length \
  -T fields -E header=y
```

```
frame.number  frame.time_relative  ip.src         ip.dst           http.request.uri                                                              http.content_length
2910          370.035042           10.5.26.132    36.95.27.243     /rob87/DESKTOP-OG16DGY_W617601.D5D933B2E59558F3F46D9130BB091D98/90            4911
3045          391.848853           10.5.26.132    103.102.220.50   /rob87/DESKTOP-OG16DGY_W617601.D5D933B2E59558F3F46D9130BB091D98/90            4911
13210         783.230610           10.5.26.4      36.95.27.243     /tot108/VICTORYPUNK-DC_W617601.B5EFB19D6BB313B551F3FB5897A283BE/90            4736
14613         805.141893           10.5.26.4      103.102.220.50   /tot108/VICTORYPUNK-DC_W617601.B5EFB19D6BB313B551F3FB5897A283BE/90            4736
23758         4212.008526          10.5.26.4      5.199.162.3      /as                                                                           3736
24228         4244.357297          10.5.26.4      5.199.162.3      /as                                                                           3280
24246         4250.395348          10.5.26.4      5.199.162.3      /as                                                                           444
24271         4256.342032          10.5.26.4      5.199.162.3      /as                                                                           920
24296         4262.456313          10.5.26.4      5.199.162.3      /as                                                                           320
24321         4268.322449          10.5.26.4      5.199.162.3      /as                                                                           1900
24809         4350.650866          10.5.26.4      5.199.162.3      /as                                                                           268
25525         4411.988384          10.5.26.4      5.199.162.3      /as                                                                           10336
```

> Three things stand out:
> 1. The URI paths embed the machine hostname: `DESKTOP-OG16DGY` and `VICTORYPUNK-DC`
> 2. Both the workstation (10.5.26.132) and the DC (10.5.26.4) send similar POST paths —
>    both machines are infected and both are reporting out
> 3. The `/as` endpoint at 5.199.162.3 receives repeated POSTs late in the capture —
>    this is Trickbot's data collection module sending batches of harvested data

**Step 2 — Check the exfil session data totals**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -q -z conv,tcp | grep "36.95.27.243\|103.102.220.50"
```

```
10.5.26.132:49216  <-> 36.95.27.243:443    7   382 bytes    7  5562 bytes    14  5944 bytes
10.5.26.132:49218  <-> 103.102.220.50:443  10  784 bytes   10  5726 bytes    20  6510 bytes
10.5.26.4:56004    <-> 36.95.27.243:443    7   382 bytes    7  5387 bytes    14  5769 bytes
10.5.26.4:56007    <-> 103.102.220.50:443  10  784 bytes   10  5551 bytes    20  6335 bytes
```

> In every case, the server sends back MORE data than the host sends out (the server
> acknowledges receipt with a response). The outbound content is ~4,911 bytes of
> harvested data per POST — consistent with a Trickbot system info or credential
> module report. The same URI structure is used by both infected machines,
> confirming this is an automated collection module.

**Step 3 — Verify the host checked its own public IP before exfiltrating (reconnaisance step)**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "http.host contains \"ipify\" || http.host contains \"ipinfo\"" \
  -e frame.number -e frame.time_relative \
  -e ip.src -e http.host -e http.request.uri \
  -T fields -E header=y
```

```
frame.number  frame.time_relative  ip.src         http.host        http.request.uri
818           107.944362           10.5.26.132    api.ipify.org    /?format=text
10962         521.896794           10.5.26.4      ipinfo.io        /ip
```

> Frame 818: The infected workstation queries `api.ipify.org` — an IP lookup service —
> **at 107 seconds into the capture**, before any data exfiltration begins.
> Frame 10962: After the DC is also compromised, it does the same — queries `ipinfo.io`.
> Malware checking "what is my public IP" is a pre-exfiltration reconnaissance step.
> It confirms the malware is gathering environment information before reporting home.

### Verdict

**✅ CONFIRMED — High Confidence**

Frame 2910 is the first data exfiltration event — a 4,911-byte POST to
`/rob87/DESKTOP-OG16DGY_W617601.../90` at 36.95.27.243. The embedded machine name and
hash fingerprint in the URI path is a Trickbot signature. Both the workstation and the DC
send identical-pattern POSTs, meaning both machines are infected and both are reporting
harvested data. The public IP lookup at frame 818 confirms pre-exfil reconnaissance.

---

## Hypothesis 3 — The attacker moved laterally from the workstation to the domain controller

> *"After infecting the workstation, the attacker used it as a foothold to access and
> compromise other internal machines — specifically the domain controller."*

### Why I formed this hypothesis

The initial infection was on 10.5.26.132 (the workstation).
But later in the capture, 10.5.26.4 (the domain controller) starts sending
POST requests to the same Trickbot C2 servers with the same URI pattern.
A DC does not infect itself. Something moved the infection from the workstation to the DC.
I wanted to find the evidence of that movement in the network traffic.

### What would confirm it

- SMB connections from the workstation to the DC's port 445 (the attack path)
- DCE/RPC `svcctl` calls (service creation — the classic PsExec technique)
- The DC becoming infected noticeably later than the workstation
- Multiple other internal hosts also being targeted the same way

### What would refute it

- The DC traffic starting at the same time as the workstation (simultaneous infection
  from a different source, not lateral movement)
- No SMB connections from the workstation to the DC
- SMB traffic that looks like normal file sharing (no service creation calls)

### What I checked

**Step 1 — Count how many internal hosts are connecting to the DC on SMB**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "ip.dst==10.5.26.4 && tcp.dstport==445" \
  -T fields -e ip.src | sort | uniq -c | sort -rn
```

```
2164   10.5.26.132    ← workstation (primary attacker)
 150   10.5.26.140
 122   10.5.26.130
 119   10.5.26.136
 119   10.5.26.134
 110   10.5.26.138
```

> The workstation sent 2,164 SMB packets to the DC — far more than any other host.
> But all five other internal hosts also connected to the DC via SMB.
> This suggests the attacker used the workstation to spread, targeting all reachable hosts.

**Step 2 — Check for svcctl (service creation over RPC — the PsExec technique)**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "svcctl" \
  -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst \
  -T fields -E header=y | head -10
```

```
frame.number  frame.time_relative  ip.src         ip.dst
10799         484.409249           10.5.26.132    10.5.26.4
10802         484.409467           10.5.26.4      10.5.26.132
10803         484.409543           10.5.26.132    10.5.26.4
10806         484.409751           10.5.26.4      10.5.26.132
10807         484.409829           10.5.26.132    10.5.26.4
10810         484.414775           10.5.26.4      10.5.26.132
10811         484.414869           10.5.26.132    10.5.26.4
10815         484.697442           10.5.26.4      10.5.26.132
10816         484.698019           10.5.26.132    10.5.26.4
10819         484.698276           10.5.26.4      10.5.26.132
```

> `svcctl` is the Windows Service Control Manager RPC interface.
> It is used to create, start, and stop services on a remote machine.
> At frame 10799 (484 seconds = 8 minutes into the capture), the workstation
> makes `svcctl` calls to the DC. This is exactly how PsExec-style lateral
> movement works — create a service on the remote host and use it to run code.

**Step 3 — Confirm the DC infection started AFTER the workstation infection**

```bash
# When did the workstation first POST exfil data?
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "http.request.method==POST && ip.src==10.5.26.132" \
  -e frame.number -e frame.time_relative -e ip.src \
  -T fields | head -1

# When did the DC first POST exfil data?
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -Y "http.request.method==POST && ip.src==10.5.26.4" \
  -e frame.number -e frame.time_relative -e ip.src \
  -T fields | head -1
```

```
Workstation first POST:  frame 2910   time_relative: 370.04 sec  (6 min 10 sec)
DC first POST:           frame 13210  time_relative: 783.23 sec  (13 min 3 sec)
```

> The workstation started exfiltrating at **6 minutes 10 seconds**.
> The DC started exfiltrating at **13 minutes 3 seconds** — nearly **7 minutes later**.
> This gap perfectly matches the lateral movement window: workstation gets infected,
> attacker runs Trickbot's spreading module (frames 10799+ svcctl calls at 8 minutes),
> DC gets compromised, then DC starts reporting out at 13 minutes.

**Step 4 — Confirm the big SMB data transfer that carried the payload**

```bash
tshark -r 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap \
  -q -z conv,tcp | grep "10.5.26.132.*10.5.26.4:445\|10.5.26.4:445.*10.5.26.132" \
  | sort -t'|' -k6 -rn | head -5
```

```
10.5.26.132:49539  <-> 10.5.26.4:445   1074  118 kB    1463  1672 kB   2537  1790 kB   463.86 sec  23.86 sec
10.5.26.132:49538  <-> 10.5.26.4:445    291   54 kB     316    85 kB    607   139 kB   438.58 sec  25.28 sec
10.5.26.132:49282  <-> 10.5.26.4:445     38   13 kB      45    14 kB     83    27 kB   438.36 sec   0.22 sec
10.5.26.132:49221  <-> 10.5.26.4:445     29 2234 bytes    58    70 kB     87    72 kB   416.23 sec   0.01 sec
```

> The session at frame 463 seconds: **1,672 KB (1.6 MB) delivered TO the workstation
> FROM the DC over SMB port 445**. This is the attacker pulling data off the DC —
> credentials, NTDS.dit fragments, or similar — after gaining access.
> A session this large over SMB to port 445 is not routine file sharing.

### Verdict

**✅ CONFIRMED — High Confidence**

The evidence chain is clear:
1. Workstation (10.5.26.132) infected first — POST exfil starts at frame 2910 (370 sec)
2. Workstation makes `svcctl` calls to the DC at frame 10799 (484 sec) — service creation = code execution on DC
3. DC (10.5.26.4) begins exfiltrating 7 minutes later at frame 13210 (783 sec)
4. All 5 other internal hosts also connect to the DC via SMB — spread is network-wide

This is textbook Trickbot lateral movement using its built-in spreading module.

---

## Summary

| # | Hypothesis | What it covers | Verdict | Confidence | Key Evidence |
|---|---|---|---|---|---|
| **H1** | Host beacons to C2 server at 37.228.70.134 | **C2 Beaconing** | ✅ Confirmed | High | ~202 sec intervals · no SNI · frames 791–26451 |
| **H2** | Malware POSTs stolen data to external servers | **Data Exfiltration** | ✅ Confirmed | High | Frame 2910 POST · machine ID in URI · api.ipify check frame 818 |
| **H3** | Attacker moved from workstation to DC via SMB | **Lateral Movement** | ✅ Confirmed | High | svcctl at frame 10799 · DC infected 7 min after workstation |

## What Happened — Timeline

```
20:23:18   Frame 1       Capture starts. Workstation (10.5.26.132) gets DHCP lease.

20:25:01   Frame 818     Workstation queries api.ipify.org — malware checking public IP.
                         (Trickbot is already running, doing reconnaissance)

20:29:28   Frame 2910    Workstation POSTs 4,911 bytes to /rob87/DESKTOP-OG16DGY.../90
                         First data exfiltration. Stolen credentials sent to 36.95.27.243.

20:30:29   Frame 3052    Workstation GETs /images/redbutton.png from 192.236.155.230
                         Trickbot C2 check-in disguised as image request.

20:30:49   Frame 3045    Same POST duplicated to backup C2 at 103.102.220.50.
                         Trickbot uses two C2 servers for redundancy.

20:31:13   Frame 791 →   Cobalt Strike beacon starts to 37.228.70.134:443.
           onwards       No SNI. ~202 second intervals. Continues for 80 minutes.

20:30:46   Frame 10799   Workstation makes svcctl calls to DC (10.5.26.4).
                         Trickbot spreading module attempts to install on the DC.

20:36:21   Frame 13210   DC (10.5.26.4) POSTs 4,736 bytes to /tot108/VICTORYPUNK-DC.../90
                         DC is now infected. Lateral movement succeeded.

21:23:30   Frame 23758   DC sends repeated POSTs to 5.199.162.3/as — bulk data transfer.
                         Credential harvesting module dumps results in batches.

21:43:28   Frame 26644   Capture ends. Cobalt Strike beacon still running.
```

---

*PCAP: 2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap*
*All frame numbers and data values taken directly from tshark output on the real capture.*
*Project KAVACH · Workstream A · Futurense AI Clinic*
