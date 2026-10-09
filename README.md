ؤ# 🛡️ SOC Incident Investigation: Detection & Analysis Report

## 1. Executive Summary
During routine log monitoring, an anomaly was detected involving an internal workstation sending suspicious outbound traffic over non-standard ports. This report documents the complete investigation lifecycle—from initial alert detection using Suricata IDS, to deep packet investigation with Wireshark, root-cause correlation via Splunk (SPL), and final containment and remediation actions.

## 2. Environment & Incident Details
- **Target Workstation (Victim):** 192.168.1.105 (Finance Host)
- **External Suspicious IP (Attacker):** 198.51.100.45
- **Protocol/Port:** HTTP / TCP Port 8080
- **Timeline of Attack:** 2026-08-05 | 14:15:00 UTC - 14:45:00 UTC
- **Severity Level:** High
- **Status:** Contained & Resolved

## 3. Step 1: Intrusion Detection with Suricata
To catch the initial malicious traffic, custom Suricata rules were implemented to flag high-frequency TCP connections and suspicious user-agent patterns.

**Suricata Custom Rule:**
alert tcp 192.168.1.0/24 any -> 198.51.100.45 8080 (msg:"SEC_ALERT: Suspicious Outbound Connection & Data Transfer"; content:"POST"; http_method; content:"/upload.php"; http_uri; classtype:trojan-activity; sid:1000045; rev:1;)

**Findings:** Suricata generated an alert `SEC_ALERT: Suspicious Outbound Connection` indicating potential data exfiltration via POST requests.

## 4. Step 2: Packet Analysis via Wireshark
A PCAP capture was analyzed to inspect the payload and HTTP header details.
- **Wireshark Display Filters Used:**
  - Host traffic filter: `ip.addr == 192.168.1.105 && ip.addr == 198.51.100.45`
  - POST requests filter: `http.request.method == "POST"`
- **Key Discovery:**
  - Inspection of the HTTP Stream revealed an unauthorized base64 encoded payload being transmitted inside the request body.
  - The User-Agent string was identified as a non-standard script (`Python-urllib/3.10`), confirming automated script activity on the host.

## 5. Step 3: Event Correlation using Splunk SPL
To measure the scope of the incident across the entire network, Splunk was queried using Search Processing Language (SPL).

- **SPL Query 1 (Top External Destinations):**
  `index=network_logs src_ip="192.168.1.105" | stats count sum(bytes_out) as TotalBytes by dest_ip, dest_port | sort - TotalBytes`

- **SPL Query 2 (Outbound Traffic Spike / Anomaly Detection):**
  `index=suricata_events signature="SEC_ALERT*" | timechart span=5m count by src_ip`

- **Outcome:** The query confirmed that host `192.168.1.105` had transferred ~45MB of data to `198.51.100.45` within a 30-minute window, identifying a successful data exfiltration attempt.

## 6. Step 4: Containment & Incident Response Actions
To immediately neutralize the threat and stop data leakage, the following actions were executed:
- **Network Isolation:** Temporarily disconnected workstation `192.168.1.105` from the network segment to prevent lateral movement or further communication with the C2 server.
- **Perimeter Firewall Blocking:** Implemented strict drop rules at the edge firewall for external IP `198.51.100.45`.
- **Process Termination:** Terminated the unauthorized Python script running in the background of the user session.

## 7. Recommendations & Preventive Actions
- **Endpoint Remediation:** Run a comprehensive offline anti-malware and EDR scan on `192.168.1.105` to check for rootkits or hidden persistence mechanisms.
- **Application Whitelisting:** Restrict unauthorized Python script executions on finance and sensitive workstations.
- **Network Segmentation:** Ensure financial segment hosts have restricted outbound internet access strictly limited to approved business ports.
