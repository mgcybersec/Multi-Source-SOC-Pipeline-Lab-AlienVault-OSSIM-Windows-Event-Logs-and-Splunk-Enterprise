# Multi-Source SOC Pipeline Lab: AlienVault OSSIM, Windows Event Logs, and Splunk Enterprise

## Project Overview

This lab built a two-stage log pipeline feeding a home-lab SOC environment: Windows Security Event Logs into AlienVault OSSIM via NXLog, and OSSIM's own system/security event stream into Splunk Enterprise via rsyslog. The goal was to demonstrate a working multi-source SIEM ingestion path that could ultimately be queried by Claude through an MCP server, extending a prior Splunk + Claude Desktop MCP integration to a second, independent log source (OSSIM).

The project required deep troubleshooting of NXLog output formatting, a corrupted OSSIM plugin configuration, Splunk data-input state issues, and a silent rsyslog forwarding failure that produced no errors anywhere in the stack.

---

## Project Architecture

```text
WindowsAgent Virtual Machine (192.168.1.22)
        |
        | NXLog (im_msvistalog -> xm_csv -> om_udp)
        | UDP 514, OSSIM-specific CSV format
        v
AlienVault OSSIM (192.168.1.160)
        |
        | nxlog plugin (Analysis -> SIEM)
        |
        | rsyslog *.* forward (omfwd, UDP)
        v
Splunk Enterprise (192.168.1.161, local laptop instance)
        |
        | UDP:5514 input, sourcetype=linux_messages_syslog
        v
Splunk MCP Server
        |
        v
Claude
```

---

## Technologies Used

- AlienVault OSSIM (VirtualBox VM)
- NXLog Community Edition (3.2.2329)
- Windows Event Log (Security channel)
- rsyslog 8.24.0
- Splunk Enterprise (local instance)
- Splunk MCP Server
- Claude (chat + MCP-connected client)
- tcpdump
- iptables
- SysV init (`service`)

---

## Lab Objectives

1. Collect Windows Security Event Log data (logons, logoffs, failed logons) from a Windows VM using NXLog.
2. Get that data correctly parsed and ingested by OSSIM's nxlog plugin into Analysis → SIEM.
3. Forward OSSIM's own syslog stream to a local Splunk Enterprise instance via rsyslog.
4. Verify data landing correctly in Splunk under the right index and sourcetype.
5. Confirm the pipeline end-to-end using Splunk's MCP server from a Claude client.
6. Troubleshoot failures at every layer of the pipeline: NXLog formatting, OSSIM plugin config, Splunk input state, and rsyslog forwarding.

---

## Stage 1: Windows Event Log → OSSIM

### Initial Problem

NXLog was installed and running cleanly on the WindowsAgent VM, and rsyslog reception on OSSIM was confirmed working — raw Windows Event Log syslog data (including Security-Auditing 4624 logon events) was landing correctly in `/var/log/alienvault/devices/192.168.1.22/192.168.1.22.log`. Despite this, OSSIM's Analysis → SIEM showed zero events for that host.

### Root Cause

OSSIM's nxlog plugin (`/etc/ossim/agent/plugins/nxlog.cfg`) does not parse plain syslog text. It expects a specific semicolon-delimited, quoted CSV format tagged `WIN-NXLOG`. The default NXLog output didn't match this format and was being silently discarded by the plugin's regex matcher — no errors, just no matches.

### Fix

NXLog was reconfigured on the WindowsAgent VM (`nxlog.conf` + `patterndb.xml`) to:

- Use `im_msvistalog` as the input module (native Windows Event Log reader)
- Transform events into the required CSV format using `xm_csv`
- Forward via `om_udp` to `192.168.1.160:514`

After this change, the OSSIM nxlog plugin began actively detecting and processing WindowsAgent events.

### A Second Failure: Config Corruption

While attempting a cosmetic fix for a `src_ip=0.0.0.0` display issue, a `nano` regex "replace all" edit unintentionally applied 102 unexpected replacements across the plugin config file, breaking ingestion entirely. Recovery was done by copying a known-good backup from `/usr/share/alienvault-plugins/d_clean_plugins/nxlog.cfg` and manually reapplying only the necessary `location=` path edit — skipping the cosmetic `src_ip` fix to avoid the risk a second time.

### Result

Confirmed fully working: 32+ successful logon events, 13 failed logons, and other Security-Auditing events showing correctly in OSSIM's Analysis → SIEM for host 192.168.1.22.

---

## Stage 2: OSSIM → Splunk Enterprise

### Setup

- Splunk Enterprise runs locally on the laptop (192.168.1.161), not on a separate VM.
- A UDP data input was created in Splunk (Settings → Data Inputs → UDP), port 5514, sourcetype `linux_messages_syslog`.
- An rsyslog forwarding rule was added on OSSIM:

```text
# /etc/rsyslog.d/99-splunk-forward.conf
*.* @@192.168.1.161:5514
```

- Windows Firewall on the laptop confirmed to allow inbound UDP 5514.

### Problem 1: Misleading Splunk Internal Error

Splunk's internal log (`index=_internal source=*splunkd.log*`) repeatedly showed:

```text
Could not find object id=5514
```

This looked like the data input itself was broken. The input was deleted and recreated cleanly through the Add Data wizard (New Local UDP → port 5514 → sourcetype `linux_messages_syslog` → Review → Submit), which completed with no error banner.

**Verification test:** a raw UDP packet was sent directly from the laptop to itself via PowerShell:

```powershell
$client = New-Object System.Net.Sockets.UdpClient
$bytes = [System.Text.Encoding]::ASCII.GetBytes("test message from laptop")
$client.Send($bytes, $bytes.Length, "127.0.0.1", 5514)
$client.Close()
```

This event appeared correctly in Splunk (`host=127.0.0.1`, `source=udp:5514`, correct sourcetype), confirming the Splunk input itself was healthy. The `Could not find object id=5514` message turned out to be an unrelated internal Splunk warning (`AdminManager`/`TcpChannelThread`, a known REST-object-resolution quirk) and not indicative of actual data-path failure.

### Problem 2: A Stray, Corrupted Config File

`/etc/rsyslog.d/` contained an unexpected duplicate file, `99-splunkoforward.conf`, with malformed content:

```text
*.* @@192.168.1.161:5514 service rsyslog restart
```

A shell command had apparently been pasted directly into the config value at some point, appending `service rsyslog restart` onto the same line as the forwarding directive. This file was removed.

### Problem 3: Silent rsyslog Forwarding Failure (Root Cause)

Even after cleanup, real OSSIM system events (CRON, nfsen, SSH sessions, etc. — all actively generating in `/var/log/syslog`) were not reaching Splunk, despite:

- `rsyslogd -N1` (full config validation) reporting no errors anywhere in the config chain
- No blocking rules found in `iptables -L OUTPUT`
- No CRLF or hidden characters found in the forward rule file (`cat -A`)
- No conflicting `stop` rules in the rule-processing order (verified by tracing `$IncludeConfig` placement relative to AlienVault's own filtering rules)

**Diagnosis:** `tcpdump -i any -n udp port 5514` while triggering a local `logger` event showed **zero packets** leaving the box — the forward action was not firing at all, despite passing every syntax and config check available.

**Fix:** The legacy rsyslog forwarding syntax was replaced with the modern action-based syntax:

```text
# Before (silently non-functional on this rsyslog 8.24.0 build)
*.* @@192.168.1.161:5514

# After
*.* action(type="omfwd" target="192.168.1.161" port="5514" protocol="udp")
```

After restarting rsyslog, `tcpdump` immediately captured outbound packets (33 captured in one test run) to `192.168.1.161:5514`.

### Result

Real OSSIM system events — SSH sessions, sudo activity, CRON jobs, nfsen housekeeping — began arriving in Splunk under `sourcetype=linux_messages_syslog`, confirmed via direct SPL query:

```spl
index=* sourcetype=linux_messages_syslog
```

---

## Verification via Splunk MCP Server

With both pipelines live, the Splunk MCP server (previously integrated with Claude in an earlier lab) was used to query the newly-flowing OSSIM data directly from a Claude client:

```spl
index=* sourcetype=linux_messages_syslog
```

Results confirmed live OSSIM host activity (`host=192.168.1.160`) flowing into Splunk in real time, including SSH accepted-publickey events, sudo session opens/closes, and scheduled job activity.

A follow-up query for Linux-specific authentication failures returned no results — expected, since no actual failed logins had occurred on the OSSIM box during the test window. This distinguishes the two ingestion paths clearly:

- **Windows failed logons** (EventCode-equivalent Security-Auditing failures) live in **OSSIM's own SIEM**, ingested via NXLog — not in Splunk.
- **OSSIM/Linux system and auth events** are what actually flow through the rsyslog → Splunk pipeline built in Stage 2.

Extending Splunk visibility to include the Windows-originated SIEM data would require a separate integration (re-emitting OSSIM SIEM/alarm data to local syslog, or a dedicated AlienVault-to-Splunk data path) beyond the raw OS-level syslog forwarding built here.

---

## Key Lessons Learned

- A clean `rsyslogd -N1` validation and zero firewall blocks do not guarantee a forwarding rule is actually executing — packet-level verification with `tcpdump` was the only test that revealed the real problem.
- Legacy rsyslog `@`/`@@` forwarding syntax can silently fail to bind or fire on some builds without throwing any parse or runtime error; the modern `action()` syntax is more reliable and should be preferred.
- Splunk's own internal error messages aren't always indicative of the actual problem — the `Could not find object id=X` warning looked like a broken data input but was unrelated to real data flow.
- A single malformed config file pasted with an extra shell command appended can sit undetected among dozens of legitimate vendor config files unless directly inspected.
- Vendor-specific SIEM plugins (like OSSIM's nxlog plugin) often expect a proprietary parsing format, not raw syslog — matching that format exactly is a prerequisite for ingestion, and mismatches fail silently rather than erroring.
- Editing fragile, security-appliance-shipped config files (like OSSIM's plugin definitions) with broad find-and-replace operations is high-risk; targeted, minimal edits and known-good backups are safer.
- Distinguishing where different event types actually live (OSSIM's internal SIEM vs. raw OS syslog forwarded to Splunk) matters when building cross-platform correlation — they are not automatically the same data.

---

## Project Outcome

The completed lab demonstrated two independently working ingestion pipelines feeding a home-lab SOC:

```text
Windows Event Logs (WindowsAgent)
        ↓ NXLog (CSV-formatted for OSSIM)
AlienVault OSSIM SIEM
        ↓ rsyslog (action-based UDP forward)
Splunk Enterprise
        ↓ Splunk MCP Server
Claude (natural-language querying)
```

Both the Windows→OSSIM and OSSIM→Splunk legs were verified end-to-end with real event data, and the Splunk leg was confirmed queryable through the existing Splunk MCP integration with Claude — establishing the foundation for querying and correlating alarms across both platforms from a single AI-assisted interface.

---

## Skills Demonstrated

- AlienVault OSSIM administration and jailbreak-shell troubleshooting
- NXLog configuration (im_msvistalog, xm_csv, om_udp, patterndb.xml)
- Windows Event Log collection and format transformation
- rsyslog configuration, rule ordering, and forwarding syntax (legacy vs. modern `action()`)
- Splunk Enterprise data input configuration and troubleshooting
- Packet-level network verification with `tcpdump`
- iptables inspection
- Root-cause isolation across a multi-hop, multi-vendor log pipeline
- Config file recovery from vendor-provided clean backups
- Splunk MCP Server query usage via Claude
- Technical documentation and incident write-up

---

## Resume Project Description

**Multi-Source SOC Pipeline: AlienVault OSSIM, NXLog, and Splunk Enterprise with Claude MCP Querying**

Built and troubleshot a two-stage security log pipeline: Windows Security Event Logs collected via NXLog and ingested into AlienVault OSSIM's SIEM, and OSSIM's own system event stream forwarded to Splunk Enterprise via rsyslog. Diagnosed and resolved a proprietary SIEM plugin parsing mismatch, a corrupted vendor config file, and a silent rsyslog forwarding failure invisible to standard config validation, isolating the root cause through packet-level network capture. Verified live data ingestion at each stage and queried the resulting Splunk data through an existing Splunk MCP Server integration with Claude.
