# DDoS Security Assessment Framework v1.0

![Python Version](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

A professional-grade DDoS resilience assessment tool for authorized security testing. Orchestrates 15 real-world attack vectors across multiple Linux instances, measures target resilience metrics, and generates comprehensive vulnerability assessments.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Example Output](#example-output)
- [Configuration](#configuration)
- [Security Notice](#security-notice)
- [License](#license)

---

## Overview

DDoS Security Assessment Framework is a distributed attack simulation platform designed for security professionals conducting authorized DDoS resilience testing. It orchestrates 15 real-world DDoS attack vectors (Layer 3, Layer 4, and Layer 7) across multiple remote Linux instances, continuously monitors target behavior, and generates detailed vulnerability reports with severity ratings.

**Perfect for:**
- DDoS resilience testing and validation
- Infrastructure hardening assessments
- Proof-of-concept demonstrations
- Security posture validation before production launch
- Load balancer and WAF effectiveness testing

---

## Features

### 15 Real-World DDoS Attack Vectors

**Layer 3 & 4 (Network Layer):**
- SYN Flood with spoofed IP addresses
- TCP Amplification attacks
- ICMP Ping of Death (oversized packets)
- UDP Reflective Amplification (DNS)
- TCP Fragmentation with custom offsets
- SYN+ACK and FIN+ACK flood variants

**Layer 7 (Application Layer):**
- Slowloris (Response Read Delay)
- Slow Read attacks (1-byte TCP reads)
- HTTP Request Flood (pipelined requests)
- Request Exaggeration (oversized headers)
- Range Request DoS (byte-range fragmentation)
- Connection Buffer Exhaustion
- Reflection and Mirroring techniques

### Distributed Multi-Instance Architecture
- Single controller orchestrates unlimited remote bot instances over SSH
- Automatic Paramiko-based SSH management
- Per-instance adaptive worker scaling based on CPU utilization
- Real-time metrics collection from all instances

### Live Monitoring & Real-Time HUD
- Response time tracking with baseline comparison
- Timeout counting and percentage calculation
- Bandwidth monitoring per instance
- Active thread count display
- 1-second update intervals during attacks

### Intelligent CPU-Adaptive Scaling
- Starts at 10x thread multiplier
- Auto-scales up to 60x multiplier (~4,800 threads per instance)
- Targets 80-85% remote CPU utilization
- Dynamic redeployment as load changes
- Aggressive scaling for maximum impact

### Comprehensive Reporting
- Severity-based verdicts: Resilient, Info, Low, Medium, High, Critical
- Timeout percentages and latency degradation metrics
- Comparative analysis across all 15 vectors
- Per-instance and centralized logging
- Structured output for documentation

---

## Quick Start

### Prerequisites

- Controller: Python 3.8+
- Remote instances: Linux (Debian/Ubuntu recommended)
- SSH access to all instances
- Python 3 on remote instances
- Outbound connectivity from instances to target

### 1. Clone Repository

```bash
git clone https://github.com/srikqr/ddos-assessment-framework.git
cd ddos-assessment-framework
```

### 2. Install Dependencies

```bash
python3 -m pip install paramiko psutil
```

### 3. Prepare Instance File

Create `instances.txt`:

```
10.10.1.10
10.10.1.11
10.10.1.12
```

Or use comma-separated IPs: `10.10.1.10,10.10.1.11,10.10.1.12`

### 4. Run Assessment

```bash
python3 ddos_assessment.py \
  -u vaptuser \
  -p 'YourPassword' \
  -ips instances.txt \
  -t target.example.com \
  -pt 443 \
  -d 120
```

Select "All Attack Vectors" at the menu to run all 15 vectors.

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/srikqr/ddos-assessment-framework.git
cd ddos-assessment-framework
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

Manual installation:

```bash
pip install paramiko psutil
```

The framework auto-installs dependencies on first run if missing.

### Step 3: Prepare Remote Instances

Each instance must have:

1. SSH enabled with password or key-based authentication
2. Python 3 installed (auto-installed if missing via apt-get)
3. Sudo access for sysctl tuning (non-interactive)
4. Outbound connectivity to the target

Test connectivity:

```bash
ssh vaptuser@10.10.1.10 "python3 --version"
```

### Step 4: Verify Target Reachability

```bash
nc -vz target.example.com 443
```

---

## Usage

### Command-Line Interface

```bash
python3 ddos_assessment.py [OPTIONS]
```

#### Required Arguments

| Argument | Short | Description | Example |
|----------|-------|-------------|---------|
| --username | -u | SSH username | vaptuser |
| --password | -p | SSH password | MyPassword123 |
| --instances | -ips | IPs or file path | instances.txt or 10.10.1.10,10.10.1.11 |
| --target | -t | Target IP/hostname | 192.168.1.50 or api.example.com |

#### Optional Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| --port | -pt | 80 | Target TCP port |
| --duration | -d | 120 | Attack duration per vector (seconds) |
| --sshPort | -sp | 22 | SSH port on instances |

### Usage Examples

#### Example 1: Single Instance, Single Vector (30 seconds)

```bash
python3 ddos_assessment.py \
  -u root \
  -p 'password123' \
  -ips 192.168.1.100 \
  -t 10.0.0.50 \
  -pt 80 \
  -d 30
```

Then select "Request Flood" from the menu.

#### Example 2: Multi-Instance Full Battery (All 15 Vectors)

```bash
python3 ddos_assessment.py \
  -u vaptuser \
  -p 'SecurePassword' \
  -ips instances.txt \
  -t prod-api.internal \
  -pt 443 \
  -d 120
```

Select "All Attack Vectors" to run complete assessment.

#### Example 3: Custom SSH Port & Extended Duration

```bash
python3 ddos_assessment.py \
  -u admin \
  -p 'AdminPass' \
  -ips 172.16.0.5 \
  -t staging.example.com \
  -pt 8443 \
  -sp 2222 \
  -d 180
```

#### Example 4: Comma-Separated Instances

```bash
python3 ddos_assessment.py \
  -u vaptuser \
  -p 'password' \
  -ips 10.10.1.10,10.10.1.11,10.10.1.12 \
  -t target.com \
  -pt 443 \
  -d 120
```

---

## Architecture

### System Design

```
┌─────────────────────────────────────────────────────────┐
│         Controller (Your Machine)                        │
│  ┌─────────────────────────────────────────────────────┐│
│  │ Main Framework Process                              ││
│  │ • CLI parsing and attack menu                        ││
│  │ • SSH orchestration via Paramiko                     ││
│  │ • TargetMonitor (ping checks)                        ││
│  │ • HUD display thread                                 ││
│  │ • Centralized logging                               ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────┬───────────────────────────────────────┘
                  │ SSH + Attack Script
        ┌─────────┴──────────┬──────────────┐
        │                    │              │
   ┌────▼─────┐         ┌───▼────┐     ┌──▼──────┐
   │Instance 1│         │Instance 2│    │Instance N│
   │(Bot Node)│         │(Bot Node)│    │(Bot Node)│
   │ Procs    │         │ Procs   │    │ Procs   │
   │ Threads  │         │ Threads │    │ Threads │
   │ CPU Auto │         │ CPU Auto│    │ CPU Auto│
   └────┬─────┘         └───┬────┘     └──┬──────┘
        │                    │              │
        └────────────────────┼──────────────┘
                             │ Attack Traffic
                        ┌────▼────────┐
                        │ Target      │
                        │ IP:Port     │
                        └──────────────┘
```

### Core Components

| Component | Function |
|-----------|----------|
| **CentralizedLoggingManager** | Manages per-run and per-instance logs |
| **TargetMonitor** | Tracks response times, timeouts, and degradation |
| **SSHInstance** | Manages individual bot instance via SSH |
| **SingleLineDisplayThread** | Updates live HUD metrics every second |
| **DDoSAssessmentFramework** | Main orchestrator for attack execution |

### Execution Flow

1. **Setup Phase:** Connects to all instances, installs Python 3 if needed
2. **Baseline:** Measures 10 target pings to establish response baseline
3. **Attack Selection:** User selects vector(s) from menu
4. **Deployment:** Framework pushes attack script to each instance
5. **Execution:** Instances spawn processes × threads × multiplier
6. **Monitoring:** Real-time collection of metrics and target responsiveness
7. **Verdict:** Generates severity rating based on timeout %, latency degradation
8. **Cleanup:** Kills attack processes and disconnects

---

## Example Output

### Live HUD During Attack

```
[ATTACK 5/15] Connection Buffer Exhaustion - 500 connections/thread + Threading
=====================================================================

[  0.0s] [✓] Resp: 0.85ms   | Timeouts: 0/0  | InstancesWorking: 3 | Bandwidth: 0.00 Mbps | Threads: 0
[  1.0s] [✓] Resp: 1.12ms   | Timeouts: 0/1  | InstancesWorking: 3 | Bandwidth: 89.34 Mbps | Threads: 2400
[  5.0s] [✓] Resp: 2.45ms   | Timeouts: 0/5  | InstancesWorking: 3 | Bandwidth: 156.78 Mbps | Threads: 4800
[ 10.0s] [✗] Resp: TIMEOUT  | Timeouts: 2/10 | InstancesWorking: 3 | Bandwidth: 225.12 Mbps | Threads: 4800
[ 20.0s] [✗] Resp: TIMEOUT  | Timeouts: 8/20 | InstancesWorking: 3 | Bandwidth: 234.56 Mbps | Threads: 4800
[ 60.0s] [✗] Resp: TIMEOUT  | Timeouts: 32/60| InstancesWorking: 3 | Bandwidth: 198.45 Mbps | Threads: 4800
[120.0s] [✓] Resp: 18.92ms  | Timeouts: 45/120| InstancesWorking: 3 | Bandwidth: 178.34 Mbps | Threads: 4800

-------------------------------------------------------------------
[Verdict] Connection Buffer Exhaustion - 500 connections/thread + Threading
-------------------------------------------------------------------
Checks: 120 | Timeouts: 45 (37.5%) | AvgResponse: 245.67ms | Degradation: +1200%
Status: High - Severe degradation detected
-------------------------------------------------------------------
```

### Final Assessment Report

```
=====================================================================
DDoS Resilience Assessment Report - api.example.com:443
=====================================================================

Attack Vector                               | Timeouts  | Degradation | Verdict
─────────────────────────────────────────────────────────────────────────────
SYN Flood                                   | 62.1%     | +1500%      | Critical
Connection Buffer Exhaustion                | 37.5%     | +1200%      | High
Response Read Delay (Slowloris)             | 28.9%     | +890%       | High
SYN Mirroring                               | 25.6%     | +750%       | Medium
FIN+ACK Flood                               | 15.3%     | +520%       | Medium
TCP Fragmentation                           | 8.2%      | +290%       | Medium
Slow Read                                   | 3.1%      | +80%        | Info
Request Exaggeration                        | 1.5%      | +45%        | Info
UDP Reflective Amplification                | 0.8%      | +12%        | Resilient
Request Flood                               | 0.0%      | +2%         | Resilient

=====================================================================
[FINAL VERDICT] High DDoS Vulnerability - Multiple severe impacts detected
=====================================================================

Critical Findings:
- SYN Flood renders target completely unresponsive
- Connection exhaustion bypasses rate limiting
- Layer 7 attacks cause 890%+ latency increases

Recommendations:
- Implement DDoS mitigation service
- Deploy geo-distributed CDN
- Configure connection limits
- Enable HTTP/2 push
```

---

## Output Logs

Assessment logs saved in `ddos_assessment_logs/run_<timestamp>/`:

```
ddos_assessment_logs/
└── run_2026-01-04_14-30-45/
    ├── logs/
    │   ├── 00_main.log
    │   ├── instance_10.10.1.10.log
    │   ├── instance_10.10.1.11.log
    │   └── instance_10.10.1.12.log
    └── reports/
        └── assessment_summary.log
```

Each log contains:
- Timestamp
- Connection status
- Deployment info
- Metrics updates
- CPU scaling events
- Verdicts and findings

---

## Configuration

### Adjust Thread Scaling

Edit `SSHInstance` class `threadsPerProcess` (default: 50):

```python
self.threadsPerProcess = 100  # Increase for more aggressive load
```

### Modify CPU Targets

In `SSHInstance.adjustThreads()`:

```python
self.targetMinCpu = 75.0   # Lower bound
self.targetMaxCpu = 90.0   # Upper bound
```

### Add Custom DDoS Vector

Extend `logicMap` in `_generateEnhancedAttackScript()`:

```python
"CustomAttack": '''def attack_worker():
    while time.time() < end_time:
        # Your custom DDoS logic
        pass
'''
```

Add to `AVAILABLE_ATTACKS`:

```python
AVAILABLE_ATTACKS.append("CustomAttack - Custom DDoS technique + Threading")
```

---

## Security Notice

**IMPORTANT - READ BEFORE USE**

This framework is designed for authorized DDoS testing only. Unauthorized testing is illegal.

**Legal requirements:**
- Obtain signed written authorization before any test
- Only test systems you own or have explicit permission to test
- Test in controlled environments first
- Stay within approved scope
- Document all findings
- Follow local laws and regulations

Violation of these requirements may result in serious legal consequences including criminal charges.

---

## Requirements

```
paramiko==3.4.0      # SSH client
psutil==5.9.6        # System metrics
python>=3.8
```

Install all:

```bash
pip install -r requirements.txt
```

---

## License

MIT License - See LICENSE file for details

---

## Author

Created by srikqr from scratch for professional DDoS resilience assessment.

---

## Support

For issues and questions:
- Report bugs via GitHub Issues
- Start discussions for questions
- For security concerns, do not open public issues

---

## Changelog

### v1.0 (2026-01-04)
- Initial release
- 15 DDoS attack vectors
- Multi-instance SSH orchestration
- Real-time HUD monitoring
- Adaptive CPU scaling
- Comprehensive reporting

---

## Learning Resources

- OWASP DDoS Testing Guide: https://owasp.org/www-community/attacks/DoS_attack
- CWE-400: Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html
- RFC 5508: Slowloris: https://tools.ietf.org/html/rfc5508

---

Made for security professionals. Test responsibly.
