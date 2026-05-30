# 🛡️ SSH Brute Force Detection & Monitoring with Splunk SIEM

> **Built by a cybersecurity engineer passionate about proactive threat detection, SOC operations, and turning raw log data into actionable intelligence.**

---

## 👋 About This Project

This is not a tutorial I followed — this is a **fully self-designed detection engineering lab** that mirrors the exact workflow a Tier 1/Tier 2 SOC analyst or Security Engineer executes in production environments every single day.

If you're a recruiter or hiring manager evaluating cybersecurity candidates, here's what this project demonstrates in practical terms:

- I can **ingest and normalize log data** into a SIEM from scratch
- I can **write detection logic** (SPL queries) that identify real attack patterns
- I can **configure automated alerting** with proper trigger thresholds
- I can **build monitoring dashboards** for continuous visibility
- I understand the **attacker mindset** well enough to hunt for it in logs

This is the work. Let me show you how it's done.

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Architecture & Tools](#-architecture--tools)
- [Attack Scenario](#-attack-scenario-simulated)
- [Step-by-Step Build Guide](#-step-by-step-build-guide)
  - [Step 1 – Environment Setup](#step-1--environment-setup)
  - [Step 2 – Data Ingestion](#step-2--data-ingestion)
  - [Step 3 – Log Parsing & Field Extraction](#step-3--log-parsing--field-extraction)
  - [Step 4 – Detection Logic (SPL Queries)](#step-4--detection-logic-spl-queries)
  - [Step 5 – Alert Configuration](#step-5--alert-configuration)
  - [Step 6 – Dashboard & Visualization](#step-6--dashboard--visualization)
- [Screenshots](#-screenshots)
- [Key Findings from the Lab](#-key-findings-from-the-lab)
- [Skills Demonstrated](#-skills-demonstrated)
- [How to Reproduce This Lab](#-how-to-reproduce-this-lab)
- [Future Enhancements](#-future-enhancements)

---

## 🔍 Project Overview

**Objective:** Build an end-to-end detection pipeline that identifies SSH brute force attacks in real time using Splunk as the SIEM platform.

**Why SSH Brute Force?**
SSH brute force is one of the most common initial access techniques used by threat actors (referenced in MITRE ATT&CK as [T1110.001 – Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)). It's simple, automated, and devastatingly effective against systems with weak credentials or no rate-limiting controls. Any SOC worth its salt must be able to detect this in real time.

**Timeline:** September 2025  
**Platform:** Splunk Enterprise (Free Trial / Home Lab)  
**Log Source:** Linux `auth.log` (SSH authentication events)

---

## 🏗️ Architecture & Tools

```
Linux Host (auth.log)
        │
        ▼
  Splunk Universal Forwarder  ──►  Splunk Indexer
                                        │
                                   ┌────┴────┐
                                   │  Index  │
                                   └────┬────┘
                                        │
                              ┌─────────┴──────────┐
                              │                    │
                         SPL Searches         Dashboards
                              │
                         Alert Engine
                              │
                      Email Notification
```

| Component | Tool/Technology |
|-----------|----------------|
| SIEM Platform | Splunk Enterprise |
| Query Language | SPL (Search Processing Language) |
| Log Source | Linux `auth.log` |
| Detection Method | Threshold-based alerting (≥5 failures / 5 min) |
| Visualization | Splunk Dashboard Studio |
| Alert Delivery | Email + Triggered Alerts |

---

## 🎯 Attack Scenario (Simulated)

To validate the detection pipeline, a simulated brute force attack was executed against a home lab Linux VM:

- **Attacker IP:** `192.168.1.10` (internal test machine)
- **Target accounts tested:** `deploy`, `test`, `root`, `admin`
- **Total failed attempts:** 5+ within a 5-minute window
- **Attack tool simulation:** Repeated `ssh` commands with invalid credentials

This is the same pattern a real-world attacker using tools like **Hydra**, **Medusa**, or **Ncrack** would generate in victim logs.

---

## 🚀 Step-by-Step Build Guide

### Step 1 – Environment Setup

#### 1a. Install Splunk Enterprise

1. Go to [https://www.splunk.com/en_us/download/splunk-enterprise.html](https://www.splunk.com/en_us/download/splunk-enterprise.html)
2. Download the free trial (up to 500MB/day ingestion — more than enough for a home lab)
3. Install on your local machine or a VM:
   ```bash
   # On Linux (Debian/Ubuntu)
   wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/...'
   sudo dpkg -i splunk.deb
   sudo /opt/splunk/bin/splunk start --accept-license
   ```
4. Access Splunk at `http://localhost:8000`
5. Set your admin username and password on first launch

#### 1b. Set Up a Linux Target VM

Use VirtualBox, VMware, or any hypervisor. A minimal Ubuntu Server install works perfectly.

```bash
# Ensure SSH is installed and running
sudo apt update && sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
```

Verify that `/var/log/auth.log` is actively being written to:
```bash
tail -f /var/log/auth.log
```

---

### Step 2 – Data Ingestion

You have two options to get log data into Splunk:

#### Option A: Direct File Monitor (Simplest)

1. In Splunk Web, go to **Settings → Data Inputs → Files & Directories**
2. Click **Add New**
3. Enter the full path to your auth.log: `/var/log/auth.log`
4. Set **Source type** to `linux_secure` or `syslog`
5. Set **Index** to `main` (or create a dedicated `ssh_logs` index)
6. Click **Review → Submit**

#### Option B: Splunk Universal Forwarder (Production-Style)

This is how it's done in enterprise environments:

```bash
# Install the Universal Forwarder on the Linux target
wget -O splunkforwarder.deb 'https://download.splunk.com/products/universalforwarder/...'
sudo dpkg -i splunkforwarder.deb

# Configure it to forward to your Splunk indexer
sudo /opt/splunkforwarder/bin/splunk add forward-server <SPLUNK_IP>:9997

# Add the auth.log as a monitored input
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index main -sourcetype linux_secure

# Start the forwarder
sudo /opt/splunkforwarder/bin/splunk start
```

**Verify data is flowing:** In Splunk Web, run:
```
index=main sourcetype=linux_secure | head 20
```

---

### Step 3 – Log Parsing & Field Extraction

Raw auth.log lines look like this:
```
Sep 12 10:00:01 hostname sshd[1234]: Failed password for invalid user deploy from 192.168.1.10 port 54321 ssh2
```

We need to extract **structured fields** from this unstructured text. This is where SPL's `rex` command comes in.

#### Field Extraction SPL

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port \d+"
| table _time, src_ip, user, host
```

**What this does:**
- Filters only failed SSH login events
- Uses regex to extract:
  - `user` → the account name being targeted
  - `src_ip` → the attacker's IP address
  - `_time` → Splunk's parsed timestamp

#### Create Persistent Field Extractions (Optional but Recommended)

1. Run the search above in Splunk
2. Click on a field value in the results
3. Select **Extract Fields**
4. Use the regex method and save the extraction for reuse

---

### Step 4 – Detection Logic (SPL Queries)

This is the core of the detection engineering work. Below are the exact queries used in this project.

#### Query 1: Failed SSH Login Attempts Over Time (Timeline View)

```spl
index=main sourcetype=linux_secure "Failed password"
| timechart span=1m count by host
```

Use this to visualize attack volume over time. Spikes indicate automated brute force activity.

#### Query 2: Top Source IPs with Failed Logins

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\S+) port"
| stats count by src_ip
| sort -count
```

Immediately surfaces which IP addresses are generating the most noise. In a real environment, these IPs would be fed into a threat intel lookup or immediately blocked at the firewall.

#### Query 3: Top Targeted User Accounts

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "for (invalid user )?(?<user>\S+) from"
| stats count by user
| sort -count
```

This tells you *who* the attacker is trying to compromise. High counts on `root` or `admin` suggest automated tooling cycling through default accounts.

#### Query 4: Brute Force Candidate Detection (Core Detection Rule)

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port"
| bucket _time span=5m
| stats count(user) as failed_attempts, dc(user) as unique_users by src_ip, _time
| where failed_attempts >= 5
```

**This is the detection rule.** Any IP generating 5 or more failed SSH login attempts within a 5-minute window is flagged as a brute force candidate. This threshold mirrors real-world SOC detection standards.

---

### Step 5 – Alert Configuration

#### Creating the Alert in Splunk

1. Run the **Brute Force Candidate Detection** query above
2. Click **Save As → Alert**
3. Configure the alert:

| Setting | Value |
|---------|-------|
| **Alert Name** | `SSH Brute Force from Single IP (≥5 in 5m)` |
| **Alert Type** | Scheduled |
| **Schedule** | Every hour, at 15 minutes past the hour |
| **Trigger Condition** | Number of Results is greater than 0 |
| **Actions** | Add to Triggered Alerts + Send Email |

4. For email action:
   - Add recipient email address
   - Subject: `[ALERT] SSH Brute Force Detected - $result.src_ip$`
   - Include search results in email body

#### Why These Settings?

- **Hourly scheduling** catches sustained attacks without overwhelming the alert queue
- **"Number of Results > 0"** means any match fires the alert — zero false negatives for this threshold
- **Dual actions** ensure both SOC visibility (Triggered Alerts log) and immediate notification (email)

---

### Step 6 – Dashboard & Visualization

#### Building the Dashboard

1. In Splunk Web, go to **Dashboards → Create New Dashboard**
2. Name it: `SSH Brute Force Monitoring – Home Lab`
3. Add the following panels:

#### Panel 1: Failed SSH Login Attempts Over Time
- **Visualization:** Line Chart
- **SPL:**
```spl
index=main sourcetype=linux_secure "Failed password"
| timechart span=1m count
```

#### Panel 2: Top Source IPs with Failed Logins
- **Visualization:** Bar Chart
- **SPL:**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\S+) port"
| stats count by src_ip
| sort -count
| head 10
```

#### Panel 3: Top Targeted User Accounts
- **Visualization:** Bar Chart
- **SPL:**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "for (invalid user )?(?<user>\S+) from"
| stats count by user
| sort -count
| head 10
```

#### Panel 4: Brute Force Candidates Table
- **Visualization:** Statistics Table
- **SPL:**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port"
| bucket _time span=5m
| stats count(user) as failed_attempts, dc(user) as unique_users by src_ip, _time
| where failed_attempts >= 5
| sort -failed_attempts
```

4. Set dashboard **Auto-Refresh** to every 5 minutes for real-time monitoring
5. Save and share with your team (or set as your Splunk home screen)

---

## 📸 Screenshots

### Dashboard – Full Monitoring View
![SSH Brute Force Monitoring Dashboard](screenshots/dashboard.png)
> Real-time view showing failed login attempts over time and top attacking IPs. IP `192.168.1.10` is clearly the dominant source with 5 failed attempts.
<img width="1902" height="716" alt="dashboard" src="https://github.com/user-attachments/assets/83cbb4d7-be1a-4fa9-97b7-459e348fc5a8" />

### Top Targeted User Accounts Panel
![Top Targeted User Accounts](screenshots/alert-config.png)
> The `deploy` account was the most targeted (5 attempts), followed by `test` and `root` (2 each). This pattern is consistent with automated credential stuffing tools.
<img width="1915" height="230" alt="field-extraction" src="https://github.com/user-attachments/assets/fdd5cb71-811e-4824-92f6-3dd7395795e9" />

### Alert Configuration
![Alert Configuration](screenshots/alert-config-detail.png)
> Splunk alert configured to fire hourly when ≥5 failed SSH attempts are detected from a single IP within a 5-minute window. Actions: Add to Triggered Alerts + Send Email.
<img width="1844" height="443" alt="alert-config" src="https://github.com/user-attachments/assets/14d55812-8e38-42a5-9a75-111a49f2073d" />

---

## 🔎 Key Findings from the Lab

| Finding | Detail |
|---------|--------|
| **Primary Attacker IP** | `192.168.1.10` |
| **Attack Window** | 2025-09-12 10:00:00 AM |
| **Total Failed Attempts** | 5 (within 5 minutes) |
| **Accounts Targeted** | `deploy` (5x), `test` (2x), `root` (2x), `admin` (1x) |
| **Unique Users Targeted** | 4 accounts from single IP |
| **Detection Latency** | Alert fires within 15 minutes of attack |
| **MITRE ATT&CK Technique** | T1110.001 – Brute Force: Password Guessing |

**Analysis:** The attacker's pattern — hitting multiple non-standard accounts (`deploy`, `test`) alongside privileged accounts (`root`, `admin`) — is consistent with automated tooling that cycles through wordlists of common default credentials. The `deploy` account is a particularly interesting target, suggesting the adversary may have done prior reconnaissance or is using a sophisticated wordlist targeting DevOps environments.

---

## 🎓 Skills Demonstrated

| Skill | How It's Applied |
|-------|-----------------|
| **SIEM Implementation** | Deployed and configured Splunk Enterprise from scratch |
| **Log Ingestion & Normalization** | Onboarded Linux auth.log with proper sourcetype tagging |
| **SPL Query Writing** | Wrote multi-step SPL for extraction, aggregation, and detection |
| **Regex / Field Extraction** | Used `rex` to parse unstructured log data into structured fields |
| **Detection Engineering** | Built threshold-based rule mirroring real SOC detection standards |
| **Alerting & Incident Response** | Configured automated alerts with proper trigger conditions and actions |
| **Dashboard & Visualization** | Created multi-panel operational dashboard for continuous monitoring |
| **MITRE ATT&CK Mapping** | Mapped detected activity to T1110.001 |
| **Threat Analysis** | Interpreted results to characterize attacker behavior and tooling |

---

## 🔁 How to Reproduce This Lab

### Prerequisites
- A computer with at least 8GB RAM (Splunk is memory-hungry)
- VirtualBox or VMware (free versions work)
- Ubuntu Server ISO ([download here](https://ubuntu.com/download/server))
- Splunk Enterprise free trial account

### Quick Start
```bash
# 1. Clone this repo
git clone https://github.com/YOUR_USERNAME/ssh-bruteforce-splunk-siem.git
cd ssh-bruteforce-splunk-siem

# 2. Review the SPL queries in /queries/
ls queries/

# 3. Follow the step-by-step guide in this README

# 4. Generate test data (simulate brute force from your lab)
for i in {1..10}; do
  ssh invaliduser@TARGET_IP 2>/dev/null
done
```

> ⚠️ **Legal Notice:** Only simulate attacks on systems you own or have explicit written authorization to test. Unauthorized access attempts are illegal.

---

## 🚀 Future Enhancements

- [ ] **Threat Intelligence Integration** – Enrich src_ip fields with VirusTotal or AbuseIPDB lookups via API
- [ ] **Geo-IP Mapping** – Add geographic visualization of attack origins using MaxMind GeoLite2
- [ ] **Automated Blocking** – Integrate alert actions with firewall API (pfSense/iptables) to auto-block flagged IPs
- [ ] **Correlation Search** – Cross-correlate failed SSH attempts with successful logins to detect post-brute-force compromise
- [ ] **Risk-Based Alerting** – Implement Splunk RBA to score and prioritize events dynamically
- [ ] **Elastic Stack Port** – Rebuild detection stack using ELK (Elasticsearch, Logstash, Kibana) for multi-platform comparison
- [ ] **Wazuh Integration** – Forward alerts to Wazuh for unified security event management

---

## 📬 Connect With Me

I'm actively seeking opportunities in:
- **SOC Analyst (Tier 1 / Tier 2)**
- **Security Engineer**
- **Detection Engineer**
- **Threat Hunter**

I bring hands-on experience with SIEM platforms, log analysis, detection rule development, and incident investigation workflows — not just theoretical knowledge.

📧 [Your Email]  
💼 [Your LinkedIn]  
🐙 [Your GitHub Profile]

---

## 📄 License

This project is open-sourced under the MIT License. All SPL queries, configurations, and documentation are free to use, adapt, and build upon.

---

*"Security is not a product, but a process." – Bruce Schneier*
