# **Splunk Security Investigation Project: Analyzing Cyber Attack Logs**
Overview: Brief description (2–3 sentences) of the problem solved and the value provided.

## **1. What Was the Goal?**

The primary goal was to **develop practical cybersecurity investigation skills using Splunk** in a hands-on TryHackMe lab environment. Specifically, this involved:

- **Learning to use Splunk** as a Security Information and Event Management (SIEM) tool for real-world security incident investigation
- **Analyzing diverse log data** (endpoints, network devices, applications) to identify security incidents
- **Identifying Indicators of Compromise (IOCs)** through systematic log analysis
- **Performing digital forensics** using Splunk's Search Processing Language (SPL)
- **Understanding threat hunting** methodologies in network and endpoint logs
- **Completing TryHackMe challenges** by investigating simulated attack datasets and answering specific investigative questions

## **2. What Did I Do?**

### **A. Environment Setup**
- Accessed the **TryHackMe-provided Splunk instance** with pre-loaded lab datasets
- Configured and navigated the **Splunk interface** for optimal investigation workflow

### **B. Log Analysis & Investigation**
- **Ingested and examined multiple log types** including:
  - Windows Event Logs (authentication, process execution)
  - Web server logs (Apache/IIS access and error logs)
  - Firewall and network traffic logs
  - Endpoint security logs
  - System and application logs

- **Designed and executed Splunk SPL queries** to:
  ```splunk
  # Example investigative queries used:
  index=wineventlog EventCode=4625 | stats count by user, src_ip
  | search count>5  # Find brute force attempts
  
  index=web sourcetype=access_combined 
  | search "POST" AND ("sql" OR "union" OR "select")
  # Detect SQL injection attempts
  ```
- **Filtered and correlated events** by time ranges, source IPs, user accounts, and event codes
- **Extracted critical forensic fields** including:
  - Usernames and authentication patterns
  - Source and destination IP addresses
  - File paths and process execution details
  - Command-line arguments and PowerShell activity

### **C. Guided Investigation Process**
Followed the **TryHackMe room's structured investigation** to:
1. **Identify the initial attack vector** (e.g., compromised credentials, web vulnerability exploitation)
2. **Track lateral movement** across the network using authentication and process logs
3. **Discover persistence mechanisms** (scheduled tasks, registry modifications, malicious services)
4. **Identify data exfiltration methods** (unusual outbound connections, large data transfers)
5. **Document the complete attack chain** from initial access to final objective

### **D. Methodology & Documentation**
- **Applied systematic DFIR (Digital Forensics and Incident Response) methodology**
- **Created comprehensive investigation notes** explaining query logic and result interpretation
- **Built a narrative of attacker activities** based on log evidence
- **Verified findings** through multiple log source correlation

## **3. What Was the Outcome?**

### **A. Specific Investigation Findings:**
Successfully **uncovered the complete attack chain**, typically including:
- **Initial compromise method**: Identified specific vulnerability exploitation or credential theft
- **Attacker tools and techniques**: Discovered malware, scripts, and commands used
- **Lateral movement path**: Mapped how the attacker moved between systems
- **Persistence mechanisms**: Found backdoors, scheduled tasks, or registry modifications
- **Data exfiltration evidence**: Identified what data was stolen and how
- **Scope of compromise**: Determined which systems and accounts were affected

### **B. Skills and Knowledge Gained:**
- **Practical Splunk SPL proficiency**: Developed ability to craft effective security queries
- **Threat hunting methodology**: Learned systematic approach to log-based investigation
- **Incident response workflow**: Understood how to progress from detection to analysis
- **Log correlation techniques**: Learned to connect events across multiple data sources
- **Forensic analysis skills**: Developed ability to extract actionable intelligence from logs

### **C. Tangible Achievements:**
- ✅ **Completed all TryHackMe challenge questions** accurately
- ✅ **Earned TryHackMe points and completion badge**
- ✅ **Built a portfolio piece** demonstrating practical security analysis skills
- ✅ **Developed reusable investigation techniques** applicable to real-world scenarios

### **D. Broader Impact:**
- **Enhanced understanding** of attacker behaviors and TTPs (Tactics, Techniques, and Procedures)
- **Improved ability** to translate log data into security intelligence
- **Gained confidence** in using enterprise security tools for incident response
- **Developed mindset** of curiosity and thoroughness essential for security investigations

---

**Final Assessment**: The project successfully transformed theoretical security concepts into practical investigation skills. By solving a realistic attack scenario using Splunk, I demonstrated not just tool proficiency but also critical thinking and analytical capabilities essential for cybersecurity professionals. The outcome represents both a **solved investigation case** and **substantial skill development** in security operations and incident response.