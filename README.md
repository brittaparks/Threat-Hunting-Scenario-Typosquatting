# Threat-Hunting-Scenario-Typosquatting
## Detecting and Responding to Brand Impersonation through Typosquatting

### 🧪 Example Scenario

As part of a simulated threat-hunting exercise focused on **Typosquatting/Brand Impersonation**, I investigated suspicious domains that resemble the fictitious, but "legitimate" banking site `goldenbank.com`. This activity highlights the use of domain mutation tools and Microsoft Defender for Endpoint (MDE) to simulate real-world phishing and spoofing scenarios.

---

### 🛠️ Tool Setup and Customization Notes

To simulate typosquatting and detect brand impersonation domains, I set up a local analysis environment with the following tools:

| Tool/Action                  | Command/Source                                                                                                   | Purpose                                                       |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Python 3.10 (64-bit)         | [https://www.python.org/downloads/release/python-3100/](https://www.python.org/downloads/release/python-3100/)   | Needed to run the `dnstwist` tool                             |
| pip (Python package manager) | `python get-pip.py`                                                                                              | Enables installation of additional Python packages            |
| dnstwist                     | `pip install dnstwist`                                                                                           | Primary tool for generating and analyzing domain permutations |
| dnspython                    | `pip install dnspython`                                                                                          | Resolves DNS records for discovered domains                   |
| Pillow                       | `pip install pillow`                                                                                             | Enables image handling for webpage screenshots                |
| Selenium                     | `pip install selenium`                                                                                           | Automates browser for capturing screenshots                   |
| ChromeDriver (for Selenium)  | [https://googlechromelabs.github.io/chrome-for-testing/](https://googlechromelabs.github.io/chrome-for-testing/) | Allows Selenium to control Chrome and capture screenshots     |

---

**📝 Modification Made to ****************`dnstwist.py`**************** for Windows Compatibility (Line 486)**

```python
# Original code (WNOHANG is not supported on Windows)
def stop(self):
    pid, status = os.waitpid(-1, os.WNOHANG)
```

```python
# Updated code that worked on Windows
def stop(self):
    while pid:
        break  # prevent infinite loop since we're not waiting for child process

    except AttributeError:
        # Windows does not support os.waitpid with WNOHANG, so we pass here.
        pass
```

---

### 🧪 Execution Summary

```bash

# Pulled WHOIS data and saved output to file
dnstwist -r --whois goldenbank.com > goldenbank.txt

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/1c5aa2e1-dcdc-47b6-8049-eb8bb23049d9">

```bash

# Took screenshots of ~10 domains (stopped early due to VM resource constraints)
dnstwist -r --phash --screenshots desktop -t 40 goldenbank.com

```


*Screenshots of selected websites from ********`dnstwist`********'s phash analysis are included below.*


<img width="1212" alt="image" src="https://github.com/user-attachments/assets/53c408c6-17af-49f3-a681-5c80a2b0ddf0">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/190e9234-2305-4b36-86fe-af5705bbf024">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d2dd55e0-460f-4828-ab54-08f05d3ecbf9">


---

### 🔍 Threat Hunting Queries (MDE)

These queries were used during the investigation. They are presented in the logical order of how an incident responder may approach the scenario—from initial domain contact to file behavior and script execution.

---

#### 🔎 1. Detecting Contact With Spoofed Domain

```kql
DeviceNetworkEvents
| where DeviceName == "britt-windows10"
| where InitiatingProcessFileName == "msedge.exe"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, RemoteIP, RemotePort
| order by Timestamp desc

```

📌 **Purpose**: To track network events specifically from msedge.exe.

✅ **Results** We observe two events showing a visit to an IP address matching the website in question.


<img width="1212" alt="image" src="https://github.com/user-attachments/assets/206d53e0-dd51-4548-920f-5c019b4702a5">


---

#### 📥 2. Detecting PDF Downloads in the Downloads Folder

```kql
DeviceFileEvents
| where DeviceName == "britt-windows10"
| where FileName endswith ".pdf"
| where FolderPath contains "Downloads"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

📌 **Purpose**: Filters for PDFs downloaded to the user's Downloads folder.

✅ **Results** We observe that during this period, a file has been downloaded with the name `bank_statement.pdf` 

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/7fb337a6-e458-4665-a2ec-07a0b55eae80">


📌 **Notes**: During simulation, `bank_statement.pdf` was downloaded via PowerShell using `Invoke-WebRequest`. In a real-world attack, we'd expect `msedge.exe` to appear as the InitiatingProcessFileName.

---

#### 📥 3. Detecting PDF Downloads in the Downloads Folder

```kql
DeviceNetworkEvents
| where DeviceName == "britt-windows10"
| where RemoteIP startswith "194.58" 
| where InitiatingProcessFileName == "msedge.exe"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, RemoteIP, RemotePort
| order by Timestamp desc
```

📌 **Purpose**: This will show network traffic related to any IPs starting with 194.58, potentially capturing other malicious IPs or related infrastructure.

✅ **Results** 4 unique IPs contacted.  This pattern is consistent with webpage loading behavior—browser loads various resources (images, scripts, iframes) from multiple backend servers, all tied to the spoofed domain.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/61a93b5a-4bdc-4f5a-a874-b65c961c00e9">


---

#### 📤 4. PowerShell-Initiated Network Connections (C2 or Exfiltration)

```kql
DeviceNetworkEvents
| where DeviceName == "britt-windows10"
| where InitiatingProcessFileName == "powershell.exe"
| where RemoteIP != "internal_network_range"  
| where RemotePort !in (80, 443)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

📌 **Purpose**: Detects outbound connections made by PowerShell. Could be indicative of C2 or exfiltration over non-standard ports.

❌ **No Results** — Included for completeness.

---

#### 🧠 5. PowerShell Script Execution (Suspicious Commands)

```kql
DeviceProcessEvents
| where DeviceName == "britt-windows10"
| where ProcessCommandLine has "powershell.exe"
| where ProcessCommandLine contains "Invoke-Expression" or ProcessCommandLine contains "DownloadString"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

📌 **Purpose**: Catches use of PowerShell commands that are common in script-based attacks.

❌ **No Results** — Still useful in real-world investigations.

---

#### 🌐 6. Suspicious Browser Child Process Activity

```kql
DeviceProcessEvents
| where DeviceName == "britt-windows10"
| where InitiatingProcessFileName in~ ("msedge.exe", "chrome.exe")
| where FileName !in~ ("msedge.exe", "chrome.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

📌 **Purpose**: Detects suspicious child processes spawned by browsers, which could indicate exploitation.

❌ **No Results** — Helpful for detecting browser-based script execution or persistence.

---

#### 🛠️ 7. Verifying PowerShell Binary Usage

```kql
DeviceProcessEvents
| where DeviceName == "britt-windows10"
| where FolderPath endswith "powershell.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

📌 **Purpose**: Validates when and how PowerShell was executed on the system.

❌ **No Results** — Still included for thoroughness.

---

### 🎯 MITRE ATT&CK Techniques

| Technique                         | ID    | Description                        |
| --------------------------------- | ----- | ---------------------------------- |
| Command and Scripting Interpreter | T1059 | PowerShell execution               |
| User Execution                    | T1204 | Spoofed domain access via phishing |
| Domain Generation Algorithms      | T1568 | Typosquatting or domain spoofing   |
| Ingress Tool Transfer             | T1105 | Downloading file using PowerShell  |

---

### 🛡️ Response Actions Taken

- Blocked typosquatting domain on internal DNS firewall
- Initiated system scan using Defender AV
- Added related IOC indicators to watchlists
- Reviewed URL filtering policy for further tightening

---

### 🔐 Recommendations for GoldenBank

- **Domain Take-Down Requests**: Proactively report and request removal of spoofed domains through respective registrars and abuse contacts.
- **Continuous Monitoring**: Regularly scan for newly registered lookalike domains using tools like `dnstwist`.
- **Customer Education**: Train customers to recognize fake sites, verify URLs, and avoid clicking links from unknown sources.
- **Defensive Domain Registration**: Purchase similar-looking domains (e.g., common typos, homoglyphs) to prevent malicious use.
- **Threat Intelligence Integration**: Monitor threat intel feeds and domain registries for mentions of brand-related typosquatting.
- **Enhanced Email Protections**: Ensure SPF, DKIM, and DMARC are correctly configured to reduce phishing via spoofed email domains.

---

### 📇 Analyst Contact

**Name**: Britt Parks\
**Contact: linkedin.com/in/brittaparks**\
**Date**: April 20, 2025

