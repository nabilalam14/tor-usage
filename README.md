# 🧅 Threat Hunt Report: Unauthorized TOR Usage

------------------------------------------------------------------------

## 📌 Scenario Overview

Management suspects that some employees may be using TOR browsers to
bypass network security controls due to unusual encrypted traffic
patterns and connections to known TOR-related ports. The goal of this
investigation was to detect TOR usage and analyze related activity on
the endpoint.

------------------------------------------------------------------------

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

------------------------------------------------------------------------

# 🛠 Investigation Steps

------------------------------------------------------------------------

## 1️⃣ DeviceFileEvents Investigation

Searched for any file that had the string "tor" in it and discovered
that the user **"windows11lab-na"** downloaded a TOR installer. Multiple
TOR-related files were copied to the Desktop, and a file named
**tor-shopping-list.txt** was created at `2026-03-03T18:00:00.6087814Z`.

### Query Used

``` kql
DeviceFileEvents
| where DeviceName == 'windows11lab-na'
| where InitiatingProcessAccountName == 'windows11lab-na'
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-03T17:53:13.0765631Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1296" height="653" alt="image" src="https://github.com/user-attachments/assets/33fb5c13-2796-424a-9837-7ae4ca006e30" />


------------------------------------------------------------------------

## 2️⃣ DeviceProcessEvents -- Installer Execution

Identified execution of
`tor-browser-windows-x86_64-portable-15.0.7.exe`, confirming silent
installation behavior.

### Query Used

``` kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1296" height="165" alt="image" src="https://github.com/user-attachments/assets/5f6eaa07-71ea-4efe-8ca8-a3220cb9b9f3" />


------------------------------------------------------------------------

## 3️⃣ DeviceProcessEvents -- TOR Browser Execution

Confirmed that the user launched TOR at `2026-03-03T17:55:04.274827Z`.
Processes observed included `tor-browser.exe`, `firefox.exe`, and
`tor.exe`.

### Query Used

``` kql
DeviceProcessEvents
| where DeviceName == "windows11lab-na"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

<img width="1455" height="687" alt="image" src="https://github.com/user-attachments/assets/8cc7fa80-21a6-419d-8fb8-7680ee0f8543" />


------------------------------------------------------------------------

## 4️⃣ DeviceNetworkEvents -- TOR Network Connections

Observed connection to `127.0.0.1:9150`, confirming TOR SOCKS proxy
initialization. Additional outbound encrypted connections over port 443
followed.

### Query Used

``` kql
DeviceNetworkEvents
| where DeviceName == "windows11lab-na"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001","9030","9040","9050","9051","9150","80","443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
         RemoteIP, RemotePort, RemoteUrl,
         InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

<img width="1445" height="449" alt="image" src="https://github.com/user-attachments/assets/723af50e-20e4-4e34-8f0c-87867c3a5be5" />


------------------------------------------------------------------------

# 📅 Chronological Event Timeline

  Timestamp                         Event
  --------------------------------- -------------------------------
  2026-03-03T17:53:13.0765631Z      TOR installer downloaded
  2026-03-03T17:53:13Z--17:55:00Z   Files extracted to Desktop
  2026-03-03T17:55:04.274827Z       TOR browser executed
  2026-03-03T17:55:50.0060487Z      Connection to 127.0.0.1:9150
  2026-03-03T18:00:00.6087814Z      tor-shopping-list.txt created

------------------------------------------------------------------------

# 📊 Summary

The user "windows11lab-na" on the "windows11lab-na" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

------------------------------------------------------------------------

# 🚨 Response Taken

-   Endpoint isolated
-   Activity documented
-   Management notified
-   Recommendations provided for application control and monitoring

------------------------------------------------------------------------

# 🧠 MDE Tables Referenced

  Table                 Purpose
  --------------------- ---------------------------------------
  DeviceFileEvents      Detect download and file activity
  DeviceProcessEvents   Detect execution and process creation
  DeviceNetworkEvents   Detect TOR network communications

------------------------------------------------------------------------

# 👤 Author

**Nabil Alam**\
Cybersecurity \| Threat Hunting \| SOC Automation\
GitHub: https://github.com/nabilalam14\
LinkedIn: [https://linkedin.com/in/nabil-alam](https://www.linkedin.com/in/nabil-alam-32ba85158/)

------------------------------------------------------------------------
