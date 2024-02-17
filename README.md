## Malware Analysis (DCRat)

### Static Analysis

**VirusTotal Results:**
<img src="https://i.imgur.com/8xtTF7r.png">
- Hashes:
  - MD5: A2A774CE788A27A6866AAA7225A55DB3
  - SHA1: AC4E6CF7BE874C35C4F339DD7AA2F96025628476
  - SHA256: F40D98B920BDFE608A5339A3888D98892203C97EFAF3316DEE38FFDD172F84B2
- Filesize: 261632 bytes
- File Type: PE32
- File Name: f40d98b920bdfe608a5339a3888d98892203c97efaf3316dee38ffdd172f84b2.exe
- DLLs:
  - ntdll.dll
  - wow64.dll
  - wow64win.dll
  - wow64cpu.dll
  - kernel32.dll
  - user32.dll
  - kernelbase.dll

**Dynamic Analysis:**

**Processes:**
- C:\Users\admin\AppData\Local\Temp\f40d98b920bdfe608a5339a3888d98892203c97efaf3316dee38ffdd172f84b2.exe
- C:\Windows\SysWOW64\wscript.exe
- C:\Windows\SysWOW64\cmd.exe
- C:\Windows\SysWOW64\reg.exe
- C:\MssurrogateProvidercrtMonitor\agentwincommon.exe
- C:\Windows\System32\cmd.exe
- C:\Windows\System32\chcp.com
- C:\Windows\System32\w32tm.exe
- C:\MssurrogateProvidercrtMonitor\mscorsvw.exe

**DNS:**
- 369023cm.nyashmyash.top (188.114.97.3:80)

**IP addresses:**
- 188.114.96.3:80
- 188.114.97.3:80

**Registry Keys Modified:**
- HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap

**Tools used:**
- ANY.RUN

**Overview:**
Based on the analysis, this file is malicious. When the file hash was run in VirusTotal, it was flagged 48 times. During dynamic analysis performed on the file in ANY.RUN, the file immediately created multiple files such as agentwincommon.exe and mscorsvw.exe, which were flagged as malicious and associated with the known malware type DCRat, which is known for infecting a system and then allowing the attacker to gain remote access to the infected system.
