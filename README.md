# Posh-ClickFix-PopUp
This script monitors the user clipboard and alerts the user if a potentially malicious command is run from a set of regular expression patterns common in shellcode execution. Files provided in this repository should be used with caution. Scripts are provided as-is with no warranty or protection. USers are responsible for their own security.

# Usage
Clone the script from the repository to your local machine. Run the script as a background service, in PowerShell profiles, on user login, or as a scheduled task.

# Remarks
Research conducted using MITRE ATT&CK:
https://attack.mitre.org/techniques/T1115/

Microsoft Learn modules for clipboard Win32 APIs can be found here:
https://learn.microsoft.com/en-us/windows/win32/api/Winuser/nf-winuser-getclipboardsequencenumber

Notable mention to this BleepingComputer article for the idea:
https://www.bleepingcomputer.com/news/security/apple-adds-macos-terminal-warning-to-block-clickfix-attacks/
