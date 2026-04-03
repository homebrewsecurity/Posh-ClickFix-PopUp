# Author: Logan Bennett
# Last Modified: 4/3/2026

# AI was not used for the creation of this script and is a culmination of research for ATT&CK T1115
# This script monitors the clipbaord for suspicious data, such as that used in ClickFix campaigns.


############ Setup ############

# C# type definition importing Windows APIs with P/Invoke
# This wasn't too difficult but P/Invoke.net doesn't have this readily available, so the code was transposed from C++ documentation

$ClassCode = @"
using System;
using System.Runtime.InteropServices;

public static class Clipboard
{
    // Gets the clipboard sequence number to determine changes to the clipboard
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern uint GetClipboardSequenceNumber();

    // Opens the clipboard and prevents other processes from accessing it
    [DllImport("user32.dll", CharSet= CharSet.Auto)]
    public static extern bool OpenClipboard(IntPtr hwndNewOwner);

    // Gets the clipboard data based on queried format; returns a handle that needs to be converted to a readable string
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetClipboardData(uint uFormat);

    // Closes the clipboard and opens it for other processes
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool CloseClipboard();
}
"@

# Adds the new object
Add-Type -TypeDefinition $ClassCode

# Creates the main function that queries the clipboard (I know there is already a Get-Clipboard command, but this is way faster and cooler)
Function Get-Win32ClipboardData
{
    # Opens the clipboard; locks the clipboard for other processes
    [Clipboard]::OpenClipboard([IntPtr]::Zero) | Out-Null

    # Gets the handle for clipboard data; 1 is for CF_TEXT
    $ClipboardHandle = [Clipboard]::GetClipboardData([uint32]1)

    # Closes the clipboard
    [Clipboard]::CloseClipboard() | Out-Null

    # Returns the readable string
    Return [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ClipboardHandle)
}

# Gets the sequence number of the clipboard; if it changes, then the check will run
Function Get-Win32ClipboardSequenceNumber
{
    [Clipboard]::GetClipboardSequenceNumber()
}

# Creates the warning pop-up
Function New-UserCopyWarning
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$WindowString
    )

    $Shell = New-Object -ComObject wscript.shell

    $Shell.PopUp("You have copied a potentialy malicious command:`n`n$WindowString`n`nPlease be cautious when pasting as the content may be a security risk!",30,"Potentially Malicious Command Copied",0x0)
}

############ Functional Code ############

# Regex patterns to look for mal activity
$RegExPatterns = @('(?i)powershell.*-command','(?i)powershell.*-e(|[acdemno]+)','(?i)cmd.*/c','(?i)cscript.*(\.vbs|\.js)','(?i)wscript.*(\.vbs|\.js)')
$LastSequence = 0  # Placeholder value

# Runs forever until process stops
while ($true)
{
    # Gets the current sequence number (refer to MS documentation)
    $CurrentSequence = Get-Win32ClipboardSequenceNumber

    # Compares the last known sequence to the current sequence
    if ($LastSequence -ne $CurrentSequence)
    {
        $LastSequence = $CurrentSequence
        $Data = Get-Win32ClipboardData

        $ContinueLoopChecks = $True
        foreach ($RegEx in $RegExPatterns)
        {
            # If there's a match in regex, stop checking and create a new warning
            # This -and operation may need to be moved to the start of the loop because of inefficiency
            if ($Data -match $RegEx -and $ContinueLoopChecks)
            {
                $ContinueLoopChecks = $False

                New-UserCopyWarning -WindowString $Data | Out-Null
            }
        }
    }

    # Waits 3 seconds to start the cycle to check again; edit this value if you want a longer or shorter wait duration
    Start-Sleep -Seconds 3
}
