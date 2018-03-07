function Takeown-Registry($key) {
    # TODO does not work for all root keys yet
    switch ($key.split('\')[0]) {
        "HKEY_CLASSES_ROOT" {
            $reg = [Microsoft.Win32.Registry]::ClassesRoot
            $key = $key.substring(18)
        }
        "HKEY_CURRENT_USER" {
            $reg = [Microsoft.Win32.Registry]::CurrentUser
            $key = $key.substring(18)
        }
        "HKEY_LOCAL_MACHINE" {
            $reg = [Microsoft.Win32.Registry]::LocalMachine
            $key = $key.substring(19)
        }
    }

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # set owner
    $key = $reg.OpenSubKey($key, "ReadWriteSubTree", "TakeOwnership")
    $acl = $key.GetAccessControl()
    $acl.SetOwner($admins)
    $key.SetAccessControl($acl)

    # set FullControl
    $acl = $key.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
}

function Takeown-File($path) {
    takeown.exe /A /F $path
    $acl = Get-Acl $path

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # add NT Authority\SYSTEM
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "None", "None", "Allow")
    $acl.AddAccessRule($rule)

    Set-Acl -Path $path -AclObject $acl
}

function Takeown-Folder($path) {
    Takeown-File $path
    foreach ($item in Get-ChildItem $path) {
        if (Test-Path $item -PathType Container) {
            Takeown-Folder $item.FullName
        } else {
            Takeown-File $item.FullName
        }
    }
}

function Elevate-Privileges {
    param($Privilege)
    $Definition = @"
    using System;
    using System.Runtime.InteropServices;
    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
"@
    $ProcessHandle = (Get-Process -id $pid).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege)
}

# Thanks to raydric, this function should be used instead of `mkdir -force`.
#
# While `mkdir -force` works fine when dealing with regular folders, it behaves
# strange when using it at registry level. If the target registry key is
# already present, all values within that key are purged.
function force-mkdir($path) {
    if (!(Test-Path $path)) {
        #Write-Host "-- Creating full path to: " $path -ForegroundColor White -BackgroundColor DarkGreen
        New-Item -ItemType Directory -Force -Path $path
    }
}

Function Disable-OneDrive
{
Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}
}

Function Disable-WindowsTips
{
    Write-Host 'Disabling Windows Tip'
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $Name = "DisableSoftLanding"
    $Value = "1"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path .\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) {New-Item .\SOFTWARE\Policies\Microsoft\Windows\CloudContent}
    New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Set-Location $PSScriptRoot
}

Function Disable-ConsumerExperience
{
    Write-Host 'Disabling Consumer Experience'
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $Name = "DisableWindowsConsumerFeatures"
    $Value = "1"
    $Type = "DWORD"

    Set-Location HKLM:
    if (!(test-Path .\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) {New-Item .\SOFTWARE\Policies\Microsoft\Windows\CloudContent}
    New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Set-Location $PSScriptRoot
}

Function Disable-Ads
{
    $reglocation = "HKCU"
    #Start menu ads
    Write-Host 'Disabling Start Menu Ads for Current User'
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
    #Lock Screen suggestions
    Write-Host 'Disabling Lock Screen Suggentions for Current User'
    Reg Add "$reglocation\SOFTWARE\Microsoft\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
    Write-Host "Disabling explorer ads for current user"
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F

    $reglocation = "HKLM\AllProfile"
    reg load "$reglocation" c:\users\default\ntuser.dat
    Write-Host 'Disabling Start Menu Ads for default user'
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
    Write-Host 'Disabling Lock Screen Suggentions for Current User'
    Reg Add "$reglocation\SOFTWARE\Microsoft\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
    Write-Host "Disabling explorer ads for default user"
    Reg Add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F
    #unload default user hive
    [gc]::collect()
    reg unload "$reglocation"
}

Function Set-PageFile
{
    #Gets total memory 
    $Getmemorymeasure = Get-WMIObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    #Converts the memory into GB
    $TotalMemSize = $($Getmemorymeasure.sum/1024/1024/1024)

    if ($PageFileDrive -eq $null)
    {
        $Drive = "C:"
    }
    else 
    {
        IF ($PageFileDrive -like "*:")
        {
            $Drive = $PageFileDrive
        }
        else 
        {
            $Drive = $PageFileDrive + ":"
        }
    }
    #recomended Page file size is double the memory installed
    Write-Host "Setting Page file size on: $Drive"
    write-host "Total Memory Installed (gb): $TotalMemSize"
    #2gb
    If (($TotalMemSize -gt "1") -and ($TotalMemSize -le "2.1")) 
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 4096 4096"
        Write-Host "Set page file for 2 gb of memory"
    }
    #4gb
    If (($TotalMemSize -gt "2") -and ($TotalMemSize -le "4.1")) 
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 8194 8194"
        Write-Host "Set page file for 4 gb of memory"
    }
    #6gb
    If (($TotalMemSize -gt "4") -and ($TotalMemSize -le "6.1"))
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 12288 12288"
        Write-Host "Set page file for 6 gb of memory"
    }
    #8gb
    If (($TotalMemSize -gt "6") -and ($TotalMemSize -le "8.1"))
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 16384 16384"
        Write-Host "Set page file for 8 gb of memory"
    }
    #12
    If (($TotalMemSize -gt "8") -and ($TotalMemSize -le "12.1")) 
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 24576 24576"
        Write-Host "Set page file for 12 gb of memory"
    }
    #16
    If (($TotalMemSize -gt "12") -and ($TotalMemSize -le "16.1"))
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 32768 32768"
        Write-Host "Set page file for 16 gb of memory"
    }
    #24
    If (($TotalMemSize -gt "16") -and ($TotalMemSize -le "24.1"))
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 49152 49152"
        Write-Host "Set page file for 24 gb of memory"
    }
    #32
    If (($TotalMemSize -gt "24") -and ($TotalMemSize -le "32.1"))
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 65536 65536"
        Write-Host "Set page file for 32 gb of memory"
    }
    #64
    If (($TotalMemSize -gt "32") -and ($TotalMemSize -le "64.1"))
    {
        Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value "$Drive\pagefile.sys 131072 131072"
        Write-Host "Set page file for 32 gb of memory"
    }
}

Function Update-HostsFile {
  $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
  $domains = @(
    "adclick.g.doublecklick.net", 
    "adeventtracker.spotify.com", 
    "ads-fa.spotify.com", 
    "analytics.spotify.com", 
    "audio2.spotify.com", 
    "b.scorecardresearch.com", 
    "bounceexchange.com", 
    "bs.serving-sys.com", 
    "content.bitsontherun.com", 
    "core.insightexpressai.com", 
    "crashdump.spotify.com", 
    "d2gi7ultltnc2u.cloudfront.net", 
    "d3rt1990lpmkn.cloudfront.net", 
    "desktop.spotify.com", 
    "doubleclick.net", 
    "ds.serving-sys.com", 
    "googleadservices.com", 
    "googleads.g.doubleclick.net", 
    "gtssl2-ocsp.geotrust.com", 
    "js.moatads.com", 
    "log.spotify.com", 
    "media-match.com", 
    "omaze.com", 
    "open.spotify.com", 
    "pagead46.l.doubleclick.net", 
    "pagead2.googlesyndication.com", 
    "partner.googleadservices.com", 
    "pubads.g.doubleclick.net", 
    "redirector.gvt1.com", 
    "s0.2mdn.net", 
    "securepubads.g.doubleclick.net", 
    "spclient.wg.spotify.com", 
    "tpc.googlesyndication.com", 
    "v.jwpcdn.com", 
    "video-ad-stats.googlesyndication.com", 
    "weblb-wg.gslb.spotify.com", 
    "www.googleadservices.com", 
    "www.googletagservices.com", 
    "www.omaze.com"
  )
  Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
  foreach ($domain in $domains) {
      if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
          Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
      }
  }
  
}

Function Optimize-UI
{
Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Apply MarkC's mouse acceleration fix"
Set-ItemProperty "HKCU:\Control Panel\Mouse" "MouseSensitivity" "10"
Set-ItemProperty "HKCU:\Control Panel\Mouse" "MouseSpeed" "0"
Set-ItemProperty "HKCU:\Control Panel\Mouse" "MouseThreshold1" "0"
Set-ItemProperty "HKCU:\Control Panel\Mouse" "MouseThreshold2" "0"
Set-ItemProperty "HKCU:\Control Panel\Mouse" "SmoothMouseXCurve" ([byte[]](0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
Set-ItemProperty "HKCU:\Control Panel\Mouse" "SmoothMouseYCurve" ([byte[]](0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))

Write-Output "Disable mouse pointer hiding"
Set-ItemProperty "HKCU:\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x9e,
0x1e, 0x06, 0x80, 0x12, 0x00, 0x00, 0x00))

Write-Output "Disable Game DVR and Game Bar"
force-mkdir "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowgameDVR" 0

Write-Output "Disable easy access keyboard stuff"
Set-ItemProperty "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"
Set-ItemProperty "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122"
Set-ItemProperty "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58"

Write-Output "Setting default explorer view to This PC"
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1

Write-Output "Removing user folders under This PC"
# Remove Desktop from This PC
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
# Remove Documents from This PC
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
# Remove Downloads from This PC
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
# Remove Music from This PC
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
# Remove Pictures from This PC
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
# Remove Videos from This PC
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
# Remove 3D Objects from This PC
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
Remove-Item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
}

Set-PageFile
Disable-Ads
Disable-ConsumerExperience
Disable-WindowsTips
Disable-OneDrive
Update-HostsFile
Optimize-UI

$DesktopPath = [Environment]::GetFolderPath("Desktop");
mkdir "$DesktopPath\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
