##########
# Master Branch : https://github.com/ChrisTitusTech/win10script
# Current Author : Daddy Madu 
# Current Author Source: https://github.com/DaddyMadu/Windows10GamingFocus
#
#    Note from author: Never run scripts without reading them & understanding what they do.
#
#	Addition: One command to rule them all, One command to find it, and One command to Run it! 
#
#     > powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://tweaks.daddymadu.gg')"
#
#     Changelogs Moved to ReadMe File for better mangement. 
#
##########
$host.ui.RawUI.WindowTitle = "Keidorian Windows 10 Debloater and Gaming Tweaker"
cmd /c 'title [DaddyMadu Ultimate Windows 10 Debloater and Gaming Focus Tweaker]'
Write-Host 'Welcome to DaddyMadu Ultimate Windows 10 Debloater and Gaming Focus Tweaker';
Write-Host "Please DISABLE your ANTIVIRUS to prevent any issues and PRESS any KEY to Continue!" -ForegroundColor Red -BackgroundColor Black
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
cls
# Default preset
$tweaks = @(
	### Require administrator privileges ###
	"RequireAdmin",
	
	### Chris Titus Tech Additions
	#"SlowUpdatesTweaks",
	"Write-ColorOutput", #Utilizing Colors for better Warning messages!
	"EnableUlimatePower",    # DaddyMadu don't change order it will break other functions! just disable if you want with #
	# "ChangeDefaultApps", # Removed due to issues with steam and resetting default apps
	
	### DaddyMadu Windows Defender Settings! Don't Change Order Just Disable with # If You Don't want it ###
	#"askDefender",
	#"DorEOneDrive",                  #Option to Install Or Uninstall Microsoft One Drive!
	#"askXBOX",
	#"Windows11Extra",
	#"askMSPPS",                      #Option to enable or disable Microsoft Software Protection Platform Service” Causing High CPU Usage
	#"askMSWSAPPX",                   #Option to enable or disable Wsappx to Fix 100% Disk Usage in Windows 10 in older systems

	### Windows Apps
	"DebloatAll",

	### Privacy Tweaks ###
	"DisableTelemetry",             # "EnableTelemetry",
	"DisableMapUpdates",            # "EnableMapUpdates",
	"DisableCortana",               # "EnableCortana",
	"DisableNewsFeed",

	### Security Tweaks ###
	#"DisableAdminShares",           # "EnableAdminShares",
	"DisableSMB1",                # "EnableSMB1",
	
	### Service Tweaks ###
	"DisableHomeGroups",          # "EnableHomeGroups",
	"DisableSharedExperiences",     # "SharedExperiences",
	"DisableHibernation",		# "EnableHibernation",
	"DisableFastStartup",         # "EnableFastStartup",

    ### Windows Tweaks ###
	"DisableCloudSearch",
	
	### UI Tweaks ###
	"DisableStickyKeys",            # "EnableStickyKeys",
	"Finished"
)

#########
# Pre Customizations
#########

Function SlowUpdatesTweaks {
	Write-Output "Improving Windows Update to delay Feature updates and only install Security Updates"
	### Fix Windows Update to delay feature updates and only update at certain times
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWord -Value 1 -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 30d -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4d -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseFeatureUpdatesStartTime" -Type String -Value "" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "PauseFeatureUpdatesStartTime" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "PauseQualityUpdatesStartTime" -Type String -Value "" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "PauseQualityUpdatesStartTime" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd" -Type DWord -Value 2 -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ActiveHoursStart" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart" -Type DWord -Value 8 -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" -Name "PausedQualityDate" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" -Name "PausedFeatureDate" -ErrorAction SilentlyContinue | Out-Null
}

#Utilizing Clolors For Better Warning Messages!
function Write-ColorOutput
{
    [CmdletBinding()]
    Param(
         [Parameter(Mandatory=$False,Position=1,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][Object] $Object,
         [Parameter(Mandatory=$False,Position=2,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $ForegroundColor,
         [Parameter(Mandatory=$False,Position=3,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $BackgroundColor,
         [Switch]$NoNewline
    )    

    # Save previous colors
    $previousForegroundColor = $host.UI.RawUI.ForegroundColor
    $previousBackgroundColor = $host.UI.RawUI.BackgroundColor

    # Set BackgroundColor if available
    if($BackgroundColor -ne $null)
    { 
       $host.UI.RawUI.BackgroundColor = $BackgroundColor
    }

    # Set $ForegroundColor if available
    if($ForegroundColor -ne $null)
    {
        $host.UI.RawUI.ForegroundColor = $ForegroundColor
    }

    # Always write (if we want just a NewLine)
    if($Object -eq $null)
    {
        $Object = ""
    }

    if($NoNewline)
    {
        [Console]::Write($Object)
    }
    else
    {
        Write-Output $Object
    }

    # Restore previous colors
    $host.UI.RawUI.ForegroundColor = $previousForegroundColor
    $host.UI.RawUI.BackgroundColor = $previousBackgroundColor
}

#Enable or Disable and remove xbox related apps
Function askXBOX {
	do
 {
    cls
    Write-Host "================ Do You Want To Disable XBOX features and all related APPS? ================"
	Write-ColorOutput "WARNING: REMOVING XBOX APPS will make Win+G do nothing!" Red
    Write-Host "Y: Press 'Y' to Disable XBOX features."
    Write-Host "N: Press 'N' to Enable XBOX features."
    Write-Host "Q: Press 'Q' to Skip this."
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    'y' { 
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
        Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
        $ErrorActionPreference = $errpref #restore previous preference
	cls
	}
    'n' {
        $errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
        Write-Output "Enabling Xbox features..."
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
        $ErrorActionPreference = $errpref #restore previous preference
	cls
		}
    'q' { }
    }
 }
 until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
	
}

##########
# Privacy Tweaks
##########

# Disable Telemetry
# Note: This tweak may cause Enterprise edition to stop receiving Windows updates.
# Windows Update control panel will then show message "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going".
# In such case, enable telemetry, run Windows update and then disable telemetry again. See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57
Function DisableTelemetry {
	Write-Output "Disabling Telemetry..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

# Enable Telemetry
Function EnableTelemetry {
	Write-Output "Enabling Telemetry..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

# Disable automatic Maps updates
Function DisableMapUpdates {
	Write-Output "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

# Enable automatic Maps updates
Function EnableMapUpdates {
	Write-Output "Enable automatic Maps updates..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue
}

# Disable Cortana
Function DisableCortana {
	Write-Output "Disabling Cortana..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
}

# Enable Cortana
Function EnableCortana {
	Write-Output "Enabling Cortana..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
}

# Disable New Windows 10 21h1 News Feed
Function DisableNewsFeed {
        Write-Output "Disabling Windows 10 News and Interests Feed..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
	}

##########
# Security Tweaks
##########

# Disable implicit administrative shares
Function DisableAdminShares {
	Write-Output "Disabling implicit administrative shares..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

# Enable implicit administrative shares
Function EnableAdminShares {
	Write-Output "Enabling implicit administrative shares..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}

#Ask User If He Want to Enable Or Disable Windows Defender
Function askDefender {
	
	do
 {
    cls
    Write-Host "================ Do you want to Disable Microsoft Windows Defender? ================"
    Write-Host "Y: Press 'Y' to Disable Microsoft Windows Defender."
    Write-Host "N: Press 'N' to Enable Microsoft Windows Defender."
	Write-Host "Q: Press 'Q' to Skip this."
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    'y' { 
	Write-Output "Disabling Microsoft Windows Defender and related Processes..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -ErrorAction SilentlyContinue
	Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
    cls
	}
    'n' {
        Write-Output "Enabling Microsoft Windows Defender and related Processes..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
	}
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Type DWord -Value 1
	Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
	Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
	cls
		}
    'q' {  }
    }
 }
 until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
	
}

#Ask User If He Want to Enable Or Disable Microsoft Software Protection Platform Service
Function askMSPPS {
	
	do
 {
    cls
    Write-Host "================ Do you have High CPU Usage from Microsoft Software Protection Platform Service? ================"
	Write-ColorOutput "WARNING: Windows Default is ENABLED, if you Disabled it, Windows 10/Office will show not activated state but you can use it as normal" Red
    Write-Host "Y: Press 'Y' to Disable this."
    Write-Host "N: Press 'N' to Enable this."
	Write-Host "Q: Press 'Q' to stop the entire script."
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    'y' { 
	    Write-Output "Disabling Microsoft Software Protection Platform Service and related Processes..."
		Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" | Out-Null
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sppsvc" -Name "Start" -Type DWord -Value 4 -ErrorAction SilentlyContinue
		cls
	}
    'n' {
        Write-Output "Enabling Microsoft Software Protection Platform Service and related Processes..."
	    Enable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" | Out-Null
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sppsvc" -Name "Start" -Type DWord -Value 2 -ErrorAction SilentlyContinue
		cls
		}
    'q' { Exit  }
    }
 }
 until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
	
}

#Ask User If He Want to Enable Or Disable Microsoft Store and WSAPPX Service
Function askMSWSAPPX {
	
	do
 {
    cls
    Write-Host "================ Do you want to disable Microsoft Store and Disable WSAPPX Service? ================"
	Write-ColorOutput "WARNING: Windows Default is ENABLED, if you Disabled it and wanted to enable it again and restore Microsoft Store Please run the script twise and choose N" Red
    Write-Host "Y: Press 'Y' to Disable this."
    Write-Host "N: Press 'N' to Enable this."
	Write-Host "Q: Press 'Q' to stop the entire script."
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    'y' { 
	    Write-Output "Disabling Microsoft Store and WSAPPX Service..."
	        $errpref = $ErrorActionPreference #save actual preference
                $ErrorActionPreference = "silentlycontinue"
		Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage -ErrorAction SilentlyContinue
		Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage -ErrorAction SilentlyContinue
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Type DWord -Value 1 -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\AppXSvc" -Name "Start" -Type DWord -Value 4 -ErrorAction SilentlyContinue
		$ErrorActionPreference = $errpref #restore previous preference
		cls
	}
    'n' {
        Write-Output "Enabling Microsoft Store and WSAPPX Service..."
		$errpref = $ErrorActionPreference #save actual preference
                $ErrorActionPreference = "silentlycontinue"
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -ErrorAction SilentlyContinue
		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
		Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\AppXSvc" -Name "Start" -Type DWord -Value 3 -ErrorAction SilentlyContinue
		Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} -ErrorAction SilentlyContinue
		Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} -ErrorAction SilentlyContinue
		$ErrorActionPreference = $errpref #restore previous preference
		cls
		}
    'q' { Exit  }
    }
 }
 until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
	
}

##########
# Service Tweaks
##########
#Disabling Un nessessary Services For Gaming
Function DISGaming {
	Write-Output "Stopping and disabling Un nessessary Services For Gaming..."
	$errpref = $ErrorActionPreference #save actual preference
    	$ErrorActionPreference = "silentlycontinue"
	Stop-Service "wisvc" -WarningAction SilentlyContinue
	Set-Service "wisvc" -StartupType Disabled
	Stop-Service "MapsBroker" -WarningAction SilentlyContinue
	Set-Service "MapsBroker" -StartupType Disabled
	Stop-Service "UmRdpService" -WarningAction SilentlyContinue
	Set-Service "UmRdpService" -StartupType Disabled
	Stop-Service "TrkWks" -WarningAction SilentlyContinue
	Set-Service "TrkWks" -StartupType Disabled
	Stop-Service "TermService" -WarningAction SilentlyContinue
	Set-Service "TermService" -StartupType Disabled
	Stop-Service "PcaSvc" -WarningAction SilentlyContinue
	Set-Service "PcaSvc" -StartupType Disabled
	$ErrorActionPreference = $errpref #restore previous preference
}

# Stop and disable Home Groups services - Not applicable to 1803 and newer or Server
Function DisableHomeGroups {
	Write-Output "Stopping and disabling Home Groups services..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled
	$ErrorActionPreference = $errpref #restore previous preference
}

# Enable and start Home Groups services - Not applicable to 1803 and newer or Server
Function EnableHomeGroups {
	Write-Output "Starting and enabling Home Groups services..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	Set-Service "HomeGroupListener" -StartupType Manual
	Set-Service "HomeGroupProvider" -StartupType Manual
	Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
		$ErrorActionPreference = $errpref #restore previous preference
}

# Disable Shared Experiences - Not applicable to Server
Function DisableSharedExperiences {
	Write-Output "Disabling Shared Experiences..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0
}

# Enable Shared Experiences - Not applicable to Server
Function EnableSharedExperiences {
	Write-Output "Enabling Shared Experiences..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -ErrorAction SilentlyContinue
}

# Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
Function EnableHibernation {
	Write-Output "Enabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 1
}

# Disable Hibernation
Function DisableHibernation {
	Write-Output "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
}

# Disable Fast Startup
Function DisableFastStartup {
	Write-Output "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

# Enable Fast Startup
Function EnableFastStartup {
	Write-Output "Enabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}


##########
# Windows Tweaks
##########

#Setting Processor scheduling.
Function Win32PrioritySeparation {
	Write-Output "Setting Processor scheduling..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000026
}

#Disabling Cloud Search.
Function DisableCloudSearch {
	Write-Output "Disabling Cloud Search..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0
}

##########
# UI Tweaks
##########

# Disable Sticky keys prompt
Function DisableStickyKeys {
	Write-Output "Disabling Sticky keys prompt..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

# Enable Sticky keys prompt
Function EnableStickyKeys {
	Write-Output "Enabling Sticky keys prompt..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
}

##########
# Application Tweaks
##########
# Option To Uninstall Or install OneDrive 
Function DorEOneDrive {
	
	do
 {
    cls
    Write-Host "================ Do you want to Disable Microsoft OneDrive? ================"
    Write-Host "Y: Press 'Y' to Disable OneDrive."
    Write-Host "N: Press 'N' to Enable OneDrive."
	Write-Host "Q: Press 'Q' to Skip this."
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    'y' { 
	Write-Output "Disabling Microsoft OneDrive and related Processes..."
        # Disable OneDrive
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 -ErrorAction SilentlyContinue
# Uninstall OneDrive - Not applicable to Server
	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
        reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
        reg unload "hku\Default"
	Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
	Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
	$ErrorActionPreference = $errpref #restore previous preference
	cls
	}
    'n' {
        Write-Output "Enabling Microsoft OneDrive and related Processes..."
	# Enable OneDrive
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
	
    # Install OneDrive - Not applicable to Server
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive -NoNewWindow
	$ErrorActionPreference = $errpref #restore previous preference
	cls
		}
    'q' {  }
    }
 }
 until ($selection -match "y" -or $selection -match "n" -or $selection -match "q")
	
}

##########
# DaddyMadu Quality Of Life Tweaks
##########
# Windows 11 Extra Tweaks
function Windows11Extra {
	If ([System.Environment]::OSVersion.Version.Build -ge 22000) {
	        Write-Output "Restoring windows 10 context menu and disabling start menu recommended section..."
		New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -ErrorAction SilentlyContinue | Out-Null #context menu setup
		Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value "" #restore windows 10 context menu
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0 #set taskbar icons to the left
		Get-appxpackage -all *shellexperience* -packagetype bundle |% {add-appxpackage -register -disabledevelopmentmode ($_.installlocation + '\appxmetadata\appxbundlemanifest.xml')}
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0 #disable widget icon from taskbar
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0 #disable chat icon from taskbar
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1 #Disable start menu RecentlyAddedApps
	}
}

##########
# Gaming Tweaks Functions
##########

#Add Utimate Power Plan And Activate It
Function EnableUlimatePower {
	Write-Output "Enabling and Activating Bitsum Highest Performance Power Plan..."
	Invoke-WebRequest -Uri "https://git.io/JsWhn" -OutFile "$Env:windir\system32\Bitsum-Highest-Performance.pow" -ErrorAction SilentlyContinue
	powercfg -import "$Env:windir\system32\Bitsum-Highest-Performance.pow" e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
	powercfg -setactive e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
}

#Disable DMA memory protection and cores isolation ("virtualization-based protection").
Function DisableDMA {
        Write-Output "Disabling DMA memory protection and cores isolation..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
        bcdedit /set vsmlaunchtype Off | Out-Null
        bcdedit /set vm No | Out-Null
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Type DWord -Value 0
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Out-Null -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0
	$ErrorActionPreference = $errpref #restore previous preference
}

#DaddyMadu Ultimate CLeaner
Function UltimateCleaner {
    Write-Host "Running DaddyMadu Ultimate Cleaner => Temp folders & Flush DNS + Reset IP...."
cmd /c 'netsh winsock reset 2>nul' >$null
cmd /c 'netsh int ip reset 2>nul' >$null
cmd /c 'ipconfig /release 2>nul' >$null
cmd /c 'ipconfig /renew 2>nul' >$null
cmd /c 'ipconfig /flushdns 2>nul' >$null
cmd /c 'echo Flush DNS + IP Reset Completed Successfully!'
cmd /c 'echo Clearing Temp folders....'
cmd /c 'del /f /s /q %systemdrive%\*.tmp 2>nul' >$null
cmd /c 'del /f /s /q %systemdrive%\*._mp 2>nul' >$null
cmd /c 'del /f /s /q %systemdrive%\*.log 2>nul' >$null
cmd /c 'del /f /s /q %systemdrive%\*.gid 2>nul' >$null
cmd /c 'del /f /s /q %systemdrive%\*.chk 2>nul' >$null
cmd /c 'del /f /s /q %systemdrive%\*.old 2>nul' >$null
cmd /c 'del /f /s /q %systemdrive%\recycled\*.* 2>nul' >$null
cmd /c 'del /f /s /q %windir%\*.bak 2>nul' >$null
cmd /c 'del /f /s /q %windir%\prefetch\*.* 2>nul' >$null
cmd /c 'del /f /q %userprofile%\cookies\*.* 2>nul' >$null
cmd /c 'del /f /q %userprofile%\recent\*.* 2>nul' >$null
cmd /c 'del /f /s /q %userprofile%\Local Settings\Temporary Internet Files\*.* 2>nul' >$null
$errpref = $ErrorActionPreference #save actual preference
$ErrorActionPreference = "silentlycontinue"
Get-ChildItem -Path "$env:temp" -Exclude "dmtmp" | foreach ($_) {
       "CLEANING :" + $_.fullname
       Remove-Item $_.fullname -Force -Recurse
       "CLEANED... :" + $_.fullname
   }
$ErrorActionPreference = $errpref #restore previous preference
cmd /c 'del /f /s /q %userprofile%\recent\*.* 2>nul' >$null
cmd /c 'del /f /s /q %windir%\Temp\*.* 2>nul' >$null
cmd /c 'echo Temp folders Cleared Successfully!'
}

#Notifying user to reboot!
Function Finished {
  	cmd /c 'REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Manufacturer" /t REG_SZ /d "This PC is Optimized by Keidorian" /f 2>nul' >$null
      	Start-Sleep -s 5
        Write-Output "Done! Please Reboot Your PC!"
}

##########
# Auxiliary Functions
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

# Wait for key press
Function WaitForKey {
	Write-Output "Press any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}

##########
# Debloat Script Additions
##########

Function Stop-EdgePDF {
    
    #Stops edge from taking over as the default .PDF viewer    
    Write-Output "Stopping Edge from taking over as the default .PDF viewer"
# Identify the edge application class 
$Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" 
$edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge" 
 
# Specify the paths to the file and URL associations 
$FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations 
$URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations 
 
# get the software classes for the file and URL types that Edge will associate 
$FileTypes = Get-Item $FileAssocKey 
$URLTypes = Get-Item $URLAssocKey 
 
$FileAssoc = Get-ItemProperty $FileAssocKey 
$URLAssoc = Get-ItemProperty $URLAssocKey 
 
$Associations = @() 
$Filetypes.Property | foreach {$Associations += $FileAssoc.$_} 
$URLTypes.Property | foreach {$Associations += $URLAssoc.$_} 
 
# add registry values in each software class to stop edge from associating as the default 
foreach ($Association in $Associations) 
     { 
     $Class = Join-Path HKCU:SOFTWARE\Classes $Association 
     #if (Test-Path $class) 
     #   {write-host $Association} 
     # Get-Item $Class 
     Set-ItemProperty $Class -Name NoOpenWith -Value "" 
     Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value "" 
     } 
}

# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse

Function DebloatAll {
cls
    $Bloatware = @(
    #Unnecessary Windows 10 AppX Apps
      "*Microsoft.Microsoft3DViewer*",
      "*Microsoft.AppConnector*",
      "*Microsoft.BingFinance*",
      "*Microsoft.BingNews*",
      "*Microsoft.BingSports*",
      "*Microsoft.BingTranslator*",
      "*Microsoft.BingWeather*",
      "*Microsoft.BingFoodAndDrink*",
      "*Microsoft.BingHealthAndFitness*",
      "*Microsoft.BingTravel*",
      "*Microsoft.MinecraftUWP*",
      "*Microsoft.GamingServices*",
      "*Microsoft.GetHelp*",
      "*Microsoft.Getstarted*",
      "*Microsoft.Messaging*",
      "*Microsoft.Microsoft3DViewer*",
      "*Microsoft.MicrosoftSolitaireCollection*",
      "*Microsoft.NetworkSpeedTest*",
      "*Microsoft.News*",
      "*Microsoft.Office.Lens*",
      "*Microsoft.Office.Sway*",
      "*Microsoft.Office.OneNote*",
      "*Microsoft.OneConnect*",
      "*Microsoft.People*",
      "*Microsoft.Print3D*",
      "*Microsoft.SkypeApp*",
      "*Microsoft.Wallet*",
      "*Microsoft.Whiteboard*",
      "*Microsoft.WindowsAlarms*",
      "*microsoft.windowscommunicationsapps*",
      "*Microsoft.WindowsFeedbackHub*",
      "*Microsoft.WindowsMaps*",
      "*Microsoft.WindowsPhone*",
      "*Microsoft.WindowsSoundRecorder*",
      "*Microsoft.XboxApp*",
      "*Microsoft.ConnectivityStore*",
      "*Microsoft.CommsPhone*",
      "*Microsoft.ScreenSketch*",
      "*Microsoft.Xbox.TCUI*",
      "*Microsoft.XboxGameOverlay*",
      "*Microsoft.XboxGameCallableUI*",
      "*Microsoft.XboxSpeechToTextOverlay*",
      "*Microsoft.MixedReality.Portal*",
      "*Microsoft.XboxIdentityProvider*",
      "*Microsoft.ZuneMusic*",
      "*Microsoft.ZuneVideo*",
      "*Microsoft.Getstarted*",
      "*Microsoft.MicrosoftOfficeHub*",
      
      		
        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
	
      "*EclipseManager*",
      "*ActiproSoftwareLLC*",
      "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
      "*Duolingo-LearnLanguagesforFree*",
      "*PandoraMediaInc*",
      "*CandyCrush*",
      "*BubbleWitch3Saga*",
      "*Wunderlist*",
      "*Flipboard*",
      "*Twitter*",
      "*Facebook*",
      "*Royal Revolt*",
      "*Sway*",
      "*Speed Test*",
      "*Dolby*",
      "*Viber*",
      "*ACGMediaPlayer*",
      "*Netflix*",
      "*OneCalendar*",
      "*LinkedInforWindows*",
      "*HiddenCityMysteryofShadows*",
      "*Hulu*",
      "*HiddenCity*",
      "*AdobePhotoshopExpress*",
      "*HotspotShieldFreeVPN*",
      "*Microsoft.Advertising.Xaml*"
		
    )
    foreach ($Bloat in $Bloatware) {
	$errpref = $ErrorActionPreference #save actual preference
   	 $ErrorActionPreference = "silentlycontinue"
        Get-AppxPackage -AllUsers -Name $Bloat| Remove-AppxPackage | Out-Null -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online | Out-Null -ErrorAction SilentlyContinue
	$ErrorActionPreference = $errpref #restore previous preference
        Write-Output "Trying to remove $Bloat."
    }
}

##########
# Parse parameters and apply tweaks
##########

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }
