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
	"SlowUpdatesTweaks",
	"Write-ColorOutput", #Utilizing Colors for better Warning messages!
	#"EnableUlimatePower",    # DaddyMadu don't change order it will break other functions! just disable if you want with #
	# "ChangeDefaultApps", # Removed due to issues with steam and resetting default apps
	
	### DaddyMadu Windows Defender Settings! Don't Change Order Just Disable with # If You Don't want it ###
	#"askDefender",
	#"DorEOneDrive",                  #Option to Install Or Uninstall Microsoft One Drive!
	"askXBOX",
	#"Windows11Extra",
	#"askMSPPS",                      #Option to enable or disable Microsoft Software Protection Platform Service” Causing High CPU Usage
	#"askMSWSAPPX",                   #Option to enable or disable Wsappx to Fix 100% Disk Usage in Windows 10 in older systems

	### Windows Apps
	"DebloatAll",

	### Privacy Tweaks ###
	"DisableTelemetry",             # "EnableTelemetry",
	#"DisableWiFiSense",             # "EnableWiFiSense",
	#"DisableSmartScreen",         # "EnableSmartScreen",
	#"DisableWebSearch",             # "EnableWebSearch",
	#"DisableAppSuggestions",        # "EnableAppSuggestions",
	#"DisableActivityHistory",       # "EnableActivityHistory",
	#"EnableBackgroundApps",           
	#"DisableBackgroundApps",
	#"DisableLocationTracking",      # "EnableLocationTracking",
	"DisableMapUpdates",            # "EnableMapUpdates",
	#"DisableFeedback",              # "EnableFeedback",
	#"DisableTailoredExperiences",   # "EnableTailoredExperiences",
	#"DisableAdvertisingID",         # "EnableAdvertisingID",
	"DisableCortana",               # "EnableCortana",
	#"DisableErrorReporting",        # "EnableErrorReporting",
	#"SetP2PUpdateLocal",          # "SetP2PUpdateInternet",
	#"DisableDiagTrack",             # "EnableDiagTrack",
	#"DisableWAPPush",               # "EnableWAPPush",
	"DisableNewsFeed",

	### Security Tweaks ###
	#"SetUACLow",                  # "SetUACHigh",
	# "EnableSharingMappedDrives",  # "DisableSharingMappedDrives",
	# "DisableAdminShares",           # "EnableAdminShares",
	"DisableSMB1",                # "EnableSMB1",
	# "DisableSMBServer",           # "EnableSMBServer",
	# "DisableLLMNR",               # "EnableLLMNR",
	#"SetCurrentNetworkPrivate",     # "SetCurrentNetworkPublic",
	#"SetUnknownNetworksPrivate",  # "SetUnknownNetworksPublic",
	#"DisableNetDevicesAutoInst",  # "EnableNetDevicesAutoInst",
	#"SetDEPOptOut",                 # "SetDEPOptIn",
	# "EnableCIMemoryIntegrity",    # "DisableCIMemoryIntegrity",
	#"DisableScriptHost",            # "EnableScriptHost",
	#"EnableDotNetStrongCrypto",     # "DisableDotNetStrongCrypto",
	#"DisableMeltdownCompatFlag", # "EnableMeltdownCompatFlag"    

	### Service Tweaks ###
	#"EnableUpdateMSRT",          # "EnableUpdateMSRT",    #"DisableUpdateMSRT",
	#"EnableUpdateDriver",        # "EnableUpdateDriver",  #"DisableUpdateDriver",
	#"DisableUpdateRestart",         # "EnableUpdateRestart",
	"DisableHomeGroups",          # "EnableHomeGroups",
	"DisableSharedExperiences",     # "SharedExperiences",
	#"DisableRemoteAssistance",      # "EnableRemoteAssistance",
	#"EnableRemoteDesktop",          # "DisableRemoteDesktop",
	#"DisableAutoplay",              # "EnableAutoplay",
	#"DisableAutorun",               # "EnableAutorun",
	#"DisableStorageSense",        # "EnableStorageSense",
	#"DisableDefragmentation",     # "EnableDefragmentation",
	#"DisableSuperfetch",          # "EnableSuperfetch",
	#"EnableIndexing",
	"DisableHibernation",		# "EnableHibernation",
	"DisableFastStartup",         # "EnableFastStartup",
	"DISGaming",


    ### Windows Tweaks ###
	#"PowerThrottlingOff",
	#"Win32PrioritySeparation",
	#"DisableAERO",
	#"BSODdetails",
	#"Disablelivetiles",
	#"wallpaperquality",
	#"DisableShistory",
	#"Disableshortcutword",
	#"DisableMouseKKS",
	#"DisableTransparency",
	#"TurnOffSafeSearch",
	"DisableCloudSearch",
	#"DisableDeviceHistory",
	#"DisableRemoteAssistance",
	#"DisableSearchHistroy",
	#"RemoveMeet",
	
	
	### UI Tweaks ###
	"DisableStickyKeys",            # "EnableStickyKeys",
	#"SetVisualFXPerformance",     # "SetVisualFXAppearance",
	# "AddENKeyboard",              # "RemoveENKeyboard",
	#"EnableNumlock",             	# "DisableNumlock",
	#"Stop-EdgePDF",

	### Explorer UI Tweaks ###
	#"EnableThumbnails",          # "EnableThumbnails", # "DisableThumbnails",
	#"EnableThumbsDB",              # "EnableThumbsDB", # "DisableThumbsDB", 

	### Application Tweaks ###
	#"DisableAdobeFlash",            # "EnableAdobeFlash",
	#"UninstallMediaPlayer",         #"InstallMediaPlayer",
	#"UninstallInternetExplorer",  # "InstallInternetExplorer",
	#"UninstallWorkFolders",       # "InstallWorkFolders",
	#"UninstallLinuxSubsystem",      # "UninstallLinuxSubsystem",     #"InstallLinuxSubsystem",
	# "InstallHyperV",              # "UninstallHyperV",
	#"InstallPDFPrinter",		# "UninstallPDFPrinter",
	# "UninstallXPSPrinter",          # "InstallXPSPrinter",
	# "RemoveFaxPrinter",             # "AddFaxPrinter",

        ### DaddyMadu Gaming Tweaks ###
	#"RawMouseInput",
	#"DetectnApplyMouseFIX",
	#"DisableHPET",
	#"EnableGameMode",
	#"EnableHAGS",
	#"DisableDMA",
	#"DisablePKM",
	#"DecreaseMKBuffer",
	#"StophighDPC",
	#"NetworkOptimizations",
	#"RemoveEdit3D",
	#"FixURLext",  # fix issue with games shortcut that created by games lunchers turned white!
	#"UltimateCleaner",
	"Finished"
	### Auxiliary Functions ###
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

# Disable Wi-Fi Sense
Function DisableWiFiSense {
	Write-Output "Disabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
}

# Enable Wi-Fi Sense
Function EnableWiFiSense {
	Write-Output "Enabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -ErrorAction SilentlyContinue
}

# Disable SmartScreen Filter
Function DisableSmartScreen {
	Write-Output "Disabling SmartScreen Filter..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}

# Enable SmartScreen Filter
Function EnableSmartScreen {
	Write-Output "Enabling SmartScreen Filter..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
	Write-Output "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

# Enable Web Search in Start Menu
Function EnableWebSearch {
	Write-Output "Enabling Bing Search in Start Menu..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
	Write-Output "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

# Enable Application suggestions and automatic installation
Function EnableAppSuggestions {
	Write-Output "Enabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
}

# Disable Activity History feed in Task View - Note: The checkbox "Let Windows collect my activities from this PC" remains checked even when the function is disabled
Function DisableActivityHistory {
	Write-Output "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

# Enable Activity History feed in Task View
Function EnableActivityHistory {
	Write-Output "Enabling Activity History..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue
}

# Disable Background application access - ie. if apps can download or update when they aren't used - Cortana is excluded as its inclusion breaks start menu search
Function DisableBackgroundApps {
	Write-Output "Disabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}
}

# Enable Background application access
Function EnableBackgroundApps {
	Write-Output "Enabling Background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach {
		Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
	}
}

# Disable Location Tracking
Function DisableLocationTracking {
	Write-Output "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

# Enable Location Tracking
Function EnableLocationTracking {
	Write-Output "Enabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
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

# Disable Feedback
Function DisableFeedback {
	Write-Output "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Enable Feedback
Function EnableFeedback {
	Write-Output "Enabling Feedback..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Disable Tailored Experiences
Function DisableTailoredExperiences {
	Write-Output "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

# Enable Tailored Experiences
Function EnableTailoredExperiences {
	Write-Output "Enabling Tailored Experiences..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue
}

# Disable Advertising ID
Function DisableAdvertisingID {
	Write-Output "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

# Enable Advertising ID
Function EnableAdvertisingID {
	Write-Output "Enabling Advertising ID..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue
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

# Disable Error reporting
Function DisableErrorReporting {
	Write-Output "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Enable Error reporting
Function EnableErrorReporting {
	Write-Output "Enabling Error reporting..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Restrict Windows Update P2P only to local network - Needed only for 1507 as local P2P is the default since 1511
Function SetP2PUpdateLocal {
	Write-Output "Restricting Windows Update P2P only to local network..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1 | Out-Null -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 1 -Force | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

# Unrestrict Windows Update P2P
Function SetP2PUpdateInternet {
	Write-Output "Unrestricting Windows Update P2P to internet..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue
}

# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
	Write-Output "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}

# Enable and start Diagnostics Tracking Service
Function EnableDiagTrack {
	Write-Output "Enabling and starting Diagnostics Tracking Service..."
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack" -WarningAction SilentlyContinue
}

# Stop and disable WAP Push Service
Function DisableWAPPush {
	Write-Output "Stopping and disabling WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}

# Enable and start WAP Push Service
Function EnableWAPPush {
	Write-Output "Enabling and starting WAP Push Service..."
	Set-Service "dmwappushservice" -StartupType Automatic
	Start-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
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

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Output "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Raise UAC level
Function SetUACHigh {
	Write-Output "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
	Write-Output "Enabling sharing mapped drives between users..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}

# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
	Write-Output "Disabling sharing mapped drives between users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

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

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
	Write-Output "Enabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

# Disable SMB Server - Completely disables file and printer sharing, but leaves the system able to connect to another SMB server as a client
Function DisableSMBServer {
	Write-Output "Disabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
}

# Enable SMB Server
Function EnableSMBServer {
	Write-Output "Enabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
}

# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
Function DisableLLMNR {
	Write-Output "Disabling LLMNR..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
}

# Enable Link-Local Multicast Name Resolution (LLMNR) protocol
Function EnableLLMNR {
	Write-Output "Enabling LLMNR..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}

# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
	Write-Output "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private
}

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public
}

# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
	Write-Output "Setting unknown networks profile to private..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}

# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
	Write-Output "Setting unknown networks profile to public..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
	Write-Output "Disabling automatic installation of network devices..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst {
	Write-Output "Enabling automatic installation of network devices..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue
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

# Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security - Supported from 1803
Function EnableCIMemoryIntegrity {
	Write-Output "Enabling Core Isolation Memory Integrity..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
}

# Disable Core Isolation Memory Integrity - 
Function DisableCIMemoryIntegrity {
	Write-Output "Disabling Core Isolation Memory Integrity..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Enable strong cryptography for .NET Framework (version 4 and above)
# https://stackoverflow.com/questions/36265534/invoke-webrequest-ssl-fails
Function EnableDotNetStrongCrypto {
	Write-output "Enabling .NET strong cryptography..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
}

# Disable strong cryptography for .NET Framework (version 4 and above)
Function DisableDotNetStrongCrypto {
	Write-output "Disabling .NET strong cryptography..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
}

# Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January 2018 and all subsequent Windows updates
# This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
# Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
# See https://support.microsoft.com/en-us/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software for details.
Function EnableMeltdownCompatFlag {
	Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

# Disable Meltdown (CVE-2017-5754) compatibility flag
Function DisableMeltdownCompatFlag {
	Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
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

# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
	Write-Output "Disabling Malicious Software Removal Tool offering..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT {
	Write-Output "Enabling Malicious Software Removal Tool offering..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

# Disable offering of drivers through Windows Update
# Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
# Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
Function DisableUpdateDriver {
	Write-Output "Disabling driver offering through Windows Update..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
}

# Enable offering of drivers through Windows Update
Function EnableUpdateDriver {
	Write-Output "Enabling driver offering through Windows Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}

# Disable Windows Update automatic restart
# Note: This doesn't disable the need for the restart but rather tries to ensure that the restart doesn't happen in the least expected moment. Allow the machine to restart as soon as possible anyway.
Function DisableUpdateRestart {
	Write-Output "Disabling Windows Update automatic restart..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
}

# Enable Windows Update automatic restart
Function EnableUpdateRestart {
	Write-Output "Enabling Windows Update automatic restart..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
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

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
	Write-Output "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
	Write-Output "Enabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
}

# Enable Remote Desktop w/o Network Level Authentication
Function EnableRemoteDesktop {
	Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
	Enable-NetFirewallRule -Name "RemoteDesktop*" | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

# Disable Remote Desktop
Function DisableRemoteDesktop {
	Write-Output "Disabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"
}

# Disable Autoplay
Function DisableAutoplay {
	Write-Output "Disabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

# Enable Autoplay
Function EnableAutoplay {
	Write-Output "Enabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
}

# Disable Autorun for all drives
Function DisableAutorun {
	Write-Output "Disabling Autorun for all drives..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

# Enable Autorun for removable drives
Function EnableAutorun {
	Write-Output "Enabling Autorun for all drives..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}

# Enable Storage Sense - automatic disk cleanup - Not applicable to Server
Function EnableStorageSense {
	Write-Output "Enabling Storage Sense..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "08" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "32" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1
}

# Disable Storage Sense - Not applicable to Server
Function DisableStorageSense {
	Write-Output "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

# Disable scheduled defragmentation task
Function DisableDefragmentation {
	Write-Output "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Enable scheduled defragmentation task
Function EnableDefragmentation {
	Write-Output "Enabling scheduled defragmentation..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Stop and disable Superfetch service - Not applicable to Server
Function DisableSuperfetch {
	Write-Output "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}

# Start and enable Superfetch service - Not applicable to Server
Function EnableSuperfetch {
	Write-Output "Starting and enabling Superfetch service..."
	Set-Service "SysMain" -StartupType Automatic
	Start-Service "SysMain" -WarningAction SilentlyContinue
}

# Stop and disable Windows Search indexing service
Function DisableIndexing {
	Write-Output "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
}

# Start and enable Windows Search indexing service
Function EnableIndexing {
	Write-Output "Starting and enabling Windows Search indexing service..."
	Set-Service "WSearch" -StartupType Automatic
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
	Start-Service "WSearch" -WarningAction SilentlyContinue
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
#Disabling power throttling.
Function PowerThrottlingOff {
	Write-Output "Disabling power throttling..."
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 1
}

#Setting Processor scheduling.
Function Win32PrioritySeparation {
	Write-Output "Setting Processor scheduling..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000026
}

#Disabling aero shake.
Function DisableAERO {
	Write-Output "Disabling aero shake..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 0
}

#Show BSOD details instead of the sad smiley.
Function BSODdetails {
	Write-Output "Show BSOD details instead of the sad smiley..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1
}

#Disabling live tiles.
Function Disablelivetiles {
	Write-Output "Disabling live tiles..."
	New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1
}

#Disabling search history.
Function DisableShistory {
	Write-Output "Disabling search history..."
	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1
}

#Disabling "- Shortcut" Word.
Function Disableshortcutword {
	Write-Output "Disabling - Shortcut Word..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
}

#Disabling Mouse Keys Keyboard Shortcut.
Function DisableMouseKKS {
	Write-Output "Disabling Mouse Keys Keyboard Shortcut..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "Flags" -Type String -Value "186"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "MaximumSpeed" -Type String -Value "40"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "TimeToMaximumSpeed" -Type String -Value "3000"
}

#Disabling Windows Transparency.
Function DisableTransparency {
	Write-Output "Disabling Windows Transparency..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
}

#Turning Off Safe Search.
Function TurnOffSafeSearch {
	Write-Output "Turning Off Safe Search..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearchMode" -Type DWord -Value 0
}

#Disabling Cloud Search.
Function DisableCloudSearch {
	Write-Output "Disabling Cloud Search..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0
}

#Disabling Device History.
Function DisableDeviceHistory {
	Write-Output "Disabling Device History..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "DeviceHistoryEnabled" -Type DWord -Value 0
}

#Disabling Windows Remote Assistance.
Function DisableRemoteAssistance {
	Write-Output "Disabling Windows Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

#Disabling Search Histroy.
Function DisableSearchHistroy {
	Write-Output "Disabling Search Histroy..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0
}

#Removing Microsoft MeetNow
Function RemoveMeet {
        Write-Output "Disabling Microsoft MeetNow..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
	$ErrorActionPreference = $errpref #restore previous preference
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

# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
	Write-Output "Adjusting visual effects for performance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Type String -Value 2
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
	Write-Output "Adjusting visual effects for appearance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
}

# Add secondary en-US keyboard
Function AddENKeyboard {
	Write-Output "Adding secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	$langs.Add("en-US")
	Set-WinUserLanguageList $langs -Force
}

# Remove secondary en-US keyboard
Function RemoveENKeyboard {
	Write-Output "Removing secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force
}

# Enable NumLock after startup
Function EnableNumlock {
	Write-Output "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

# Disable NumLock after startup
Function DisableNumlock {
	Write-Output "Disabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
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

# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash {
	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
}

# Enable built-in Adobe Flash in IE and Edge
Function EnableAdobeFlash {
	Write-Output "Enabling built-in Adobe Flash in IE and Edge..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -ErrorAction SilentlyContinue
}

# Uninstall Windows Media Player
Function UninstallMediaPlayer {
	Write-Output "Uninstalling Windows Media Player..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Windows Media Player
Function InstallMediaPlayer {
	Write-Output "Installing Windows Media Player..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Internet Explorer
Function UninstallInternetExplorer {
	Write-Output "Uninstalling Internet Explorer..."
	If ([System.Environment]::OSVersion.Version.Build -ge 22000) {
	} Else {
	Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Install Internet Explorer
Function InstallInternetExplorer {
	Write-Output "Installing Internet Explorer..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
	Write-Output "Uninstalling Work Folders Client..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Work Folders Client - Not applicable to Server
Function InstallWorkFolders {
	Write-Output "Installing Work Folders Client..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Linux Subsystem - Applicable to 1607 or newer
Function InstallLinuxSubsystem {
	Write-Output "Installing Linux Subsystem..."
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		# 1607 needs developer mode to be enabled
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
	}
	Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Linux Subsystem - Applicable to 1607 or newer
Function UninstallLinuxSubsystem {
	Write-Output "Uninstalling Linux Subsystem..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 0
	}
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
	Write-Output "Installing Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	} Else {
		Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall Hyper-V - Not applicable to Home
Function UninstallHyperV {
	Write-Output "Uninstalling Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	} Else {
		Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall Microsoft Print to PDF
Function UninstallPDFPrinter {
	Write-Output "Uninstalling Microsoft Print to PDF..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft Print to PDF
Function InstallPDFPrinter {
	Write-Output "Installing Microsoft Print to PDF..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Microsoft XPS Document Writer
Function UninstallXPSPrinter {
	Write-Output "Uninstalling Microsoft XPS Document Writer..."
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft XPS Document Writer
Function InstallXPSPrinter {
	Write-Output "Installing Microsoft XPS Document Writer..."
	Enable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Remove Default Fax Printer
Function RemoveFaxPrinter {
	Write-Output "Removing Default Fax Printer..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

# Add Default Fax Printer
Function AddFaxPrinter {
	Write-Output "Adding Default Fax Printer..."
	Add-Printer -Name "Fax" -DriverName "Microsoft Shared Fax Driver" -PortName "SHRFAX:" -ErrorAction SilentlyContinue
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

#Forcing Raw Mouse Input
Function RawMouseInput {
    Write-Output "Forcing RAW Mouse Input and Disabling Enhance Pointer Precision..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type String -Value "10"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Type String -Value "0"
}

#Detecting Windows Scale Layout Automatically and applying mouse fix according to it!
Function DetectnApplyMouseFIX {
Add-Type @'
  using System; 
  using System.Runtime.InteropServices;
  using System.Drawing;

  public class DPI {  
    [DllImport("gdi32.dll")]
    static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

    public enum DeviceCap {
      VERTRES = 10,
      DESKTOPVERTRES = 117
    } 

    public static float scaling() {
      Graphics g = Graphics.FromHwnd(IntPtr.Zero);
      IntPtr desktop = g.GetHdc();
      int LogicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.VERTRES);
      int PhysicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.DESKTOPVERTRES);

      return (float)PhysicalScreenHeight / (float)LogicalScreenHeight;
    }
  }
'@ -ReferencedAssemblies 'System.Drawing.dll'

$checkscreenscale = [Math]::round([DPI]::scaling(), 2) * 100
if($checkscreenscale -eq "100") {
Write-Output "Windows screen scale is Detected as 100%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,C0,CC,0C,00,00,00,00,00,80,99,19,00,00,00,00,00,40,66,26,00,00,00,00,00,00,33,33,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "125") {
Write-Output "Windows screen scale is Detected as 125%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,00,00,10,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,30,00,00,00,00,00,00,00,40,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "150") {
Write-Output "Windows screen scale is Detected as 150%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,30,33,13,00,00,00,00,00,60,66,26,00,00,00,00,00,90,99,39,00,00,00,00,00,C0,CC,4C,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "175") {
Write-Output "Windows screen scale is Detected as 175%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,60,66,16,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,20,33,43,00,00,00,00,00,80,99,59,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "200") {
Write-Output "Windows screen scale is Detected as 200%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,90,99,19,00,00,00,00,00,20,33,33,00,00,00,00,00,B0,CC,4C,00,00,00,00,00,40,66,66,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "225") {
Write-Output "Windows screen scale is Detected as 225%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,C0,CC,1C,00,00,00,00,00,80,99,39,00,00,00,00,00,40,66,56,00,00,00,00,00,00,33,73,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "250") {
Write-Output "Windows screen scale is Detected as 250%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,40,00,00,00,00,00,00,00,60,00,00,00,00,00,00,00,80,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "300") {
Write-Output "Windows screen scale is Detected as 300%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,60,66,26,00,00,00,00,00,C0,CC,4C,00,00,00,00,00,20,33,73,00,00,00,00,00,80,99,99,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} elseif($checkscreenscale -eq "350") {
Write-Output "Windows screen scale is Detected as 350%, Applying Mouse Fix for it..."
$YourInputX = "00,00,00,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,80,99,59,00,00,00,00,00,40,66,86,00,00,00,00,00,00,33,B3,00,00,00,00,00"
$YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
$RegPath   = 'HKCU:\Control Panel\Mouse'
$hexifiedX = $YourInputX.Split(',') | % { "0x$_"}
$hexifiedY = $YourInputY.Split(',') | % { "0x$_"}
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
} else {
Write-Output "HOUSTON WE HAVE A PROBLEM! screen scale is not set to traditional value, nothing has been set!"
}
}

### Disable HPET ###
Function DisableHPET {
        Write-Output "Disabling High Precision Event Timer..."
	$errpref = $ErrorActionPreference #save actual preference
        $ErrorActionPreference = "silentlycontinue"
        Invoke-WebRequest -Uri "https://git.io/JkrLn" -OutFile "$Env:windir\system32\SetTimerResolutionService.exe" -ErrorAction SilentlyContinue
        New-Service -name "SetTimerResolutionService" -BinaryPathName "$Env:windir\system32\SetTimerResolutionService.exe" -StartupType Automatic | Out-Null -ErrorAction SilentlyContinue
	bcdedit /deletevalue useplatformclock | Out-Null
        bcdedit /set disabledynamictick yes | Out-Null
        bcdedit /set useplatformtick Yes | Out-Null
	wmic path Win32_PnPEntity where "name='High precision event timer'" call disable | Out-Null
	$ErrorActionPreference = $errpref #restore previous preference
}

#Enable Windows 10 Gaming Mode
Function EnableGameMode {
        Write-Output "Enabling Gaming Mode..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "GamePanelStartupTipIndex" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type DWord -Value 0
}

#Enable Hardware-accelerated GPU scheduling
Function EnableHAGS {
        Write-Output "Enabling HAGS..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
}

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

#Disable Process and Kernel Mitigations
Function DisablePKM {
       Write-Output "Disabling Process and Kernel Mitigations..."
       $errpref = $ErrorActionPreference #save actual preference
       $ErrorActionPreference = "silentlycontinue"
       ForEach($v in (Get-Command -Name "Set-ProcessMitigation").Parameters["Disable"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -Type DWord -Value 0
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -Type DWord -Value 0
       $ErrorActionPreference = $errpref #restore previous preference
}

#Tell Windows to stop tolerating high DPC/ISR latencies.
Function StophighDPC {
       Write-Output "Forcing Windows to stop tolerating high DPC/ISR latencies..."
       $errpref = $ErrorActionPreference #save actual preference
       $ErrorActionPreference = "silentlycontinue"
       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" | Out-Null -ErrorAction SilentlyContinue
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatencyCheckEnabled" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "Latency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceDefault" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceFSVP" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyTolerancePerfOverride" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceScreenOffIR" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceVSyncEnabled" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "RtlCapabilityCheckLatency" -Type DWord -Value 1
       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" | Out-Null -ErrorAction SilentlyContinue
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyActivelyUsed" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleLongTime" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleMonitorOff" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleNoContext" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleShortTime" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleVeryLongTime" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0MonitorOff" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1MonitorOff" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceMemory" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContext" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContextMonitorOff" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceOther" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceTimerPeriod" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceActivelyUsed" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceMonitorOff" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceNoContext" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "Latency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MaxIAverageGraphicsLatencyInOneBucket" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MiracastPerfTrackGraphicsLatency" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorLatencyTolerance" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorRefreshLatencyTolerance" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "TransitionLatency" -Type DWord -Value 1
       $ErrorActionPreference = $errpref #restore previous preference
}

#Decrease mouse and keyboard buffer sizes.
Function DecreaseMKBuffer {
       Write-Output "Decreasing mouse and keyboard buffer sizes..."
       $errpref = $ErrorActionPreference #save actual preference
       $ErrorActionPreference = "silentlycontinue"
       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" | Out-Null -ErrorAction SilentlyContinue
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 0x00000010
       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" | Out-Null -ErrorAction SilentlyContinue
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 0x00000010
       $ErrorActionPreference = $errpref #restore previous preference
}

#Optimizing Network and applying Tweaks for no throttle and maximum speed!
Function NetworkOptimizations {
       Write-Output "Optimizing Network and applying Tweaks for no throttle and maximum speed!..."
       $errpref = $ErrorActionPreference #save actual preference
       $ErrorActionPreference = "silentlycontinue"
       New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -ErrorAction SilentlyContinue | Out-Null
       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -ErrorAction SilentlyContinue | Out-Null
       New-Item -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -ErrorAction SilentlyContinue | Out-Null
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "explorer.exe" -Type DWord -Value 10
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "explorer.exe" -Type DWord -Value 10
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "LocalPriority" -Type DWord -Value 4
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "HostsPriority" -Type DWord -Value 5
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "DnsPriority" -Type DWord -Value 6
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "NetbtPriority" -Type DWord -Value 7
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortlimit" -Type DWord -Value 0
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -Name "Do not use NLA" -Type String -Value "1"
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Size" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 65534
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 30
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 64
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Lsa" -Name "LmCompatibilityLevel" -Type DWord -Value 1
       Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Type DWord -Value 2
       Set-NetTCPSetting -SettingName internet -EcnCapability disabled | Out-Null
       Set-NetOffloadGlobalSetting -Chimney disabled | Out-Null
       Set-NetTCPSetting -SettingName internet -Timestamps disabled | Out-Null
       Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 | Out-Null
       Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled | Out-Null
       Set-NetTCPSetting -SettingName internet -InitialRto 2000 | Out-Null
       Set-NetTCPSetting -SettingName internet -MinRto 300 | Out-Null
       Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal normal | Out-Null
       Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled | Out-Null
       netsh int tcp set supplemental internet congestionprovider=ctcp | Out-Null
       Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing enabled | Out-Null
       Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled | Out-Null
       Disable-NetAdapterLso -Name * | Out-Null
       Disable-NetAdapterChecksumOffload -Name * | Out-Null
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy-Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy Efficient Ethernet" -DisplayValue "Off" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Ultra Low Power Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "System Idle Power Saver" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Green Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Power Saving Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Gigabit Lite" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "EEE" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Advanced EEE" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "ARP Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "NS Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Idle Power Saving" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Flow Control" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Reduce Speed On Power Down" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
       Set-NetAdapterAdvancedProperty -Name * -DisplayName "Interrupt Moderation Rate" -DisplayValue "Off" -ErrorAction SilentlyContinue
       $ErrorActionPreference = $errpref #restore previous preference
       if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2)
{
    $adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Where-Object -FilterScript {$_.AllowComputerToTurnOffDevice -ne "Unsupported"}
    foreach ($adapter in $adapters)
    {
        $adapter.AllowComputerToTurnOffDevice = "Disabled"
        $adapter | Set-NetAdapterPowerManagement
    }
}
       Start-Sleep -s 5
}

#Remove Edit with 3D Paint
Function RemoveEdit3D {
       Write-Output "Removing Edit with Paint 3D from context menu..."
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.3mf\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.bmp\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.fbx\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.gif\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jfif\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jpe\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jpeg\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.jpg\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.png\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.tif\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
       Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\.tiff\Shell\" -Name "3D Edit" -ErrorAction SilentlyContinue
}

#fix issue with games shortcut that created by games lunchers turned white!
Function FixURLext {
    Write-Host "Fixing White Games Shortcuts created by game launchers...."
    choco install -y setuserfta | Out-Null
    Start-Sleep -s 5
    Push-Location
    set-location "$env:ProgramData\chocolatey\lib\setuserfta\tools\SetUserFTA\"
    SetUserFTA.exe del .url | Out-Null
    SetUserFTA.exe .url, InternetShortcut | Out-Null
    Pop-Location
    choco uninstall -y setuserfta | Out-Null
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
