[console]::WindowWidth=90
[console]::WindowHeight=40
[console]::BufferWidth = [console]::WindowWidth
$host.UI.RawUI.WindowTitle = "Remote Tool"
cls
Write-Host '
█▀█  █▀▀  █▀▄▀█  █▀█  ▀█▀  █▀▀       ▀█▀  █▀█  █▀█  █  
█▀▄  ██▄  █ ▀ █  █▄█   █   ██▄        █   █▄█  █▄█  █▄▄
'

Write-Host ''
Write-Host '--------------------------------------------------------'
Write-Host '| Enter A account credentials and asset tag to log in  |'
Write-Host '--------------------------------------------------------'
Write-Host ''
$username = Read-Host "USERNAME"
Write-Host ''
$password = Read-Host "PASSWORD" -AsSecureString
Write-Host ''
$credentials = New-Object System.Management.Automation.PSCredential ($username, $password)
$hostname = Read-Host "ASSET TAG"
Write-Host ''
Write-Host "\\\\\\\Establishing session with $hostname as $username..." -ForegroundColor Black -BackgroundColor Green
$newsession = New-PSSession -ComputerName $hostname -Credential $credentials




function WaitForUserToContinue() {
    Write-Host ''
    Read-Host "Press ENTER to go back to the MENU SCREEN..."
    cls
    Continue
}

function WrongInput() {
Write-Host -ForegroundColor Black -BackgroundColor Red '

__________________________________________________________________________

ERROR: OPTION DOES NOT EXIST - (PLEASE ENTER ONE OF THE AVAILABLE OPTIONS)
__________________________________________________________________________

'
}

function checkIPConfig() {
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|                       IPCONFIG                       |'
    Write-Host '--------------------------------------------------------'
        Invoke-Command -Session $newsession -ScriptBlock {
            ipconfig /all;
        }
    Write-Host ''
}

function pingGoogleDNS() {
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|             Pinging Google DNS Servers               |'
    Write-Host '--------------------------------------------------------'
    Invoke-Command -Session $newsession -ScriptBlock {
        Write-Host '*---------- Pinging 8.8.8.8 ----------*' -ForegroundColor Black -BackgroundColor Yellow
        ping 8.8.8.8;
        Write-Host ''
        Write-Host '*---------- Pinging google.com ----------*' -ForegroundColor Black -BackgroundColor Yellow
        ping google.com;
    }


    Write-Host ''
}

function SpeedTest() {
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|                 Download Speed Test                  |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Downloading...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $Url = "https://link.testfile.org/PDF20MB"
        $Path = "Out-Null"
        $WebClient = New-Object System.Net.WebClient
        $Request = Get-Date;
        $WebClient.DownloadFile($Url, $Path)
        $Speed = "{0:N2}" -f(((Measure-Command {$Request=Get-Date; $WebClient.DownloadFile($Url, $Path)}).TotalSeconds))
        Write-Host ("20MB test file has been downloaded in $Speed seconds") -ForegroundColor Black -BackgroundColor Green
    }
    Write-Host ''
}

function CheckAdmins() {
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|           Members of Administrators group            |'
    Write-Host '--------------------------------------------------------'
    Invoke-Command -Session $newsession -ScriptBlock {
        Get-LocalGroupMember Administrators | ft
    }
    Write-Host ''
}

function GroupPolicyUpdate() {
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|              Updating Group Policy                   |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Processing...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $hidden = "C:\Support\hiddenGPUpdate.vbs"
        $GPUpdateTaskName = "\NEW\Run_gpupdate"

        if (-not (Test-Path $hidden)) {
            Out-File $hidden -Append -Encoding Ascii
            Set-Content $hidden 'CreateObject("Wscript.Shell").Run "C:\Windows\System32\gpupdate.exe /force", 0, True' -Encoding Ascii
        } 
        try {
            $objScheduledTask = Get-ScheduledTask -TaskName $GPUpdateTaskName -ErrorAction Stop
        } catch {
            schtasks /create /tn $GPUpdateTaskName /tr $hidden /SC ONEVENT /RU "BUILTIN\USERS" /EC Application /MO *[System/EventID=777] /f
            schtasks /Run /tn $GPUpdateTaskName
        }
		Write-Host "Group Policy should be updated"  -ForegroundColor Black -BackgroundColor Green	
    }
    Write-Host ''
}

function CheckInstalledSoftware() {
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|                   Installed Software                 |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Collecting data...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $GetAllApps = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty -Name DisplayName -ErrorAction SilentlyContinue | Select * -ExcludeProperty PS*
        foreach ($item in $GetAllApps) {
            $itemSplit = $item -split '='
            $app = $itemSplit[1].TrimEnd('}')
            if ($app -like '*update*') {
                Continue
            }
            else {
                Write-Host "$app" -ForegroundColor Black -BackgroundColor Green
            }
        }
    }
    Write-Host ''
}

function RestartIntune() {
    Write-Host ''
    Write-Host ''
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|                        Intune                        |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Restarting Intune Management Extension Service...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $IsIntuneService = Get-Service IntuneManagementExtension -ErrorAction SilentlyContinue
        if ($IsIntuneService) {
            Restart-Service IntuneManagementExtension -ErrorAction SilentlyContinue
            Write-Host "IntuneManagementExtension service restarted..." -ForegroundColor Black -BackgroundColor Green
        }
        else {
            Write-Host ''
            Write-Host "Machine is not connected to the Intune Service..." -ForegroundColor Black -BackgroundColor Red
        }
    }
    Write-Host ''
}

function ClearSystemCacheFiles() {
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|            Clearing System Cache Files               |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Deleting files...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $ErrorActionPreference = 'silentlycontinue'
        $TempPaths = "C:\Users\*\AppData\Local\Temp", "C:\Windows\Temp", "C:\Windows\Prefetch"
        foreach ($Path in $TempPaths) {
            if (Test-Path $Path) {
                Get-ChildItem -Path $Path *.* -Recurse | Remove-Item -Force -Recurse
                Write-Host "Deleted Files From $Path..." -ForegroundColor Black -BackgroundColor Green
            }
            else {
                Write-Host "$Path not found..." -ForegroundColor Black -BackgroundColor Red
            }
        }
    }
    Write-Host ''
}

function ClearFirefoxCache() {
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|               Clearing Firefox Cache                 |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Processing request...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $IsFirefoxRunning = Get-Process firefox -ErrorAction SilentlyContinue
        if ($IsFirefoxRunning) {
            Write-Host "Can't proceed with the request..." -ForegroundColor Black -BackgroundColor Red
            Write-Host "Firefox is currently running on the remote machine..." -ForegroundColor Black -BackgroundColor Red
        }
        else {
            $counter = 0
            $FirefoxVersions = @("*.default-esr", "*.default-release")
            foreach ($Version in $FirefoxVersions) {
                if (Test-Path C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\$Version\cache2) {
                    Remove-Item C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\$Version\cache2 -Recurse
                    Write-Host "Firefox Cache Cleared..." -ForegroundColor Black -BackgroundColor Green
                    break
                } 
                else {
                    if ($counter -lt 1) {
                        Write-Host "No Firefox Cache to clear..." -ForegroundColor Black -BackgroundColor Green
                        $counter += 1
                    }
                    else {
                        Continue
                    }
                }
            }
        }
    }
    Write-Host ''
}

function ClearGoogleChromeCache() {
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|           Clearing Google Chrome Cache               |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Processing request...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $IsChromeRunning = Get-Process chrome -ErrorAction SilentlyContinue
        if ($IsChromeRunning) {
            Write-Host "Can't proceed with the request..." -ForegroundColor Black -BackgroundColor Red
            Write-Host "Google Chrome is currently running on the remote machine..." -ForegroundColor Black -BackgroundColor Red
        }
        else {
            $ChromeCache = "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cache"
            if (Test-Path $ChromeCache) {
                Remove-Item $ChromeCache -Recurse -Force
                Write-Host "Google Chrome Cache Cleared..." -ForegroundColor Black -BackgroundColor Green
            } 
            else {
                Write-Host "No Google Chrome Cache to clear..." -ForegroundColor Black -BackgroundColor Green
            }
        }
    }
    Write-Host ''
}

function ClearTeamsCache() {
	Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|                      Teams Cache                     |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Processing request...' -ForegroundColor Black -BackgroundColor Yellow
	Invoke-Command -Session $newsession -ScriptBlock {
		$ConfirmPreference = 'None'
		Get-Process Teams -ErrorAction SilentlyContinue | Stop-Process
		$teamsCacheFolders = @("blob_storage", "Cache", "databases", "GPUCache", "IndexedDB", "Local Storage", "tmp")
		foreach ($teamsCacheFolder in $teamsCacheFolders) {
			Write-Host "Clearing temporary files from $teamsCacheFolder folder..." -ForegroundColor Gray
			Get-ChildItem -Path C:\Users\*\AppData\Roaming\Microsoft\$teamsCacheFolder  *.* -Recurse | Remove-Item -Force -Recurse
		}
		Write-Host "TEAMS CACHE HAS BEEN CLEARED." -ForegroundColor Black -BackgroundColor Green
	}
}

function EnableOneDrive() {
	Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|                      One Drive                       |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Processing request...' -ForegroundColor Black -BackgroundColor Yellow
	Invoke-Command -session $newsession -ScriptBlock {
		$regKey = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -ErrorAction SilentlyContinue
		if ($regKey.DisableFileSyncNGSC -eq 0) {
			Write-Host "One Drive should be already enabled." -ForegroundColor Black -BackgroundColor Green
		}
		else {
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 0 /f | Out-Null
			Write-Host "One Drive should be now enabled." -ForegroundColor Black -BackgroundColor Green
		}
	}
}

function EnableHighPerformancePowerPlan() {
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|             High Performance Power Plan              |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Processing request...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        $GetPowerPlan = powercfg /GetActiveScheme 2>$null
        if (-Not ($GetPowerPlan -eq "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)")) {
            powercfg /s SCHEME_MIN
            Write-Host "High Performance Mode enabled..." -ForegroundColor Black -BackgroundColor Green
        }
        else {
            Write-Host "High Performance Mode was already enabled..." -ForegroundColor Black -BackgroundColor Green
        }
    }
}

function AdjustVisualSettingsForBestPerformance() {
    Write-Host ''
    Write-Host '--------------------------------------------------------'
    Write-Host '|    Adjusting Visual Settings for best performance    |'
    Write-Host '--------------------------------------------------------'
    Write-Host 'Processing request...' -ForegroundColor Black -BackgroundColor Yellow
    Invoke-Command -Session $newsession -ScriptBlock {
        # Saves HKEY_USERS under HKU:
        if (-Not (Test-Path 'HKU:')) {
            Write-Host "Saving HKEY_USERS Under HKU: Path..."
            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
        }
        # Loop designed to loop through each user in HKEY_USERS and do specified things below #
        $VisualEffectsArray = "AnimateMinMax", "ComboBoxAnimation", "ControlAnimations", "CursorShadow", "ListBoxSmoothScrolling", "ListviewAlphaSelect", "ListviewShadow", "MenuAnimation", "TaskbarAnimations", "DWMAeroPeekEnabled", "DWMEnabled", "DWMSaveThumbnailEnabled", "Themes", "TooltipAnimation"
        $userProfiles = Get-ChildItem -Path "Registry::HKEY_USERS"
        foreach ($profile in $userProfiles) {
            $profileSID = $profile.PSChildName

            Write-Host "Enabling Custom Performance Settings for HKEY_USERS\$profileSID" -ForegroundColor Gray
            reg add "HKEY_USERS\$profileSID\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 3 /f | Out-Null
            
            Write-Host "Customizing Prefrence Mask Settings for HKEY_USERS\$profileSID" -ForegroundColor Gray
            reg add "HKEY_USERS\$profileSID\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012078010000000 /f | Out-Null

            # System Properties --> Advanced --> Performance Settings --> Custom Settings for best performance and look #
            foreach ($Option in $VisualEffectsArray) {
                Write-Host "Disabling $Option for $profileSID" -ForegroundColor Gray
                reg add "HKEY_USERS\$profileSID\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\$Option" /v DefaultApplied /t REG_DWORD /d 0 /f | Out-Null
            }
        }
        Write-Host ""
        Write-Host "VISUAL SETTINGS HAVE BEEN ADJUSTED FOR THE BEST PERFORMANCE." -ForegroundColor Black -BackgroundColor Green
    }
}



$IsLive = $true
cls
while ($IsLive) {
    if ($newsession.State -eq 'Opened') {
        Write-Host "█▀█  █▀▀  █▀▄▀█  █▀█  ▀█▀  █▀▀       ▀█▀  █▀█  █▀█  █  "
        Write-Host "█▀▄  ██▄  █ ▀ █  █▄█   █   ██▄        █   █▄█  █▄█  █▄▄"
        Write-Host "_____________________________________________________________________________________"
        Write-Host "Logged in as:  $username          . .  .  .  .  .  .  .  .  .  .  .  .  .            "
        Write-Host "Connected to:  $hostname          . .  .  .  .  .  .  .  .  .  .  .  .  .            "
        Write-Host "------------------------------------------|------------------------------------------"
        Write-Host "|          ___________________            |          ___________________            |"
        Write-Host "|          \      PAGE 1     /            |          \      PAGE 2     /            |"
        Write-Host "|          /_________________\            |          /_________________\            |"
        Write-Host "|                                         |                                         |"
        Write-Host "|  [0] - EXIT                             |  [8] - CLEAR SYSTEM CACHE               |"
        Write-Host "|  [1] - IPCONFIG                         |  [9] - CLEAR FIREFOX CACHE              |"
        Write-Host "|  [2] - PING GOOGLE DNS                  |  [10] - CLEAR GOOGLE CHROME CACHE       |"
        Write-Host "|  [3] - DOWNLOAD TEST FILE (Speed Test)  |  [11] - CLEAR TEAMS CACHE (CLOSES TEAMS)|"
        Write-Host "|  [4] - CHECK WHO IS ADMIN               |  [12] - ENABLE ONEDRIVE                 |"
        Write-Host "|  [5] - GPUPDATE                         |  [13] - ENABLE HIGH PERFORMANCE MODE    |"
        Write-Host "|  [6] - CHECK INSTALLED APPLICATIONS     |  [14] - CHANGE VISUAL SETTINGS          |"
        Write-Host "|  [7] - RESTART INTUNE SERVICE           |         FOR THE BEST PERFORMANCE        |"
        Write-Host "------------------------------------------|------------------------------------------"
        Write-Host ".  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  ."
        Write-Host ".  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  ."
        Write-Host ".  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  ."
        Write-Host "_____________________________________________________________________________________"


        $Option = Read-Host "SELECT OPTION"

        if ($Option -eq '1') {
            checkIPConfig
            WaitForUserToContinue
        }
        elseif ($Option -eq '2') {
            pingGoogleDNS
            WaitForUserToContinue
        }
        elseif ($Option -eq '3') {
            SpeedTest
            WaitForUserToContinue
        }
        elseif ($Option -eq '4') {
            CheckAdmins
            WaitForUserToContinue
        }
        elseif ($Option -eq '5') {
            GroupPolicyUpdate
            WaitForUserToContinue
        }
        elseif ($Option -eq '6') {
            CheckInstalledSoftware
            WaitForUserToContinue
        }
        elseif ($Option -eq '7') {
            RestartIntune
            WaitForUserToContinue
        }
        elseif ($Option -eq '8') {
            ClearSystemCacheFiles
            WaitForUserToContinue
        }
        elseif ($Option -eq '9') {
            ClearFirefoxCache
            WaitForUserToContinue
        }
        elseif ($Option -eq '10') {
            ClearGoogleChromeCache
            WaitForUserToContinue
        }
		elseif ($Option -eq '11') {
			ClearTeamsCache
			WaitForUserToContinue
		}
        elseif ($Option -eq '12') {
            EnableOneDrive
            WaitForUserToContinue
        }
        elseif ($Option -eq '13') {
            EnableHighPerformancePowerPlan
            WaitForUserToContinue
        }
        elseif ($Option -eq '14') {
            AdjustVisualSettingsForBestPerformance
            WaitForUserToContinue
        }
        elseif ($Option -eq '0') {
            $IsLive = $false
            Write-Host 'Exiting the Remote Tool...'
            Remove-PSSession $newsession
            Read-Host "Press ENTER key to exit"
        }
        else {
            WrongInput
            WaitForUserToContinue
        }
    }
    else {
        Write-Host "█▀█  █▀▀  █▀▄▀█  █▀█  ▀█▀  █▀▀       ▀█▀  █▀█  █▀█  █  "
        Write-Host "█▀▄  ██▄  █ ▀ █  █▄█   █   ██▄        █   █▄█  █▄█  █▄▄"
        Write-Host "_______________________________________________________________________________"
        Write-Host "                        CONNECTION WAS NOT SUCCESSFUL                          "   
        Write-Host "-------------------------------------------------------------------------------"
        Write-Host "|                       _______________________________                       |"
        Write-Host "|                       \           OPTIONS           /                       |"
        Write-Host "|                       /_____________________________\                       |"
        Write-Host "|                                                                             |"
        Write-Host "|                                  [0] - Exit                                 |"
        Write-Host "-------------------------------------------------------------------------------"
        Write-Host ".  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  ."
        Write-Host "_______________________________________________________________________________"
        $Option = Read-Host "SELECT OPTION"
        if ($Option -eq '0') {
            $IsLive = $false
            Write-Host 'Exiting the Remote Tool...'
            Read-Host "Press ENTER key to exit"
        }
        else {
            WrongInput
            WaitForUserToContinue
        }
    }
}
