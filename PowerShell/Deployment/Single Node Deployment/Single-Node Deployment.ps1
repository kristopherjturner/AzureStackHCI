<#
Name: Single-Node Deployment.ps1
Author: Kristopher J Turner
Contact:  kristopher.turner@tierpoint.com
Version: 1.0

Credits: A majority of the script was taken from Dell's HCI Deployment Guide.  I have modified it to work with TierPoint's environment.
.DESCRIPTION
This script will deploy Azure Stack HCI cluster on a single-node cluster using Network ATC.
.NOTES
Do not run this script as is.  It is better to copy and paste the sections you need into PowerShell. I will be working on getting it to a point where we can run it as a script.
#>

#region Variables
#Please fill in variable with node name: example: $ClusterNode = "AzSHCI1"
$ClusterNode = "AzSHCI1"

#New Cluster Name
$ClusterName = "AzSHCI-Cluster"

#Cluster IP
$ClusterIP = "" #If blank (you can write just $ClusterIP="", DHCP will be used). If $DistributedManagementPoint is true, then IP is not used

#Distributed Cluster ManagementPoint? (Cluster Name in DNS will have IP of every node - like SOFS). If $ClusterIP is set, then $clusterIP will be ignored).
$DistributedManagementPoint = $True

#Enable Kernel Soft Reboot? https://learn.microsoft.com/en-us/azure-stack/hci/manage/kernel-soft-reboot
$KSR = $False

#Deploy network using Network ATC? https://learn.microsoft.com/en-us/azure-stack/hci/manage/manage-network-atc?tabs=22H2
$NetATC = $True

#Perform Windows update? (for more info visit WU Scenario https://github.com/microsoft/WSLab/tree/dev/Scenarios/Windows%20Update)
$WindowsUpdate = "Recommended" #Can be "All","Recommended" or "None"

#Dell updates
$DellUpdates = $False

#Delete Storage Pool (like after reinstall there might be data left from old cluster)
$DeletePool = $True

#iDRAC settings
#$iDRACCredentials=Get-Credential #grab iDRAC credentials
$iDracUsername = "LabAdmin"
$iDracPassword = "LS1setup!"
$SecureStringPassword = ConvertTo-SecureString $iDracPassword -AsPlainText -Force
$iDRACCredentials = New-Object System.Management.Automation.PSCredential ($iDracUsername, $SecureStringPassword)

#IP = Idrac IP Address, USBNICIP = IP Address of  that will be configured in OS to iDRAC Pass-through USB interface
$iDRACs = @()
$iDRACs += @{IP = "192.168.100.130" ; USBNICIP = "169.254.11.1" }
$iDRACs += @{IP = "192.168.100.131" ; USBNICIP = "169.254.11.3" }
$iDRACs += @{IP = "192.168.100.139" ; USBNICIP = "169.254.11.5" }
$iDRACs += @{IP = "192.168.100.140" ; USBNICIP = "169.254.11.7" }

#endregion Variables

#region validate servers connectivity with Azure Stack HCI Environment Checker https://www.powershellgallery.com/packages/AzStackHci.EnvironmentChecker
Install-PackageProvider -Name NuGet -Force
Install-Module -Name AzStackHci.EnvironmentChecker -Force -AllowClobber

$PSSessions = New-PSSession $ClusterNode
Invoke-AzStackHciConnectivityValidation -PsSession $PSSessions
#endregion

#region Update all servers (2022 and 21H2+ systems, for more info visit WU Scenario https://github.com/microsoft/MSLab/tree/dev/Scenarios/Windows%20Update)
#check OS Build Number
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
$ComputersInfo = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    Get-ItemProperty -Path $using:RegistryPath
}
$ComputersInfo | Select-Object PSComputerName, CurrentBuildNumber, UBR

#Update servers
if ($WindowsUpdate -eq "Recommended") {
    #Create virtual account to be able to run command without credssp
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore
    #sleep a bit
    Start-Sleep 2
    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $ClusterNode -ConfigurationName 'VirtualAccount' {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
        if ($SearchResult.Count -gt 0) {
            $Session = New-Object -ComObject Microsoft.Update.Session
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $SearchResult
            $Downloader.Download()
            $Installer = New-Object -ComObject Microsoft.Update.Installer
            $Installer.Updates = $SearchResult
            $Result = $Installer.Install()
            $Result
        }
    }
    #remove temporary PSsession config
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
    }
}
elseif ($WindowsUpdate -eq "All") {
    # Update servers with all updates (including preview)
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore
    #sleep a bit
    Start-Sleep 2
    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $ClusterNode -ConfigurationName 'VirtualAccount' {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
        if ($SearchResult.Count -gt 0) {
            $Session = New-Object -ComObject Microsoft.Update.Session
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $SearchResult
            $Downloader.Download()
            $Installer = New-Object -ComObject Microsoft.Update.Installer
            $Installer.Updates = $SearchResult
            $Result = $Installer.Install()
            $Result
        }
    }
    #remove temporary PSsession config
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
    }
}
#endregion

#region install required features
#install features for management (assuming you are running these commands on Windows Server with GUI)
Install-WindowsFeature -Name RSAT-Clustering, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, RSAT-Hyper-V-Tools, RSAT-Feature-Tools-BitLocker-BdeAducExt, RSAT-Storage-Replica

#install roles and features on servers
#install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    $Result = Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if ($result.ExitCode -eq "failed") {
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    }
}
#define and install other features
$features = "Failover-Clustering", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "NetworkATC", "NetworkHUD", "Data-Center-Bridging", "RSAT-DataCenterBridging-LLDP-Tools", "FS-SMBBW", "System-Insights", "RSAT-System-Insights"
#optional - affects perf even if not enabled on volumes as filter driver is attached (SR,Dedup) and also Bitlocker, that affects a little bit
#$features+="Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","BitLocker","RSAT-Feature-Tools-BitLocker"
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Install-WindowsFeature -Name $using:features }

# Restart and wait for computers
Restart-Computer $ClusterNode -Protocol WSMan -Wait -For PowerShell -Force
Start-Sleep 20 # Allow time for reboots to complete fully
Foreach ($Server in $ClusterNode) {
    do { $Test = Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM }while ($test.TcpTestSucceeded -eq $False)
}
#endregion

#region configure OS settings
#Configure Active memory dump https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
}

#Configure high performance power plan
#set high performance if not VM
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -ne "Virtual Machine") {
        powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    }
}
#check settings
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { powercfg /list }

#Delete Storage Pool if there is any from last install
if ($DeletePool) {
    #Grab pools
    $StoragePools = Get-StoragePool -CimSession $ClusterNode -IsPrimordial $False -ErrorAction Ignore
    #remove pools if any
    if ($StoragePools) {
        $StoragePools | Remove-StoragePool -Confirm:0
    }
    #Reset disks (to clear spaces metadata)
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Get-PhysicalDisk -CanPool $True | Reset-PhysicalDisk
    }
}

#Configure max evenlope size to be 8kb to be able to copy files using PSSession (useful for dell drivers update region and Windows Admin Center)
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192 }

#Configure MaxTimeout (10s for Dell hardware - especially if you have HDDs, 30s for Virtual environment https://learn.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-direct-in-vm)
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell Inc.") {
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710 }
}
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Model -eq "Virtual Machine") {
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530 }
}

#Rename Network Adapters
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -eq "Virtual Machine") {
        Rename-NetAdapter -Name "Ethernet" -NewName "MGT01"
        Rename-NetAdapter -Name "Ethernet 2" -NewName "MGT02"
        Rename-NetAdapter -Name "Ethernet 3" -NewName "SMB01"
        Rename-NetAdapter -Name "Ethernet 4" -NewName "SMB02"
    }
}

#Verify Network Adapters
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    Get-NetAdapter
}

#endregion

#region configure OS Security (tbd: https://aka.ms/hci-securitybase)
#Enable secured core
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    #Device Guard
    #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 1 /f 
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
    #there s different setting for VM and Bare metal
    if ((Get-CimInstance -ClassName win32_computersystem).Model -eq "Virtual Machine") {
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f
    }
    else {
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 3 /f
    }
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d 1 /f

    #Cred Guard
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

    #System Guard Secure Launch (bare meta only)
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/system-guard-secure-launch-and-smm-protection
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" /v "Enabled" /t REG_DWORD /d 1 /f

    #HVCI
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f
    #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 1 /f
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "HVCIMATRequired" /t REG_DWORD /d 1 /f
}
#endregion

#region install Dell drivers https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20and%20Dell%20Servers%20Update
if ($DellUpdates -and ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell Inc.")) {
    $DSUDownloadFolder = "$env:USERPROFILE\Downloads\DSU"
    $DSUPackageDownloadFolder = "$env:USERPROFILE\Downloads\DSUPackage"
    #region prepare DSU binaries
    #Download DSU
    #https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1

    #grab DSU links from Dell website
    $URL = "https://dl.dell.com/omimswac/dsu/"
    $Results = Invoke-WebRequest $URL -UseDefaultCredentials
    $Links = $results.Links.href | Select-Object -Skip 1
    #create PSObject from results
    $DSUs = @()
    foreach ($Link in $Links) {
        $DSUs += [PSCustomObject]@{
            Link    = "https://dl.dell.com$Link"
            Version = $link -split "_" | Select-Object -Last 2 | Select-Object -First 1
        }
    }
    #download latest to separate folder
    $LatestDSU = $DSUs | Sort-Object Version | Select-Object -Last 1
    if (-not (Test-Path $DSUDownloadFolder -ErrorAction Ignore)) { New-Item -Path $DSUDownloadFolder -ItemType Directory }
    Start-BitsTransfer -Source $LatestDSU.Link -Destination $DSUDownloadFolder\DSU.exe

    #upload DSU to servers
    $Sessions = New-PSSession -ComputerName $ClusterNode
    Invoke-Command -Session $Sessions -ScriptBlock {
        if (-not (Test-Path $using:DSUDownloadFolder -ErrorAction Ignore)) { New-Item -Path $using:DSUDownloadFolder -ItemType Directory }
    }
    foreach ($Session in $Sessions) {
        Copy-Item -Path "$DSUDownloadFolder\DSU.exe" -Destination "$DSUDownloadFolder" -ToSession $Session -Force -Recurse
    }
    $Sessions | Remove-PSSession
    #install DSU
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Start-Process -FilePath "$using:DSUDownloadFolder\DSU.exe" -ArgumentList "/silent" -Wait 
    }

    #download catalog and copy DSU Package to servers
    #Dell Azure Stack HCI driver catalog https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz
    #Download catalog
    Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
    #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
    if (-not (Test-Path $DSUPackageDownloadFolder -ErrorAction Ignore)) { New-Item -Path $DSUPackageDownloadFolder -ItemType Directory }
    Function Expand-GZipArchive {
        Param(
            $infile,
            $outfile = ($infile -replace '\.gz$', '')
        )
        $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
        $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
        $buffer = New-Object byte[](1024)
        while ($true) {
            $read = $gzipstream.Read($buffer, 0, 1024)
            if ($read -le 0) { break }
            $output.Write($buffer, 0, $read)
        }
        $gzipStream.Close()
        $output.Close()
        $input.Close()
    }
    Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$DSUPackageDownloadFolder\ASHCI-Catalog.xml"
    #create answerfile for DU
    $content = '@
                a
                c
                @'
    Set-Content -Path "$DSUPackageDownloadFolder\answer.txt" -Value $content -NoNewline
    $content = '"C:\Program Files\Dell\DELL System Update\DSU.exe" --catalog-location=ASHCI-Catalog.xml --apply-upgrades <answer.txt'
    Set-Content -Path "$DSUPackageDownloadFolder\install.cmd" -Value $content -NoNewline

    #upload DSU package to servers
    $Sessions = New-PSSession -ComputerName $ClusterNode
    foreach ($Session in $Sessions) {
        Copy-Item -Path $DSUPackageDownloadFolder -Destination $DSUPackageDownloadFolder -ToSession $Session -Recurse -Force
    }
    $Sessions | Remove-PSSession

    #endregion

    #region check if there are any updates needed
    $ScanResult = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        & "C:\Program Files\Dell\DELL System Update\DSU.exe" --catalog-location="$using:DSUPackageDownloadFolder\ASHCI-Catalog.xml" --preview | Out-Null
        $Result = (Get-content "C:\ProgramData\Dell\DELL System Update\dell_dup\DSU_STATUS.json" | ConvertFrom-JSon).systemupdatestatus.invokerinfo.statusmessage
        if ($Result -like "No Applicable Update*" ) {
            $DellUpdateRequired = $False
        }
        else {
            $DellUpdateRequired = $true
        }

        #scan for microsoft updates
        $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                IsPresent=1 and DeploymentAction='Uninstallation' or
                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
        if ($SearchResult.Count -gt 0) {
            $MicrosoftUpdateRequired = $True
        }
        else {
            $MicrosoftUpdateRequired = $False
        }

        #grab windows version
        $ComputersInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'

        $Output = @()
        $Output += [PSCustomObject]@{
            "DellUpdateRequired"      = $DellUpdateRequired
            "MicrosoftUpdateRequired" = $MicrosoftUpdateRequired
            "MicrosoftUpdates"        = $SearchResult
            "ComputerName"            = $env:COMPUTERNAME
            "CurrentBuildNumber"      = $ComputersInfo.CurrentBuildNumber
            "UBR"                     = $ComputersInfo.UBR
        }
        return $Output
    }
    $ScanResult
    #endregion

    #region Install Dell updates https://dl.dell.com/content/manual36290092-dell-emc-system-update-version-1-9-3-0-user-s-guide.pdf?language=en-us&ps=true
    foreach ($Server in $ClusterNode) {
        #Install Dell updates https://dl.dell.com/content/manual36290092-dell-emc-system-update-version-1-9-3-0-user-s-guide.pdf?language=en-us&ps=true
        if (($ScanResult | Where-Object ComputerName -eq $Server).DellUpdateRequired) {
            Write-Output "$($Server): Installing Dell System Updates"
            Invoke-Command -ComputerName $Server -ScriptBlock {
                #install DSU updates
                Start-Process -FilePath "install.cmd" -Wait -WorkingDirectory $using:DSUPackageDownloadFolder
                #display result
                $json = Get-Content "C:\ProgramData\Dell\DELL System Update\dell_dup\DSU_STATUS.json" | ConvertFrom-Json
                $output = $json.SystemUpdateStatus.updateablecomponent | Select-Object Name, Version, Baselineversion, UpdateStatus, RebootRequired
                Return $output
            }
        }
        else {
            Write-Output "$($Server): Dell System Updates not required"
        }
    }
    #endregion
}
#endregion

#region restart servers to apply
Restart-Computer $ClusterNode -Protocol WSMan -Wait -For PowerShell -Force
Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
#make sure computers are restarted
Foreach ($Server in $ClusterNode) {
    do { $Test = Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM }while ($test.TcpTestSucceeded -eq $False)
}
#endregion

#region Create cluster
#Create Cluster
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell*") {
    #Disable USB NIC used by iDRAC to communicate to host just for test-cluster
    Disable-NetAdapter -CimSession $ClusterNode -InterfaceDescription "Remote NDIS Compatible Device" -Confirm:0
}
#Test-Cluster -Node $ClusterNode -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
If ($DistributedManagementPoint) {
    New-Cluster -Name $ClusterName -Node $ClusterNode -ManagementPointNetworkType "Distributed"
}
else {
    if ($ClusterIP) {
        New-Cluster -Name $ClusterName -Node $ClusterNode -StaticAddress $ClusterIP
    }
    else {
        New-Cluster -Name $ClusterName -Node $ClusterNode
    }
}
Start-Sleep 5
Clear-DnsClientCache
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell Inc.") {
    #Enable USB NIC used by iDRAC
    Enable-NetAdapter -CimSession $ClusterNode -InterfaceDescription "Remote NDIS Compatible Device"
}

Start-Sleep 5
Clear-DnsClientCache

#Configure CSV Cache (value is in MB) - disable if SCM or VM is used. For VM it's just for labs - to save some RAM.
if (Get-PhysicalDisk -cimsession $ClusterNode | Where-Object bustype -eq SCM) {
    #disable CSV cache if SCM storage is used
        (Get-Cluster $ClusterName).BlockCacheSize = 0
}
elseif ((Invoke-Command -ComputerName $ClusterNode -ScriptBlock { (get-wmiobject win32_computersystem).Model }) -eq "Virtual Machine") {
    #disable CSV cache for virtual environments
        (Get-Cluster $ClusterName).BlockCacheSize = 0

#endregion

#region Configure networking with NetATC https://techcommunity.microsoft.com/t5/networking-blog/network-atc-what-s-coming-in-azure-stack-hci-22h2/ba-p/3598442
if ($NetATC) {
    #make sure NetATC,FS-SMBBW and other required features are installed on servers
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Install-WindowsFeature -Name NetworkATC, Data-Center-Bridging, RSAT-Clustering-PowerShell, RSAT-Hyper-V-Tools, FS-SMBBW
    }

    #since ATC is not available on management machine, copy PowerShell module over to management machine from cluster. However global intents will not be automatically added as in C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetworkATC\NetWorkATC.psm1 is being checked if NetATC feature is installed [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled()
    $session = New-PSSession -ComputerName $ClusterNode
    $items = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetworkATC", "C:\Windows\System32\NetworkAtc.Driver.dll", "C:\Windows\System32\Newtonsoft.Json.dll", "C:\Windows\System32\NetworkAtcFeatureStaging.dll"
    foreach ($item in $items) {
        Copy-Item -FromSession $session -Path $item -Destination $item -Recurse -Force
    }

    #if virtual environment, then skip RDMA config
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Model -eq "Virtual Machine") {
        Import-Module NetworkATC
        #virtual environment (skipping RDMA config)
        $AdapterOverride = New-NetIntentAdapterPropertyOverrides
        $AdapterOverride.NetworkDirect = 0
        Add-NetIntent -ClusterName $ClusterName -Name ConvergedIntent -Management -Compute -AdapterName "MGT01", "MGT02" -AdapterPropertyOverrides $AdapterOverride -Verbose #-StorageVlans 1,2
    }
    else {
        #on real hardware you can configure RDMA
        #grab fastest adapters names (assuming that we are deploying converged intent with just Mellanox or Intel E810)
        $FastestLinkSpeed = (get-netadapter -CimSession $ClusterNode | Where-Object { $_.Status -eq "up" -and $_.HardwareInterface -eq $True }).Speed | Sort-Object -Descending | Select-Object -First 1
        #grab adapters
        $AdapterNames = (Get-NetAdapter -CimSession $ClusterNode | Where-Object { $_.Status -eq "up" -and $_.HardwareInterface -eq $True } | where-object Speed -eq $FastestLinkSpeed | Sort-Object Name).Name
        #$AdapterNames="SLOT 3 Port 1","SLOT 3 Port 2"
        Import-Module NetworkATC
        Add-NetIntent -ClusterName $ClusterName -Name ConvergedIntent -Management -Compute -Storage -AdapterName $AdapterNames -Verbose #
    }

    #Add default global intent
    #since when configuring from Management machine there is a test [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled() to make global intents available, it will not be configured, so it has to be configured manually with invoke command
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Import-Module NetworkATC
        $overrides = New-NetIntentGlobalClusterOverrides
        #add empty intent
        Add-NetIntent -GlobalClusterOverrides $overrides
    }

    #check
    Start-Sleep 20 #let intent propagate a bit
    Write-Output "applying intent"
    do {
        $status = Invoke-Command -ComputerName $ClusterName -ScriptBlock { Get-NetIntentStatus }
        Write-Host "." -NoNewline
        Start-Sleep 5
    } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

    #remove if necessary
    <#
            Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
                $intents = Get-NetIntent
                foreach ($intent in $intents){
                    Remove-NetIntent -Name $intent.IntentName
                }
            }
            #>

    #if deploying in VMs, some nodes might fail (quarantined state) and even CNO can go to offline ... go to cluadmin and fix
    #Get-ClusterNode -Cluster $ClusterName | Where-Object State -eq down | Start-ClusterNode -ClearQuarantine
}
#endregion

#region install network HUD (NetATC)
if ($NetATC) {
    #make sure NetworkHUD features are installed and network HUD is started on servers
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Install-WindowsFeature -Name "NetworkHUD", "Hyper-V", "Hyper-V-PowerShell", "Data-Center-Bridging", "RSAT-DataCenterBridging-LLDP-Tools", "NetworkATC", "Failover-Clustering"
        #make sure service is started and running (it is)
        #Set-Service -Name NetworkHUD -StartupType Automatic 
        #Start-Service -Name NetworkHUD
    }
    #install Network HUD modules (Test-NetStack and az.stackhci.networkhud) on nodes
    $Modules = "Test-NetStack", "az.stackhci.networkhud"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    foreach ($Module in $Modules) {
        #download module to management node
        Save-Module -Name $Module -Path $env:Userprofile\downloads\
        #copy it to servers
        foreach ($Server in $ClusterNode) {
            Copy-Item -Path "$env:Userprofile\downloads\$module" -Destination "\\$Server\C$\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
        }
    }
    #restart NetworkHUD service to activate
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Restart-Service NetworkHUD
    }
    #wait a bit
    Start-Sleep 10

    #check event logs
    $events = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Get-WinEvent -FilterHashtable @{"ProviderName" = "Microsoft-Windows-Networking-NetworkHUD"; Id = 105 }
    }
    $events | Format-Table -AutoSize
}
#endregion

#region configure what was/was not configured with NetATC
if ($NetATC) {
    #region Configure what NetATC is not configuring
    #disable unused adapters
    Get-Netadapter -CimSession $ClusterNode | Where-Object Status -ne "Up" | Disable-NetAdapter -Confirm:0

    #Rename and Configure USB NICs (iDRAC Network)
    $USBNics = get-netadapter -CimSession $ClusterNode -InterfaceDescription "Remote NDIS Compatible Device" -ErrorAction Ignore
    if ($USBNics) {
        $Network = (Get-ClusterNetworkInterface -Cluster $ClusterName | Where-Object Adapter -eq "Remote NDIS Compatible Device").Network | Select-Object -Unique
        $Network.Name = "iDRAC"
        $Network.Role = "none"
    }

    #Configure dcbxmode to be host in charge (default is firmware in charge) on mellanox adapters (Dell recommendation)
    #Caution: This disconnects adapters!
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell Inc.") {
        if (Get-NetAdapter -CimSession $ClusterNode -InterfaceDescription Mellanox*) {
            Set-NetAdapterAdvancedProperty -CimSession $ClusterNode -InterfaceDescription Mellanox* -DisplayName 'Dcbxmode' -DisplayValue 'Host in charge'
        }
    }
    #configure larger receive buffers on Mellanox adapters
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell Inc.") {
        if (Get-NetAdapter -CimSession $ClusterNode -InterfaceDescription Mellanox*) {
            Set-NetAdapterAdvancedProperty -CimSession $ClusterNode -InterfaceDescription Mellanox* -DisplayName 'Receive buffers' -DisplayValue '4096'
        }
    }

    #endregion

    #region Check settings before applying NetATC
    #Check what networks were excluded from Live Migration
    $Networks = (Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Get-ClusterParameter -Name MigrationExcludeNetworks).Value -split ";"
    foreach ($Network in $Networks) { Get-ClusterNetwork -Cluster $ClusterName | Where-Object ID -Match $Network }

    #check Live Migration option (probably bug, because it should default to SMB - version tested 1366)
    Get-VMHost -CimSession $ClusterNode | Select-Object *Migration*

    #Check smbbandwith limit cluster settings (notice for some reason is SetSMBBandwidthLimit=1)
    Get-Cluster -Name $ClusterName | Select-Object *SMB*

    #check SMBBandwidthLimit settings (should be pouplated already with defaults on physical cluster - it calculated 1562500000 bytes per second on 2x25Gbps NICs)
    Get-SmbBandwidthLimit -CimSession $ClusterNode

    #check VLAN settings (notice it's using Adapter Isolation, not VLAN)
    Get-VMNetworkAdapterIsolation -CimSession $ClusterNode -ManagementOS

    #check number of live migrations (default is 1)
    get-vmhost -CimSession $ClusterNode | Select-Object Name, MaximumVirtualMachineMigrations
    #endregion

    #region Adjust NetATC global overrides (assuming there is one vSwitch)
    $vSwitchNics = (Get-VMSwitch -CimSession $ClusterNode).NetAdapterInterfaceDescriptions
    $LinkCapacityInGbps = (Get-NetAdapter -CimSession $ClusterNode -InterfaceDescription $vSwitchNics | Measure-Object Speed -Sum).sum / 1000000000
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Import-Module NetworkATC
        $overrides = New-NetIntentGlobalClusterOverrides
        $overrides.MaximumVirtualMachineMigrations = 4
        $overrides.MaximumSMBMigrationBandwidthInGbps = $using:LinkCapacityInGbps * 0.4 #40%, if one switch is down, LM will not saturate bandwidth
        $overrides.VirtualMachineMigrationPerformanceOption = "SMB"
        Set-NetIntent -GlobalClusterOverrides $overrides
    }

    Start-Sleep 20 #let intent propagate a bit
    Write-Output "applying overrides intent"
    do {
        $status = Invoke-Command -ComputerName $ClusterName -ScriptBlock { Get-NetIntentStatus -Globaloverrides }
        Write-Host "." -NoNewline
        Start-Sleep 5
    } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")
    #endregion

    #region verify settings again
    #Check Cluster Global overrides
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Import-Module NetworkATC
        $GlobalOverrides = Get-Netintent -GlobalOverrides
        $GlobalOverrides.ClusterOverride
    }

    #check Live Migration option
    Get-VMHost -CimSession $ClusterNode | Select-Object *Migration*

    #Check LiveMigrationPerf option and Limit (SetSMBBandwidthLimit was 1, now is 0)
    Get-Cluster -Name $ClusterName | Select-Object *SMB*

    #check SMBBandwidthLimit settings
    Get-SmbBandwidthLimit -CimSession $ClusterNode

    #check number of live migrations
    get-vmhost -CimSession $ClusterNode | Select-Object Name, MaximumVirtualMachineMigrations

    #check it in cluster (is only 1 - expected)
    get-cluster -Name $ClusterName | Select-Object Name, MaximumParallelMigrations

    #endregion

    #remove net intent global overrides if necessary
    <#
        Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
            Import-Module NetworkATC
            Remove-NetIntent -GlobalOverrides
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides
        }
        #>
}
#endregion

#region Create Fault Domains (just an example) https://docs.microsoft.com/en-us/windows-server/failover-clustering/fault-domains
#note: it is useful to describe location as when fault will happen, in fault description will be location of affected cluster
#Describe Rack
$RackFD = New-ClusterFaultDomain -Name "Rack01" -FaultDomainType Rack -Location "This Is My Demo HQ, Room 2B, Aisle A, Rack 01" -CimSession $ClusterName

#describe Site
$SiteFD = New-ClusterFaultDomain -Name "ACT" -FaultDomainType Site -Location "This Is My Demo HQ, 123 My St, Room 2B, Waco" -CimSession $ClusterName

#Add nodes to rack
Foreach ($Server in $ClusterNode) {
    Set-ClusterFaultDomain -Name $Server  -Parent $RackFD.Name -CimSession $ClusterName
}

#Add rack to site
Set-ClusterFaultDomain -Name $RackFD.Name -Parent $SiteFD.Name -CimSession $ClusterName

#remove default site
#Get-ClusterFaultDomain -CimSession $ClusterName -Name site* | Remove-ClusterFaultDomain

#validate
Get-ClusterFaultDomainxml -CimSession $ClusterName

<#region more examples using PowerShell
<#
$numberofnodes=4
$ClusterNodeNamePrefix="Axnode"

if ($numberofnodes -eq 4){
    New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName

    1..4 | ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_"  -Parent "Rack01" -CimSession $ClusterName}
    Set-ClusterFaultDomain -Name "Rack01" -Parent "SEA"    -CimSession $ClusterName

}

if ($numberofnodes -eq 8){
    New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack02"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 02"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack03"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 03"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack04"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 04"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName

    1..2 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Rack01"    -CimSession $ClusterName}
    3..4 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Rack02"    -CimSession $ClusterName}
    5..6 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Rack03"    -CimSession $ClusterName}
    7..8 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Rack04"    -CimSession $ClusterName}
    1..4 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
}

if ($numberofnodes -eq 16){
    New-ClusterFaultDomain -Name "Chassis01" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Chassis02" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Chassis03" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName 
    New-ClusterFaultDomain -Name "Chassis04" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName
    New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
    New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName

    1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Chassis01" -CimSession $ClusterName}
    5..8   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Chassis02" -CimSession $ClusterName}
    9..12  |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Chassis03" -CimSession $ClusterName}
    13..16 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ClusterNodeNamePrefix)$_" -Parent "Chassis04" -CimSession $ClusterName}

    1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "Chassis0$_" -Parent "Rack01"    -CimSession $ClusterName}

    1..1 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}

}
#>
#endregion

#endregion

#region Enable S2D
#Enable-ClusterS2D
Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

#display pool
Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName

#Display disks
Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName | Get-PhysicalDisk -CimSession $ClusterName

#Get Storage Tiers
Get-StorageTier -CimSession $ClusterName

#display pool defaults
Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName
#endregion

#region create sample volumes
#configure thin provisioning (because why not)
Get-StoragePool -FriendlyName "S2D on $ClusterName" -CimSession $ClusterName | Set-StoragePool -ProvisioningTypeDefault Thin

#create 1TB volume on each node
foreach ($Server in $ClusterNode) {
    New-Volume -StoragePoolFriendlyName  "S2D on $ClusterName" -FriendlyName $Server -Size 1TB -CimSession $ClusterName
}

#align volumes ownership to with servers
foreach ($Server in $ClusterNode) {
    Move-ClusterSharedVolume -Name "Cluster Virtual Disk ($Server)" -Node $Server -Cluster $ClusterName
}
#endregion

#region register to Azure
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell Inc.") {
    #Add OEM Information so hardware is correctly billed
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name SupportProvider -Value DellEMC​
    }
}

#download Azure module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)) {
    Install-Module -Name Az.StackHCI -Force -AllowClobber
}

#login to azure
#download Azure module
if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)) {
    Install-Module -Name Az.Accounts -Force
}
if (-not (Get-AzContext)) {
    Connect-AzAccount -UseDeviceAuthentication
}

#select context if more available
$context = Get-AzContext -ListAvailable
if (($context).count -gt 1) {
    $context | Out-GridView -OutputMode Single | Set-AzContext
}

#select subscription if more available
$subscriptions = Get-AzSubscription
if (($subscriptions).count -gt 1) {
    $SubscriptionID = ($subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription).Subscription.Id
}
else {
    $SubscriptionID = $subscriptions.id
}

#enable debug logging in case something goes wrong
$ClusterNode = (Get-ClusterNode -Cluster $ClusterName).Name
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { wevtutil.exe sl /q /e:true Microsoft-AzureStack-HCI/Debug } -ErrorAction Ignore
#register Azure Stack HCI
$ResourceGroupName = "" #if blank, default will be used
if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)) {
    Install-Module -Name Az.Resources -Force
}
#choose location for cluster (and RG)
$region = (Get-AzResourceProvider -ProviderNamespace Microsoft.AzureStackHCI).Where{ ($_.ResourceTypes.ResourceTypeName -eq 'clusters' -and $_.RegistrationState -eq 'Registered') }.Locations | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata"
$region = $region -replace '\s', ''
$region = $region.ToLower()
if ($ResourceGroupName) {
    If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $region
    }
}

#Register AzSHCI with prompting for creds
if ($ResourceGroupName) {
    Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication -ResourceGroupName $ResourceGroupName
}
else {
    Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication
}

#Register AZSHCi without prompting for creds again
<#
        $armTokenItemResource = "https://management.core.windows.net/"
        #$graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        if ($ResourceGroupName){
            Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ArmAccessToken $armToken -ComputerName $ClusterName -AccountId $id -ResourceName $ClusterName -ResourceGroupName $ResourceGroupName #-ArmAccessToken $armToken
        }else{
            Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ArmAccessToken $armToken -ComputerName $ClusterName -AccountId $id -ResourceName $ClusterName
        }
        #>

#validate registration status
#grab available commands for registration
Invoke-Command -ComputerName $ClusterName -ScriptBlock { Get-Command -Module AzureStackHCI }
#validate cluster registration
Invoke-Command -ComputerName $ClusterName -ScriptBlock { Get-AzureStackHCI }
#validate certificates
Invoke-Command -ComputerName $ClusterName -ScriptBlock { Get-AzureStackHCIRegistrationCertificate }
#validate Arc integration
Invoke-Command -ComputerName $ClusterName -ScriptBlock { Get-AzureStackHCIArcIntegration }

#endregion

#region configure iDRAC USB NICs (IP and State) using RedFish
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell*") {
    #ignoring cert is needed for posh5. In 6 and newer you can just add -SkipCertificateCheck to Invoke-WebRequest
    function Ignore-SSLCertificates {
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler = $Provider.CreateCompiler()
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $False
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $False
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource = @'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
        $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
        $TAAssembly = $TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }
    Ignore-SSLCertificates

    #Patch Enable OS to iDrac Pass-through and configure IP
    $Headers = @{"Accept" = "application/json" }
    $ContentType = 'application/json'
    foreach ($iDRAC in $iDRACs) {
        $uri = "https://$($idrac.IP)/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
        $JSONBody = @{"Attributes" = @{"OS-BMC.1.UsbNicIpAddress" = "$($iDRAC.USBNICIP)"; "OS-BMC.1.AdminState" = "Enabled" } } | ConvertTo-Json -Compress
        Invoke-WebRequest -Body $JsonBody -Method Patch -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials
    }

    #wait a bit to propagate
    Start-Sleep 5

    #Check if it was patched
    $Headers = @{"Accept" = "application/json" }
    $ContentType = 'application/json'
    $results = @()
    foreach ($IP in $Idracs.IP) {
        $uri = "https://$IP/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
        $Result = Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials
        $uri = "https://$IP/redfish/v1/Systems/System.Embedded.1/"
        $HostName = (Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials).HostName
        $IPInsideOS = (get-Netadapter -CimSession $HostName -InterfaceDescription "Remote NDIS Compatible Device" | Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore).IPAddress
        $Result.Attributes | Add-Member -NotePropertyName HostName -NotePropertyValue $HostName
        $Result.Attributes | Add-Member -NotePropertyName IPInsideOS -NotePropertyValue $IPInsideOS
        $results += $Result.Attributes
    }
    $Results | Select-Object "HostName", "CurrentIPv4.1.Address", "OS-BMC.1.UsbNicIpAddress", "IPInsideOS", "OS-BMC.1.AdminState"
}
#endregion

#region (optional) install iDRAC Service Module (ism) https://www.dell.com/support/search/en-us#q=ism&sort=relevancy&f:langFacet=[en]
#note: ismrfutil is installed anyway as part of managing AzSHCI With Windows Admin Center
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell*") {
    #download and extract latest catalog
    #Download catalog
    Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
    #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
    Function Expand-GZipArchive {
        Param(
            $infile,
            $outfile = ($infile -replace '\.gz$', '')
        )
        $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
        $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
        $buffer = New-Object byte[](1024)
        while ($true) {
            $read = $gzipstream.Read($buffer, 0, 1024)
            if ($read -le 0) { break }
            $output.Write($buffer, 0, $read)
        }
        $gzipStream.Close()
        $output.Close()
        $input.Close()
    }
    Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$env:UserProfile\Downloads\ASHCI-Catalog.xml"
    #find binary in catalog
    #load catalog
    [xml]$XML = Get-Content "$env:UserProfile\Downloads\ASHCI-Catalog.xml"
    $component = $xml.manifest.SoftwareComponent | Where-Object Path -Like *systems-management*
    #find binary
    $url = "https://dl.dell.com/$($component.path)"
    $filename = $url | Split-Path -Leaf
    #download
    Start-BitsTransfer -Source $url -Destination $env:USERPROFILE\Downloads\$filename
    #copy ism to nodes and install
    $Sessions = New-PSSession -ComputerName $ClusterNode
    foreach ($session in $sessions) {
        Copy-Item -Path $env:USERPROFILE\Downloads\$filename -Destination $env:USERPROFILE\Downloads\$filename -ToSession $Session
    }
    #install
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
        Start-Process -FilePath $env:USERPROFILE\Downloads\$using:FileName -ArgumentList "/s" -Wait
    }
}
#endregion

#region (optional) Install Windows Admin Center Gateway https://github.com/microsoft/WSLab/tree/master/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA#gw-mode-installation-with-self-signed-cert
##Install Windows Admin Center Gateway 
$GatewayServerName = "WACGW"
#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")) {
    Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
    #Or preview (not updated for some time)
    #Start-BitsTransfer -Source https://aka.ms/WACInsiderDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
}
#Create PS Session and copy install files to remote server
#make sure maxevenlope is 8k
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock { Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192 }
$Session = New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
} -ErrorAction Ignore

$Session | Remove-PSSession

#add certificate to trusted root certs (workaround to trust HTTPs cert on WACGW)
start-sleep 30
$cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My\ | Where-Object subject -eq "CN=Windows Admin Center" }
$cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

#Configure Resource-Based constrained delegation
Install-WindowsFeature -Name RSAT-AD-PowerShell
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter { OperatingSystem -eq "Azure Stack HCI" }).Name

foreach ($computer in $computers) {
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}

#update installed extensions
#https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/configure/use-powershell
#Copy Posh Modules from wacgw
$Session = New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "C:\Program Files\Windows Admin Center\PowerShell\" -Destination "C:\Program Files\Windows Admin Center\PowerShell\" -Recurse -FromSession $Session
$Session | Remove-PSSession

#Import Posh Modules
$Items = Get-ChildItem -Path "C:\Program Files\Windows Admin Center\PowerShell\Modules" -Recurse | Where-Object Extension -eq ".psm1"
foreach ($Item in $Items) {
    Import-Module $Item.fullName
}

#list commands
Get-Command -Module ExtensionTools

#grab installed extensions 
$InstalledExtensions = Get-Extension -GatewayEndpoint https://$GatewayServerName  | Where-Object status -eq Installed
$ExtensionsToUpdate = $InstalledExtensions | Where-Object IsLatestVersion -eq $False

foreach ($Extension in $ExtensionsToUpdate) {
    Update-Extension -GatewayEndpoint https://$GatewayServerName -ExtensionId $Extension.ID
}

#Install OpenManage extension
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $ClusterNode).Manufacturer -like "*Dell Inc.") {
    Install-Extension -GatewayEndpoint https://$GatewayServerName -ExtensionId dell-emc.openmanage-integration
}
#endregion

#region troubleshooting
#check devices drivers
Get-CimInstance -ClassName Win32_PnPSignedDriver -CimSession $ClusterNode | Select-Object DeviceName, DriverDate, DriverVersion, Manufacturer, PSComputerName | Out-GridView

#check OS Build Number
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
$ComputersInfo = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    Get-ItemProperty -Path $using:RegistryPath
}
$ComputersInfo | Select-Object PSComputerName, ProductName, DisplayVersion, UBR

#region check if there are any updates are needed
$ScanResult = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    & "C:\Program Files\Dell\DELL System Update\DSU.exe" --catalog-location="$env:UserProfile\Downloads\ASHCI-Catalog.xml" --preview | Out-Null
    $JSON = Get-content "C:\ProgramData\Dell\DELL System Update\dell_dup\DSU_STATUS.json" | ConvertFrom-JSon
    $Result = $JSON.systemupdatestatus.invokerinfo.statusmessage
    if ($Result -like "No Applicable Update*" ) {
        Write-Output "No updates found"
        $DellUpdates = $null
    }
    else {
        $DellUpdateRequired = $true
        $DellUpdates = $json.SystemUpdateStatus.updateablecomponent | Select-Object Name, Version, Baselineversion, UpdateStatus, RebootRequired
    }
        
    #scan for microsoft updates
    $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
            IsPresent=1 and DeploymentAction='Uninstallation' or
            IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
            IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
    if ($SearchResult.Count -gt 0) {
        $MicrosoftUpdateRequired = $True
    }
    else {
        $MicrosoftUpdateRequired = $False
    }
        
    #grab windows version
    $ComputersInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        
    $Output = @()
    $Output += [PSCustomObject]@{
        "DellUpdateRequired"      = $DellUpdateRequired
        "DellUpdates"             = $DellUpdates
        "MicrosoftUpdateRequired" = $MicrosoftUpdateRequired
        "MicrosoftUpdates"        = $SearchResult
        "ComputerName"            = $env:COMPUTERNAME
        "CurrentBuildNumber"      = $ComputersInfo.CurrentBuildNumber
        "UBR"                     = $ComputersInfo.UBR
    }
    return $Output
}
$ScanResult
#endregion

#region Verify Networking
#validate vSwitch
Get-VMSwitch -CimSession $ClusterNode | Select-Object Name, IOV*, NetAdapterInterfaceDescriptions, ComputerName
#validate vNICs
Get-VMNetworkAdapter -CimSession $ClusterNode -ManagementOS
#validate vNICs to pNICs mapping
Get-VMNetworkAdapterTeamMapping -CimSession $ClusterNode -ManagementOS | Select-Object ComputerName, NetAdapterName, ParentAdapter
#validate JumboFrames setting
Get-NetAdapterAdvancedProperty -CimSession $ClusterNode -DisplayName "Jumbo Packet"
#verify RDMA settings
Get-NetAdapterRdma -CimSession $ClusterNode | Sort-Object -Property PSComputerName, Name
#validate if VLANs were set
Get-VMNetworkAdapterVlan -CimSession $ClusterNode -ManagementOS
#VLANs in NetATC are set with VMNetworkAdapterIsolation
Get-VMNetworkAdapterIsolation -CimSession $ClusterNode -ManagementOS
#verify ip config 
Get-NetIPAddress -CimSession $ClusterNode -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputerName, InterfaceAlias | Select-Object PSComputerName, InterfaceALias, IPAddress
#Validate DCBX setting
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Get-NetQosDcbxSetting } | Sort-Object PSComputerName | Select-Object PSComputerName, Willing
#validate policy (no result since it's not available in VM)
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Get-NetAdapterQos | Where-Object enabled -eq true } | Sort-Object PSComputerName
#Validate QOS Policies
Get-NetQosPolicy -CimSession $ClusterNode | Sort-Object PSComputerName, Name | Select-Object PSComputerName, NetDirectPort, PriorityValue
#validate flow control setting 
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Get-NetQosFlowControl } | Sort-Object  -Property PSComputername, Priority | Select-Object PSComputerName, Priority, Enabled
#validate QoS Traffic Classes
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Get-NetQosTrafficClass } | Sort-Object PSComputerName, Name | Select-Object PSComputerName, Name, PriorityFriendly, Bandwidth
#endregion

#region Verify Networking with Test-RDMA
#download test-rdma
Invoke-WebRequest -Uri https://raw.githubusercontent.com/microsoft/SDN/master/Diagnostics/Test-Rdma.ps1 -OutFile $env:userprofile\Downloads\Test-Rdma.ps1

#download diskspd
$downloadurl = "https://github.com/microsoft/diskspd/releases/download/v2.1/DiskSpd.ZIP"
Invoke-WebRequest -Uri $downloadurl -OutFile "$env:userprofile\Downloads\diskspd.zip"
#unzip
Expand-Archive "$env:userprofile\Downloads\diskspd.zip" -DestinationPath "$env:userprofile\Downloads\Unzip"
Copy-Item -Path (Get-ChildItem -Path "$env:userprofile\Downloads\Unzip\" -Recurse | Where-Object { $_.Directory -like '*amd64*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$env:userprofile\Downloads\"
Remove-Item -Path "$env:userprofile\Downloads\diskspd.zip"
Remove-Item -Path "$env:userprofile\Downloads\Unzip" -Recurse -Force
        
#distribute to nodes
$items = "$env:userprofile\Downloads\Test-Rdma.ps1", "$env:userprofile\Downloads\diskspd.exe"
$sessions = New-PSSession -ComputerName $ClusterNode
foreach ($item in $items) {
    foreach ($Session in $Sessions) {
        Copy-Item -Path $item -Destination $item -ToSession $Session
    }
}
        
#test RDMA
#grab connections
$connections = Get-SmbMultichannelConnection -CimSession $ClusterNode -SmbInstance SBL | Group-Object PSComputerName, ClientIPAddress, ServerIPAddress, ClientInterfaceIndex | foreach-object { $_.Group | Select-Object -First 1 } | Sort-Object -Property PSComputerName, ClientIPAddress

#test each connection
# Temporarily enable CredSSP delegation to avoid double-hop issue
foreach ($Server in $ClusterNode) {
    Enable-WSManCredSSP -Role "Client" -DelegateComputer $Server -Force
}
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Enable-WSManCredSSP Server -Force }

$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

#test
foreach ($Connection in $Connections) {
    Invoke-Command -ComputerName $Connection.PSComputerName -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Write-Host -ForegroundColor Green "$($Using:Connection.PSComputerName): $($Using:Connection.ClientIpAddress)->$($Using:Connection.ServerIpAddress)"
        & $env:USERPROFILE\Downloads\Test-Rdma.ps1 -IfIndex $using:Connection.ClientInterfaceIndex -IsRoCE $True -RemoteIpAddress $using:Connection.ServerIpAddress -PathToDiskspd $env:USERPROFILE\Downloads -outputlevel None
        Start-Sleep 10
    }
}

# Disable CredSSP
Disable-WSManCredSSP -Role Client
Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Disable-WSManCredSSP Server }
#endregion

#region others
#run test-netstack
Install-Module -Name Test-NetStack
test-netstack -Nodes $ClusterNode -LogPath c:\temp\testnetstack.log -Verbose -EnableFirewallRules -ContinueOnFailure
#check NetworkHUD event logs
$events = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    Get-WinEvent -FilterHashtable @{"ProviderName" = "Microsoft-Windows-Networking-NetworkHUD"; StartTime = (get-date).AddMinutes(-15) }
}
$events | Format-Table -AutoSize

#check NetworkATC event logs
$events = Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    Get-WinEvent -FilterHashtable @{"ProviderName" = "Microsoft-Windows-Networking-NetworkATC"; StartTime = (get-date).AddMinutes(-15) }
}
$events | Format-Table -AutoSize

#Check cluster networks
Get-ClusterNetwork -Cluster $clustername

#check last driver update status
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    #display result
    $json = Get-Content "C:\ProgramData\Dell\DELL System Update\dell_dup\DSU_STATUS.json" | ConvertFrom-Json
    $output = $json.SystemUpdateStatus.updateablecomponent #| Select-Object Name,Version,Baselineversion,UpdateStatus,RebootRequired
    Return $output
} | Out-GridView
#endregion

#region reset iDRAC NICs
#Variables
#$iDRACCredentials=Get-Credential #grab iDRAC credentials
$iDracUsername = "LabAdmin"
$iDracPassword = "LS1setup!"
$SecureStringPassword = ConvertTo-SecureString $iDracPassword -AsPlainText -Force
$iDRACCredentials = New-Object System.Management.Automation.PSCredential ($iDracUsername, $SecureStringPassword)
        
#IP = Idrac IP Address, USBNICIP = IP Address of  that will be configured in OS to iDRAC Pass-through USB interface
$iDRACs = @()
$iDRACs += @{IP = "192.168.100.130" ; USBNICIP = "169.254.11.1" }
$iDRACs += @{IP = "192.168.100.131" ; USBNICIP = "169.254.11.3" }
$iDRACs += @{IP = "192.168.100.139" ; USBNICIP = "169.254.11.5" }
$iDRACs += @{IP = "192.168.100.140" ; USBNICIP = "169.254.11.7" }

#first disable NICs in IDRAC
#ignoring cert is needed for posh5. In 6 and newer you can just add -SkipCertificateCheck to Invoke-WebRequest
function Ignore-SSLCertificates {
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $False
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $False
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource = @'
                namespace Local.ToolkitExtensions.Net.CertificatePolicy
                {
                    public class TrustAll : System.Net.ICertificatePolicy
                    {
                        public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                        {
                            return true;
                        }
                    }
                }
'@ 
    $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
    $TAAssembly = $TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}
Ignore-SSLCertificates

$Headers = @{"Accept" = "application/json" }
$ContentType = 'application/json'
#disable first
foreach ($iDRAC in $iDRACs) {
    $uri = "https://$($idrac.IP)/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
    $JSONBody = @{"Attributes" = @{"OS-BMC.1.AdminState" = "Disabled" } } | ConvertTo-Json -Compress
    Invoke-WebRequest -Body $JsonBody -Method Patch -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials
}

#Then list unkwnown adapters (iDRAC NICs should be in Unknown state now)
$Devices = Get-PnpDevice -CimSession $ClusterNode -Class Net | Where-Object Status -eq "Unknown" 
$Devices

#then clean it from registry
ForEach ($Device in $Devices) {
    Write-Host "Removing $($Device.FriendlyName)" -ForegroundColor Cyan
    $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($Device.InstanceId)"
    Invoke-Command -ComputerName $Device.PSComputerName -ScriptBlock {
        Get-Item $using:RemoveKey | Select-Object -ExpandProperty Property | Foreach-Object { Remove-ItemProperty -Path $using:RemoveKey -Name $_ -Verbose }
    }
}

#and then re-enable
foreach ($iDRAC in $iDRACs) {
    $uri = "https://$($idrac.IP)/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
    $JSONBody = @{"Attributes" = @{"OS-BMC.1.UsbNicIpAddress" = "$($iDRAC.USBNICIP)"; "OS-BMC.1.AdminState" = "Enabled" } } | ConvertTo-Json -Compress
    Invoke-WebRequest -Body $JsonBody -Method Patch -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials
}

#and now check how it looks like in OS
$Headers = @{"Accept" = "application/json" }
$ContentType = 'application/json'
$results = @()
foreach ($IP in $Idracs.IP) {
    $uri = "https://$IP/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
    $Result = Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials
    $uri = "https://$IP/redfish/v1/Systems/System.Embedded.1/"
    $HostName = (Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $iDRACCredentials).HostName
    $IPInsideOS = (get-Netadapter -CimSession $HostName -InterfaceDescription "Remote NDIS Compatible Device" | Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Ignore).IPAddress
    $Result.Attributes | Add-Member -NotePropertyName HostName -NotePropertyValue $HostName
    $Result.Attributes | Add-Member -NotePropertyName IPInsideOS -NotePropertyValue $IPInsideOS
    $results += $Result.Attributes
}
$Results | Select-Object "HostName", "CurrentIPv4.1.Address", "OS-BMC.1.UsbNicIpAddress", "IPInsideOS", "OS-BMC.1.AdminState"
#endregion

#region reset pool/disks in existing cluster
<#
        #disable S2D
        Disable-ClusterS2D -CimSession $ClusterName -Confirm:0

        #remove cluster disk in SDDC Group
        Get-ClusterResource -Cluster $ClusterName | Where-Object OwnerGroup -eq "SDDC Group" | Remove-clusterResource -Force
        #remove cluster disk from available storage
        Get-ClusterResource -Cluster $ClusterName | Where-Object OwnerGroup -eq "Available Storage" | Remove-clusterResource -Force
        #remove Storage Pool from cluster resources
        Get-ClusterResource -Cluster $ClusterName | Where-Object resourcetype -eq "Storage Pool" | Remove-ClusterResource -Force
        #remove storage pool
        Start-Sleep 5
        Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -IsReadOnly $False
        Get-StoragePool -FriendlyName S2D* -CimSession $ClusterName | Get-VirtualDisk | Remove-VirtualDisk -Confirm:0
        Get-StoragePool -FriendlyName S2D* -CimSession $ClusterName | Remove-StoragePool -Confirm:0
        #wipe disks
        Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
            Get-PhysicalDisk -CanPool $True | Reset-PhysicalDisk
        }
        Enable-ClusterS2D -CimSession $ClusterName -Confirm:0 -Verbose
    #>
#endregion

#region reset health service/performance history
<#
        #delete performance history including volume (without invoking it returned error "get-srpartnership : The WS-Management service cannot process the request. The CIM namespace")
        Invoke-Command -ComputerName $CLusterName -ScriptBlock {Stop-ClusterPerformanceHistory -DeleteHistory}
        #recreate performance history
        Start-ClusterPerformanceHistory -CimSession $ClusterName
    #>
#endregion
#endregion
