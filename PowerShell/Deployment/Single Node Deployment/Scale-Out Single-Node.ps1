<#
Name: Single-Node Deployment.ps1
Author: Kristopher J Turner
Contact:  kristopher.turner@tierpoint.com
Version: 1.0

Credits: A majority of the script was taken from Dell's HCI Deployment Guide.  I have modified it to work with TierPoint's environment.

Todos: Working to get the script to work with TierPoint's environment.  Currently, the script will not work with TierPoint's environment.
5. Storage configuraitons after node is joined.

.DESCRIPTION
This script will deploy Azure Stack HCI cluster on a single-node cluster using either traditional networking or Network ATC. It will also install Dell drivers if Dell hardware is detected.
.NOTES
Do not run this script as is.  It is better to copy and paste the sections you need into PowerShell. I will be working on getting it to a point where we can run it as a script.

# This assumes you have a single node cluster deployed.  Please fill in varialbles below with node name being added and cluster name of cluster.

#>

#region Variables
#New Node Name
$Servers = "AzSHCI2"

#Existing Cluster Name
$ClusterName = "AzSHCI-Cluster"

#Cluster-Aware-Updating role name
$CAURoleName = "AzSHCI-Cl-CAU"


#Deploy network using Network ATC? https://learn.microsoft.com/en-us/azure-stack/hci/manage/manage-network-atc?tabs=22H2
$NetATC = $True

#Variables for traditional networking (if NetATC is $False)
$vSwitchName = "vSwitch"
#start IP for Storage networks
$IP = 1
#storage networks
$StorNet1 = "172.16.1."
$StorNet2 = "172.16.2."
$StorVLAN1 = 1
$StorVLAN2 = 2
#Jumbo Frames? Might be necessary to increase for iWARP. If not default, make sure all switches are configured end-to-end and (for example 9216). Also if non-default is set, you might run into various issues such as https://blog.workinghardinit.work/2019/09/05/fixing-slow-roce-rdma-performance-with-winof-2-to-winof/.
#if 1514 is set, setting JumboFrames is skipped. All NICs are configured (vNICs + pNICs)
$JumboSize = 1514 #9014, 4088 or 1514 (default)
#DCB for ROCE RDMA?
$RoCE = $True
$iWARP = $False

#Perform Windows update? (for more info visit WU Scenario https://github.com/microsoft/WSLab/tree/dev/Scenarios/Windows%20Update)
$WindowsUpdate = "Recommended" #Can be "All","Recommended" or "None"

#Dell updates
$DellUpdates = $False

#Witness type
$WitnessType = "FileShare" #or Cloud
$WitnessServer = "DC" #name of server where witness will be configured
#if cloud then configure following (use your own, these are just examples)
<#
    $CloudWitnessStorageAccountName="MyStorageAccountName"
    $CloudWitnessStorageKey="qi8QB/VSHHiA9lSvz1kEIEt0JxIucPL3l99nRHhkp+n1Lpabu4Ydi7Ih192A4VW42vccIgUnrXxxxxxxxxxxxx=="
    $CloudWitnessEndpoint="core.windows.net"
    #>

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

#endregion

#region validate servers connectivity with Azure Stack HCI Environment Checker https://www.powershellgallery.com/packages/AzStackHci.EnvironmentChecker
Install-PackageProvider -Name NuGet -Force
Install-Module -Name AzStackHci.EnvironmentChecker -Force -AllowClobber

$PSSessions = New-PSSession $Servers
Invoke-AzStackHciConnectivityValidation -PsSession $PSSessions
#endregion

#region Update all servers (2022 and 21H2+ systems, for more info visit WU Scenario https://github.com/microsoft/MSLab/tree/dev/Scenarios/Windows%20Update)
#check OS Build Number
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
$ComputersInfo = Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-ItemProperty -Path $using:RegistryPath
}
$ComputersInfo | Select-Object PSComputerName, CurrentBuildNumber, UBR

#Update servers
if ($WindowsUpdate -eq "Recommended") {
    #Create virtual account to be able to run command without credssp
    Invoke-Command -ComputerName $servers -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore
    #sleep a bit
    Start-Sleep 2
    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
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
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
    }
}
elseif ($WindowsUpdate -eq "All") {
    # Update servers with all updates (including preview)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore
    #sleep a bit
    Start-Sleep 2
    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
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
    Invoke-Command -ComputerName $servers -ScriptBlock {
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
Invoke-Command -ComputerName $servers -ScriptBlock {
    $Result = Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if ($result.ExitCode -eq "failed") {
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    }
}
#define and install other features
$features = "Failover-Clustering", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "NetworkATC", "NetworkHUD", "Data-Center-Bridging", "RSAT-DataCenterBridging-LLDP-Tools", "FS-SMBBW", "System-Insights", "RSAT-System-Insights"
#optional - affects perf even if not enabled on volumes as filter driver is attached (SR,Dedup) and also Bitlocker, that affects a little bit
#$features+="Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","BitLocker","RSAT-Feature-Tools-BitLocker"
Invoke-Command -ComputerName $servers -ScriptBlock { Install-WindowsFeature -Name $using:features }

# Restart and wait for computers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force
Start-Sleep 20 # Allow time for reboots to complete fully
Foreach ($Server in $Servers) {
    do { $Test = Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM }while ($test.TcpTestSucceeded -eq $False)
}
#endregion

#region configure OS settings
#Configure Active memory dump https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
}

#Configure high performance power plan
#set high performance if not VM
Invoke-Command -ComputerName $servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -ne "Virtual Machine") {
        powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    }
}
#check settings
Invoke-Command -ComputerName $servers -ScriptBlock { powercfg /list }

#Delete Storage Pool if there is any from last install
if ($DeletePool) {
    #Grab pools
    $StoragePools = Get-StoragePool -CimSession $Servers -IsPrimordial $False -ErrorAction Ignore
    #remove pools if any
    if ($StoragePools) {
        $StoragePools | Remove-StoragePool -Confirm:0
    }
    #Reset disks (to clear spaces metadata)
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-PhysicalDisk -CanPool $True | Reset-PhysicalDisk
    }
}

#Configure max evenlope size to be 8kb to be able to copy files using PSSession (useful for dell drivers update region and Windows Admin Center)
Invoke-Command -ComputerName $servers -ScriptBlock { Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192 }

#Configure MaxTimeout (10s for Dell hardware - especially if you have HDDs, 30s for Virtual environment https://learn.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-direct-in-vm)
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers).Manufacturer -like "*Dell Inc.") {
    Invoke-Command -ComputerName $servers -ScriptBlock { Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710 }
}
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers).Model -eq "Virtual Machine") {
    Invoke-Command -ComputerName $servers -ScriptBlock { Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530 }
}

#Rename Network Adapters
Invoke-Command -ComputerName $Servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -eq "Virtual Machine") {
        Rename-NetAdapter -Name "Ethernet" -NewName "MGT01"
        Rename-NetAdapter -Name "Ethernet 2" -NewName "MGMT02"
        Rename-NetAdapter -Name "Ethernet 3" -NewName "SMB01"
        Rename-NetAdapter -Name "Ethernet 4" -NewName "SMB02"
    }
}

#Verify Network Adapters
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Get-NetAdapter
}

#endregion

#region configure OS Security (tbd: https://aka.ms/hci-securitybase)
#Enable secured core
Invoke-Command -ComputerName $servers -ScriptBlock {
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
if ($DellUpdates -and ((Get-CimInstance -ClassName win32_computersystem -CimSession $Servers).Manufacturer -like "*Dell Inc.")) {
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
    $Sessions = New-PSSession -ComputerName $Servers
    Invoke-Command -Session $Sessions -ScriptBlock {
        if (-not (Test-Path $using:DSUDownloadFolder -ErrorAction Ignore)) { New-Item -Path $using:DSUDownloadFolder -ItemType Directory }
    }
    foreach ($Session in $Sessions) {
        Copy-Item -Path "$DSUDownloadFolder\DSU.exe" -Destination "$DSUDownloadFolder" -ToSession $Session -Force -Recurse
    }
    $Sessions | Remove-PSSession
    #install DSU
    Invoke-Command -ComputerName $Servers -ScriptBlock {
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
    $Sessions = New-PSSession -ComputerName $Servers
    foreach ($Session in $Sessions) {
        Copy-Item -Path $DSUPackageDownloadFolder -Destination $DSUPackageDownloadFolder -ToSession $Session -Recurse -Force
    }
    $Sessions | Remove-PSSession

    #endregion

    #region check if there are any updates needed
    $ScanResult = Invoke-Command -ComputerName $Servers -ScriptBlock {
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
    foreach ($Server in $Servers) {
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
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force
Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
#make sure computers are restarted
Foreach ($Server in $Servers) {
    do { $Test = Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM }while ($test.TcpTestSucceeded -eq $False)
}
#endregion

#region Configure networking with NetATC https://techcommunity.microsoft.com/t5/networking-blog/network-atc-what-s-coming-in-azure-stack-hci-22h2/ba-p/3598442
if ($NetATC) {
    #make sure NetATC,FS-SMBBW and other required features are installed on servers
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-WindowsFeature -Name NetworkATC, Data-Center-Bridging, RSAT-Clustering-PowerShell, RSAT-Hyper-V-Tools, FS-SMBBW
    }

    #since ATC is not available on management machine, copy PowerShell module over to management machine from cluster. However global intents will not be automatically added as in C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetworkATC\NetWorkATC.psm1 is being checked if NetATC feature is installed [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled()
    $session = New-PSSession -ComputerName $Servers
    $items = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetworkATC", "C:\Windows\System32\NetworkAtc.Driver.dll", "C:\Windows\System32\Newtonsoft.Json.dll", "C:\Windows\System32\NetworkAtcFeatureStaging.dll"
    foreach ($item in $items) {
        Copy-Item -FromSession $session -Path $item -Destination $item -Recurse -Force
    }

    #Remove All Previous Intent Configurations
    Import-Module NetworkATC
    $intents = Get-NetIntent -ClusterName $ClusterName
    $clusternodes=$Servers
    foreach ($intent in $intents) {
        Remove-NetIntent -Name $intent.IntentName -ClusterName $ClusterName
    }

    foreach ($intent in $intents) {
        foreach ($clusternode in $clusternodes) {
            Remove-VMSwitch -Name "*$($intent.IntentName)*" -ComputerName $clusternode -ErrorAction SilentlyContinue -Force
        }
    }

    foreach ($clusternode in $clusternodes) {
        New-CimSession -ComputerName $clusternode -Name $clusternode
        $CimSession = Get-CimSession
        Get-NetQosTrafficClass -CimSession $CimSession | Remove-NetQosTrafficClass -CimSession $CimSession
        Get-NetQosPolicy -CimSession $CimSession | Remove-NetQosPolicy -Confirm:$false -CimSession $CimSession
        Get-NetQosFlowControl -CimSession $CimSession | Disable-NetQosFlowControl -CimSession $CimSession
        Get-CimSession | Remove-CimSession
    }

    #if virtual environment, then skip RDMA config
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers).Model -eq "Virtual Machine") {
        Import-Module NetworkATC
        #virtual environment (skipping RDMA config)
        $AdapterOverride = New-NetIntentAdapterPropertyOverrides
        $AdapterOverride.NetworkDirect = 0
        Add-NetIntent -ClusterName $ClusterName -Name ConvergedIntent -Management -Compute -AdapterName "MGT01", "MGT02" -AdapterPropertyOverrides $AdapterOverride -Verbose
        Add-NetIntent -ClusterName $ClusterName -Name ConvergedIntent -Management -Compute -AdapterName "SMB01", "SMB02" -AdapterPropertyOverrides $AdapterOverride -Verbose
    }
    else {
        #on real hardware you can configure RDMA
        #grab fastest adapters names (assuming that we are deploying converged intent with just Mellanox or Intel E810)
        $FastestLinkSpeed = (get-netadapter -CimSession $Servers | Where-Object { $_.Status -eq "up" -and $_.HardwareInterface -eq $True }).Speed | Sort-Object -Descending | Select-Object -First 1
        #grab adapters
        $AdapterNames = (Get-NetAdapter -CimSession $Servers | Where-Object { $_.Status -eq "up" -and $_.HardwareInterface -eq $True } | where-object Speed -eq $FastestLinkSpeed | Sort-Object Name).Name
        #$AdapterNames="SLOT 3 Port 1","SLOT 3 Port 2"
        Import-Module NetworkATC
        Add-NetIntent -ClusterName $ClusterName -Name ConvergedIntent -Management -Compute -Storage -AdapterName $AdapterNames -Verbose #-StorageVlans 1,2
    }

    #Add default global intent
    #since when configuring from Management machine there is a test [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled() to make global intents available, it will not be configured, so it has to be configured manually with invoke command
    Invoke-Command -ComputerName $servers -ScriptBlock {
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
            Invoke-Command -ComputerName $servers -ScriptBlock {
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

#region Configure Witness
#ConfigureWitness
if ($WitnessType -eq "FileShare") {
    ##Configure Witness on WitnessServer
    #Create new directory
    $WitnessName = $Clustername + "Witness"
    Invoke-Command -ComputerName $WitnessServer -ScriptBlock { new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory -ErrorAction Ignore }
    $accounts = @()
    $accounts += "$env:userdomain\$ClusterName$"
    $accounts += "$env:userdomain\$env:USERNAME"
    #$accounts+="$env:userdomain\Domain Admins"
    New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession $WitnessServer
    #Set NTFS permissions 
    Invoke-Command -ComputerName $WitnessServer -ScriptBlock { (Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl }
    #Set Quorum
    Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\$WitnessServer\$WitnessName"
}
elseif ($WitnessType -eq $Cloud) {
    Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $CloudWitnessStorageAccountName -AccessKey $CloudWitnessStorageKey -Endpoint $CloudWitnessEndpoint 
}
#endregion

#region Add Node to Cluster
#Add Node to Cluster
Add-ClusterNode -Name $Servers -Cluster $ClusterName

#Configure CSV Cache (value is in MB) - disable if SCM or VM is used. For VM it's just for labs - to save some RAM.
if (Get-PhysicalDisk -cimsession $servers | Where-Object bustype -eq SCM) {
    #disable CSV cache if SCM storage is used
        (Get-Cluster $ClusterName).BlockCacheSize = 0
}
elseif ((Invoke-Command -ComputerName $servers -ScriptBlock { (get-wmiobject win32_computersystem).Model }) -eq "Virtual Machine") {
    #disable CSV cache for virtual environments
        (Get-Cluster $ClusterName).BlockCacheSize = 0
}
#endregion

#region configure Cluster-Aware-Updating and Kernel Soft Reboot
if ($CAURoleName) {
    #Install required features on nodes.
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-WindowsFeature -Name RSAT-Clustering-PowerShell
    }
    #add role
    Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -GroupName $CAURoleName -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
    #disable self-updating
    Disable-CauClusterRole -ClusterName $ClusterName -Force
}
if ($KSR) {
    #list cluster parameters - as you can see, CauEnableSoftReboot does not exist
    Get-Cluster -Name $ClusterName | Get-ClusterParameter
    #let's create the value and validate
    Get-Cluster -Name $ClusterName | Set-ClusterParameter -Name CauEnableSoftReboot -Value 1 -Create
    Get-Cluster -Name $ClusterName | Get-ClusterParameter -Name CauEnableSoftReboot
    #to delete it again you can run following command
    #Get-Cluster -Name $ClusterName | Set-ClusterParameter -Name CauEnableSoftReboot -Delete
}
#endregion

#region Configure Storage
$VolumeFriendlyName = "TwoNodesMirror"
$VolumeSize = 1TB

#configure storage pool
Set-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" -FaultDomainAwarenessDefault StorageScaleUnit

#create new volume
New-Volume -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName $VolumeFriendlyName -Size $VolumeSize -ProvisioningType Thin

#validate volume fault domain awareness
Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName, FaultDomainAwareness
#endregion

#region recreate cluster performance history volume
#config

#delete performance history including volume (without invoking it returned error "get-srpartnership : The WS-Management service cannot process the request. The CIM namespace")
Invoke-Command -ComputerName $CLusterName -ScriptBlock { Stop-ClusterPerformanceHistory -DeleteHistory }
#recreate performance history
Start-ClusterPerformanceHistory -CimSession $ClusterName

#validate volume fault domain awareness again (takes some time to recreate volume)
Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName, FaultDomainAwareness
#endregion

#region move VM(s) to new volume
#config
$VolumeFriendlyName = "TwoNodesMirror"
$DestinationStoragePath = "c:\ClusterStorage\$VolumeFriendlyName"

$VMs = Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name
foreach ($VM in $VMs) {
    $VM | Move-VMStorage -DestinationStoragePath "$DestinationStoragePath\$($VM.Name)"
}
#endregion

#region install network HUD (NetATC)
if ($NetATC) {
    #make sure NetworkHUD features are installed and network HUD is started on servers
    Invoke-Command -ComputerName $Servers -ScriptBlock {
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
        foreach ($Server in $Servers) {
            Copy-Item -Path "$env:Userprofile\downloads\$module" -Destination "\\$Server\C$\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
        }
    }
    #restart NetworkHUD service to activate
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Restart-Service NetworkHUD
    }
    #wait a bit
    Start-Sleep 10

    #check event logs
    $events = Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-WinEvent -FilterHashtable @{"ProviderName" = "Microsoft-Windows-Networking-NetworkHUD"; Id = 105 }
    }
    $events | Format-Table -AutoSize
}
#endregion

#region configure what was/was not configured with NetATC
if ($NetATC) {
    #region Configure what NetATC is not configuring
    #disable unused adapters
    Get-Netadapter -CimSession $Servers | Where-Object Status -ne "Up" | Disable-NetAdapter -Confirm:0

    #Rename and Configure USB NICs (iDRAC Network)
    $USBNics = get-netadapter -CimSession $Servers -InterfaceDescription "Remote NDIS Compatible Device" -ErrorAction Ignore
    if ($USBNics) {
        $Network = (Get-ClusterNetworkInterface -Cluster $ClusterName | Where-Object Adapter -eq "Remote NDIS Compatible Device").Network | Select-Object -Unique
        $Network.Name = "iDRAC"
        $Network.Role = "none"
    }

    #Configure dcbxmode to be host in charge (default is firmware in charge) on mellanox adapters (Dell recommendation)
    #Caution: This disconnects adapters!
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers).Manufacturer -like "*Dell Inc.") {
        if (Get-NetAdapter -CimSession $Servers -InterfaceDescription Mellanox*) {
            Set-NetAdapterAdvancedProperty -CimSession $Servers -InterfaceDescription Mellanox* -DisplayName 'Dcbxmode' -DisplayValue 'Host in charge'
        }
    }
    #configure larger receive buffers on Mellanox adapters
    if ((Get-CimInstance -ClassName win32_computersystem -CimSession $servers).Manufacturer -like "*Dell Inc.") {
        if (Get-NetAdapter -CimSession $Servers -InterfaceDescription Mellanox*) {
            Set-NetAdapterAdvancedProperty -CimSession $Servers -InterfaceDescription Mellanox* -DisplayName 'Receive buffers' -DisplayValue '4096'
        }
    }

    #endregion

    #region Check settings before applying NetATC
    #Check what networks were excluded from Live Migration
    $Networks = (Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Get-ClusterParameter -Name MigrationExcludeNetworks).Value -split ";"
    foreach ($Network in $Networks) { Get-ClusterNetwork -Cluster $ClusterName | Where-Object ID -Match $Network }

    #check Live Migration option (probably bug, because it should default to SMB - version tested 1366)
    Get-VMHost -CimSession $Servers | Select-Object *Migration*

    #Check smbbandwith limit cluster settings (notice for some reason is SetSMBBandwidthLimit=1)
    Get-Cluster -Name $ClusterName | Select-Object *SMB*

    #check SMBBandwidthLimit settings (should be pouplated already with defaults on physical cluster - it calculated 1562500000 bytes per second on 2x25Gbps NICs)
    Get-SmbBandwidthLimit -CimSession $Servers

    #check VLAN settings (notice it's using Adapter Isolation, not VLAN)
    Get-VMNetworkAdapterIsolation -CimSession $Servers -ManagementOS

    #check number of live migrations (default is 1)
    get-vmhost -CimSession $Servers | Select-Object Name, MaximumVirtualMachineMigrations
    #endregion

    #region Adjust NetATC global overrides (assuming there is one vSwitch)
    $vSwitchNics = (Get-VMSwitch -CimSession $Servers).NetAdapterInterfaceDescriptions
    $LinkCapacityInGbps = (Get-NetAdapter -CimSession $Servers -InterfaceDescription $vSwitchNics | Measure-Object Speed -Sum).sum / 1000000000
    Invoke-Command -ComputerName $Servers -ScriptBlock {
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
    Get-VMHost -CimSession $Servers | Select-Object *Migration*

    #Check LiveMigrationPerf option and Limit (SetSMBBandwidthLimit was 1, now is 0)
    Get-Cluster -Name $ClusterName | Select-Object *SMB*

    #check SMBBandwidthLimit settings
    Get-SmbBandwidthLimit -CimSession $Servers

    #check number of live migrations
    get-vmhost -CimSession $Servers | Select-Object Name, MaximumVirtualMachineMigrations

    #check it in cluster (is only 1 - expected)
    get-cluster -Name $ClusterName | Select-Object Name, MaximumParallelMigrations

    #endregion

    #remove net intent global overrides if necessary
    <#
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Import-Module NetworkATC
            Remove-NetIntent -GlobalOverrides
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides
        }
        #>
}
#endregion

#region create sample volumes
#configure thin provisioning (because why not)
Get-StoragePool -FriendlyName "S2D on $ClusterName" -CimSession $ClusterName | Set-StoragePool -ProvisioningTypeDefault Thin

#create 1TB volume on each node
foreach ($Server in $Servers) {
    New-Volume -StoragePoolFriendlyName  "S2D on $ClusterName" -FriendlyName $Server -Size 1TB -CimSession $ClusterName
}

#align volumes ownership to with servers
foreach ($Server in $Servers) {
    Move-ClusterSharedVolume -Name "Cluster Virtual Disk ($Server)" -Node $Server -Cluster $ClusterName
}
#endregion

#region configure iDRAC USB NICs (IP and State) using RedFish
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $Servers).Manufacturer -like "*Dell*") {
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
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $Servers).Manufacturer -like "*Dell*") {
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
    $Sessions = New-PSSession -ComputerName $Servers
    foreach ($session in $sessions) {
        Copy-Item -Path $env:USERPROFILE\Downloads\$filename -Destination $env:USERPROFILE\Downloads\$filename -ToSession $Session
    }
    #install
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Start-Process -FilePath $env:USERPROFILE\Downloads\$using:FileName -ArgumentList "/s" -Wait
    }
}
#endregion

