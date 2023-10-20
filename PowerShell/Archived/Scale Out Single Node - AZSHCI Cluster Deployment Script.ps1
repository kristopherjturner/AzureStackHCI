# This script is for scaling out a single node cluster for Azure Stack HCI.
# This script is for virtual machines for use in a development environment.

# Variables
$ClusterName = "AzSHCI-Cluster"
$Servers = "AzSHCI2"


## - Provision Servers - ##

# Configure Active memory dump
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
}

# Configure high performance power plan
# Set high performance if not VM
Invoke-Command -ComputerName $servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -ne "Virtual Machine") {
        powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    }
}
# Check settings
Invoke-Command -ComputerName $servers -ScriptBlock { powercfg /list }

# Enable Remote Desktop
Invoke-Command -ComputerName $Servers -ScriptBlock { Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0 }
Invoke-Command -ComputerName $Servers -ScriptBlock { Enable-NetFirewallRule -DisplayGroup "Remote Desktop" }

# - Install Roles & Features
# Fill in these variables with your values
$FeatureList = "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-PowerShell", "NetworkATC", "NetworkHUD", "FS-SMBBW", "Storage-Replica"

# This part runs the Install-WindowsFeature cmdlet on all servers in $ServerList, passing the list of features in $FeatureList.
Invoke-Command ($Servers) {
    Install-WindowsFeature -Name $Using:Featurelist -IncludeAllSubFeature -IncludeManagementTools
}


# Restart and wait for computers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force
Start-Sleep 20 # Allow time for reboots to complete fully
Foreach ($Server in $Servers) {
    do { $Test = Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM }while ($test.TcpTestSucceeded -eq $False)
}

## Rename Network Adapters
# I plan to make this part better...
Invoke-Command ($Servers) {
    Rename-NetAdapter -Name "Ethernet" -NewName "vmNic01"
    Rename-NetAdapter -Name "Ethernet 2" -NewName "vmNic02"
    Rename-NetAdapter -Name "Ethernet 3" -NewName "vmNic03"
    Rename-NetAdapter -Name "Ethernet 4" -NewName "vmNic04"
    }
    Invoke-Command -ComputerName $Servers -ScriptBlock {
    Get-NetAdapter
    }


## - Prep Cluster for Setup - ##
# - Prepare Drives - #

Invoke-Command ($Servers) {
    Update-StorageProviderCache
    Get-StoragePool | ? IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
    Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
    Get-Disk | ? Number -ne $null | ? IsBoot -ne $true | ? IsSystem -ne $true | ? PartitionStyle -ne RAW | % {
        $_ | Set-Disk -isoffline:$false
        $_ | Set-Disk -isreadonly:$false
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
        $_ | Set-Disk -isreadonly:$true
        $_ | Set-Disk -isoffline:$true
    }
    Get-Disk | Where Number -Ne $Null | Where IsBoot -Ne $True | Where IsSystem -Ne $True | Where PartitionStyle -Eq RAW | Group -NoElement -Property FriendlyName
} | Sort -Property PsComputerName, Count

# - Test Cluster Configuration - #
Test-Cluster -Node $ServerList -Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"

## - Add Node To Cluster - ##
## - Cluster - ##
Add-ClusterNode -Cluster $ClusterName -Name $Servers


## - Configure Cluster Networking - ##

## - Configure Cluster Networking - ##

# - Verify Adapters
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-NetAdapter -Name vmnic01, vmnic02, vmnic03, vmNic04 -CimSession (Get-ClusterNode).Name | Select Name, PSComputerName
    }
# - Rename Adapters if needed.
Rename-NetAdapter -Name oldName -NewName newName

# Configure Intent for Storage Spaces Direct
#  Disable Network Direct Adapter Property - For Virtual Machines Only
# Note: This is not required for physical servers and since this is a single-node cluster, we will not use the vmnics for SMB traffic at this time.
Invoke-Command -ComputerName $servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -eq "Virtual Machine") {
        $AdapterOverride = New-NetIntentAdapterPropertyOverrides
        $AdapterOverride.NetworkDirect = 0
        Add-NetIntent -Name StorageIntent -AdapterName vmNIC03, vmNIC04 -Storage -AdapterPropertyOverrides $AdapterOverride
    }
}

# - Validate Intent Deployment - #
Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-NetIntent
    }

Invoke-Command -ComputerName $servers -ScriptBlock {
Get-NetIntentStatus -ClusterName $ClusterName -Name Cluster_ComputeStorage
}

## - Create Cloud Witness - ##
# Not needed for single node deployments
# Install PowerShell modules
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
$ModuleNames = "Az.Accounts", "Az.Resources", "Az.Storage"
foreach ($ModuleName in $ModuleNames) {
    Install-Module -Name $ModuleName -Force
}

# Login to Azure
if (-not (Get-AzContext)) {
    Connect-AzAccount -UseDeviceAuthentication
}
# Select context if more available
$context = Get-AzContext -ListAvailable
if (($context).count -gt 1) {
    $context | Out-GridView -OutputMode Single | Set-AzContext
}


# Create Azure Resource

$ResourceGroupName = "AzSHCICloudWitness"
$StorageAccountName = "azshcicloudwitness$(Get-Random -Minimum 100000 -Maximum 999999)"

# Select preferred Azure region
$Location = Get-AzLocation | Where-Object Providers -Contains "Microsoft.Storage" | Out-GridView -OutputMode Single

# Create resource group
if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
}
# Create Storage Account
if (-not(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore)) {
    New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName `
        -SkuName Standard_LRS -Location $location.location -Kind StorageV2 -AccessTier Cool 
}

# Retrieve storage account key
$StorageAccountAccessKey = (Get-AzStorageAccountKey -Name $StorageAccountName `
        -ResourceGroupName $ResourceGroupName | Select-Object -First 1).Value



Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $StorageAccountName `
    -AccessKey $StorageAccountAccessKey -Endpoint "core.windows.net"



## - Post Configurations After Scale Out - ##
## - For scaling out clusters only - ##


### - Inline Fault Domain Changes - ###
# Change Fault Domain
Get-StoragePool -FriendlyName S2D* | Set-StoragePool -FaultDomainAwarenessDefault StorageScaleUnit

#Remove Cluster Performance History
Remove-VirtualDisk -FriendlyName ClusterPerformanceHistory


# Generate Cluster Performance History - Enable Storage Spaces Direct Again
Enable-ClusterStorageSpacesDirect -Verbose

# Remove any storage tiers that are not applicable.
Remove-StorageTier -FriendlyName <tier_name>

#  Change Fault DOmain type of existing volumes
#  For non-tired volumns.
Set-VirtualDisk –FriendlyName <name> -FaultDomainAwareness StorageScaleUnit

#  CHeck Progress #
Get-VirtualDisk -FriendlyName <volume_name> | FL FaultDomainAwareness
Get-StorageJob


## IF using a tiered volume... which I dont ##
Get-StorageTier -FriendlyName <volume_name*> | Set-StorageTier -FaultDomainAwareness StorageScaleUnit
Get-StorageTier -FriendlyName <volume_name*> | FL FriendlyName, FaultDomainAwareness

### - Inline resilency changes - ###
Get-StorageJob

## - Single Node to Two Node - ##
## If you want to keep two-way mirror don't do this
# - Non Tiered
Set-VirtualDisk -FriendlyName <name> -NumberOfDataCopies 4
# - Tiered
Get-StorageTier -FriendlyName <volume_name*> | Set-StorageTier -NumberOfDataCopies 4

# - Move Volume
Move-ClusterSharedVolume -Name <name> -Node <node>

## - Two -Node to Multi Node - ##
## If you want to keep two-way mirror don't do this
# - non tiered
Set-VirtualDisk -FriendlyName <name> -NumberOfDataCopies 3
# - Tiered
Get-StorageTier -FriendlyName <volume_name*> | Set-StorageTier -NumberOfDataCopies 3

# - Move Volume
Move-ClusterSharedVolume -Name <name> -Node <node>











