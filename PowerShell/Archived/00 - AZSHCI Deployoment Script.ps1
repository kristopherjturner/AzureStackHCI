# Define servers as variable
#$Servers = "AzSHCI1", "AzSHCI2", "AzSHCI3", "AzSHCI4"
# For Scale Out Blog
$Servers = "AzSHCI2"
$ClusterName =


## - Configure OS - ##
## - Node - ##
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

## - Get Network Adapters - ##
Invoke-Command -ComputerName $Servers -ScriptBlock { Get-NetAdapter }

## - Install Features - ##
## - Node - ##

# Install Hyper-V using DISM if Install-WindowsFeature fails
# If nested virtualization is not enabled, Install-WindowsFeature fails
Invoke-Command -ComputerName $servers -ScriptBlock {
    $Result = Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if ($result.ExitCode -eq "failed") {
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    }
}

# Define and install features
# For VMs
# $features = "Failover-Clustering", "Hyper-V-PowerShell", "Bitlocker", "FS-FileServer", "RSAT-Feature-Tools-BitLocker", "Storage-Replica", "RSAT-Storage-Replica", "FS-Data-Deduplication", "System-Insights", "RSAT-System-Insights", "RSAT-AD-Powershell", "RSAT-Clustering-PowerShell"

# For Physical Nodes
# Install-WindowsFeature -Name "BitLocker", "RSAT-Feature-Tools-BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Storage-Replica", "RSAT-Clustering-PowerShell", "NetworkATC", "Storage-Replica" "NetworkHUD", "System-Insights", "RSAT-System-Insights",


Invoke-Command -ComputerName $servers -ScriptBlock { Install-WindowsFeature -Name $using:features -IncludeAllSubFeature -IncludeManagementTools }

# Restart and wait for computers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force
Start-Sleep 20 # Allow time for reboots to complete fully
Foreach ($Server in $Servers) {
    do { $Test = Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM }while ($test.TcpTestSucceeded -eq $False)
}


## - Create Management Team - ##
## - Node - ##
# Define the vSwitch Name
$vSwitchName = "Management Team"
Invoke-Command -ComputerName $servers -ScriptBlock {
    # Get the first 2 pNIC adapters on the system
    $NetAdapters = Get-NetAdapter | Where-Object Status -eq Up | Sort-Object Name | Select-Object -First 2
    # Create the VM Switch from those 2 adapters
    New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName $NetAdapters.Name
}

## - Create Converged Switch - ##
## - Node - ##
# Define the vSwitch Name
$vSwitchName = "ConvergedSwitch"
Invoke-Command -ComputerName $servers -ScriptBlock {
    # Get the first 2 pNIC adapters on the system
    $NetAdapters = Get-NetAdapter | Where-Object Status -eq Up | `
        Where-Object { $_.Name -like "*3*" -or $_.Name -like "*4*" } | Sort-Object Name
    # Create the VM Switch from those 2 adapters
    New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName `
    $NetAdapters.Name -AllowManagementOS $FALSE
}

## - Rename Management vNIC - ##
## - Node - ##
$vSwitchName = "Management Team"
Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName `
    -NewName Management -CimSession $Servers


## - Create SMB vNICs - ##
## - Node - ##
$vSwitchName = "ConvergedSwitch"
foreach ($Server in $Servers) {
    # Add SMB vNICs (number depends on how many pNICs are connected to vSwitch)
    $SMBvNICsCount = (Get-VMSwitch -CimSession $Server `
            -Name $vSwitchName).NetAdapterInterfaceDescriptions.Count
    foreach ($number in (1..$SMBvNICsCount)) {
        $TwoDigitNumber = "{0:D2}" -f $Number
        Add-VMNetworkAdapter -ManagementOS -Name "SMB$TwoDigitNumber" `
            -SwitchName $vSwitchName -CimSession $Server
    }
}

## - Assign Static IPs to SMB01 and SMB02 vNICs - ##
## - Node - ##
$StorNet1 = "172.16.1."
$StorNet2 = "172.16.2."
$IP = 1 # Starting IP
foreach ($Server in $Servers) {
    $SMBvNICsCount = (Get-VMSwitch -CimSession $Server -Name $vSwitchName).NetAdapterInterfaceDescriptions.Count
    foreach ($number in (1..$SMBvNICsCount)) {
        $TwoDigitNumber = "{0:D2}" -f $Number
        if ($number % 2 -eq 1) {
            New-NetIPAddress -IPAddress ($StorNet1 + $IP.ToString()) `
                -InterfaceAlias "vEthernet (SMB$TwoDigitNumber)" `
                -CimSession $Server -PrefixLength 24
        }
        else {
            New-NetIPAddress -IPAddress ($StorNet2 + $IP.ToString()) `
                -InterfaceAlias "vEthernet (SMB$TwoDigitNumber)" `
                -CimSession $Server -PrefixLength 24
            $IP++
        }
    }
}

New-NetIPAddress -InterfaceIndex 12 -IPAddress 192.168.0.1
Set-NetIPAddress -InterfaceIndex 12 -IPAddress 192.168.0.1 -PrefixLength 24

## - Validate Network Configs - ##
## - Node - ##
Get-NetIPAddress -CimSession $Servers -InterfaceAlias vEthernet* `
    -AddressFamily IPv4 | Sort-Object IPAddress |  `
    Select-Object IPAddress, InterfaceAlias, PSComputerName


## - Assign VLANs to SMB vNICs - ##
## - Node - ##
$StorVLAN1 = 1
$StorVLAN2 = 2

# Configure Odds and Evens for VLAN1 and VLAN2
foreach ($Server in $Servers) {
    $NetAdapters = Get-VMNetworkAdapter -CimSession $server -ManagementOS -Name *SMB* | Sort-Object Name
    $i = 1
    foreach ($NetAdapter in $NetAdapters) {
        if (($i % 2) -eq 1) {
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name `
                -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $Server
            $i++
        }
        else {
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name `
                -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $Server
            $i++
        }
    }
}
# Restart each host vNIC adapter so that the Vlan is active.
Get-NetAdapter -CimSession $Servers -Name "vEthernet (SMB*)" | Restart-NetAdapter

## - Map SMB vNICs to pNICs - ##
## - Node - ##
Invoke-Command -ComputerName $servers -ScriptBlock {
    # Retrieve adapter names
    $physicaladapternames = (get-vmswitch $using:vSwitchName).NetAdapterInterfaceDescriptions
    # Map pNIC and vNICs
    $vmNetAdapters = Get-VMNetworkAdapter -Name "SMB*" -ManagementOS
    $i = 0
    foreach ($vmNetAdapter in $vmNetAdapters) {
        $TwoDigitNumber = "{0:D2}" -f ($i + 1)
        Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB$TwoDigitNumber" `
            -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapternames[$i]).name
        $i++
    }
}

# Confirm it's completed
Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | `
    Format-Table ComputerName, NetAdapterName, ParentAdapter


## - Create Cluster - ##
## - Cluster - ##
$ClusterName = "AzSHCI-Cluster"
$Servers = "AzSHCI1"
$ClusterIP = "10.0.0.111"

# Test Cluster first
Test-Cluster -Node $servers -Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration", "Hyper-V Configuration"

# Traditional Cluster with Static IP
# New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
# Cluster with IP from DHCP
# New-Cluster -Name $ClusterName -Node $servers
# Cluster with Distributed Domain Name
New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"

## - Add Node To Cluster - ##
## - Cluster - ##
Add-ClusterNode -Cluster $ClusterName -Name $Servers

## - Prepare Storage on Node
## - Node - ##
## RUN WITH CAUTION!!!! - ##

$Servers = 

Invoke-Command ($Servers) {
    # Retrieve any existing virtual disks and storage pools and remove
    Update-StorageProviderCache
    Get-StoragePool | Where-Object IsPrimordial -eq $false | `
        Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
    Get-StoragePool | Where-Object IsPrimordial -eq $false | `
        Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
    Get-StoragePool | Where-Object IsPrimordial -eq $false | `
        Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
    
    # Reset the disks
    Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
    
    # Prepare the disks
    Get-Disk | Where-Object Number -ne $null | Where-Object IsBoot -ne $true | `
        Where-Object IsSystem -ne $true | Where-Object PartitionStyle -ne RAW | `
        ForEach-Object {
        $_ | Set-Disk -isoffline:$false
        $_ | Set-Disk -isreadonly:$false
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
        $_ | Set-Disk -isreadonly:$true
        $_ | Set-Disk -isoffline:$true
    }
    Get-Disk | Where-Object Number -ne $Null | Where-Object IsBoot -ne $True | `
        Where-Object IsSystem -ne $True | Where-Object PartitionStyle -eq RAW | `
        Group-Object -NoElement -Property FriendlyName
} | Sort-Object -Property PsComputerName, Count

## - Enable S2D - ##
## - Cluster - ##
Enable-ClusterStorageSpacesDirect -PoolFriendlyName "S2D on $ClusterName" -CimSession $ClusterName


## - Create Cloud Witness - ##
## - Cluster - ##

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


## - Install HCI AZ Module for Registration of Cluster - ##
## - Cluster - ##
# Install NuGet and download the Azure Module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)) {
    Install-Module -Name Az.StackHCI -Force
}

## - Login to Azure and Download Az Module - ##
## - Cluster - ##
# Download Azure Accounts module
if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)) {
    Install-Module -Name Az.Accounts -Force
}
# Login to Azure
Login-AzAccount -UseDeviceAuthentication


# Select context if more available
$context = Get-AzContext -ListAvailable

# Check if multiple subscriptions are available and choose preferred subscription
if (($context).count -gt 1) {
    $context = $context | Out-GridView -OutputMode Single
    $context | Set-AzContext
}
# Load subscription ID into variable
$subscriptionID = $context.subscription.id


## - Get AZSHCI Registration - ##
## - Cluster - ##
Invoke-Command -ComputerName azshci1 -ScriptBlock {
    Get-AzureStackHCI
}

## - Create Resources in Azure - ##
## - Cluster - ##
# Define the Azure resource group name (Customizable)
$ResourceGroupName = $ClusterName + "_Rg"

# Install the Az.Resources module to create resource groups
if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)) {
    Install-Module -Name Az.Resources -Force
}

# Display and select location for registered cluster (and RG)
$region = (Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" `
    | Out-GridView -OutputMode Single -Title "Please select Location for Azure Stack HCI metadata").Location

# Create the resource group to contain the registered Azure Stack HCI cluster
if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $region
}

## - Register Cluster - ##
## - Cluster - ##
Register-AzStackHCI -SubscriptionId $subscriptionID -ComputerName $ClusterName -Region "eastus" -ResourceName $ClusterName -ResourceGroupName $ResourceGroupName



## - Register WAC - ##
## - WAC - ##


## - Create Volumes - ##
## - Cluster - ##
New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS `
    -StoragePoolFriendlyName S2D* -Size 1TB -FriendlyName "Volume02" `
    -ResiliencySettingName Mirror -ProvisioningType Thin



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




