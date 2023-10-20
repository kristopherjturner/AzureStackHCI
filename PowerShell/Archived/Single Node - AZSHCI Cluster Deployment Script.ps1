<#
Script Name:
Author:
Contact:
Version:

This script is for configuring a single node cluster for Azure Stack HCI.
This script is for virtual machines for use in a development environment. Currently on working on a script for physical servers.  Then plans to combine the two scripts into one.
#>

<#
This assumes that the following has been completed:
1. The VMs has been created and is running AzSHCI 22H2.
2. The VMs virtual network cards are configured.
3. The Windows Admin Center has been deployed and is accessible.
4. An Active Directory Domain has been deployed (Windows 2022)
5. The VMs have been joined to the domain.
6. A Windows Server 2022 server deployed for Management (optional)
#>




### Variables
$ClusterName = "AzSHCI-Cluster"
$Servers = "AzSHCI1"


### - Provision Servers - ###

## Configure Active memory dump
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
}

## Configure high performance power plan
# Set high performance if not VM
Invoke-Command -ComputerName $servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -ne "Virtual Machine") {
        powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    }
}
# Check settings
Invoke-Command -ComputerName $servers -ScriptBlock { powercfg /list }

## Enable Remote Desktop
Invoke-Command -ComputerName $Servers -ScriptBlock { Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0 }
Invoke-Command -ComputerName $Servers -ScriptBlock { Enable-NetFirewallRule -DisplayGroup "Remote Desktop" }

## Install Roles & Features
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


### - Prep Cluster for Setup - ###

## Prepare Drives ##

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

## Test Cluster Configuration ##
Test-Cluster -Node $ServerList -Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"

### - Create Cluster - ###
$ClusterName="cluster1"
New-Cluster -Name $ClusterName –Node $Servers –nostorage -ManagementPointNetworkType "Distributed"


## - Configure Cluster Networking - ##

# - Verify Adapters
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-NetAdapter -Name vmnic01, vmnic02 -CimSession (Get-ClusterNode).Name | Select Name, PSComputerName
    }

# Configure Intent
#  Disable Network Direct Adapter Property - For Virtual Machines Only
# Note: This is not required for physical servers and since this is a single-node cluster, we will not use the vmnics for SMB traffic at this time.
Invoke-Command -ComputerName $servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -eq "Virtual Machine") {
        $AdapterOverride = New-NetIntentAdapterPropertyOverrides
        $AdapterOverride.NetworkDirect = 0
        Add-NetIntent -Name ConvergedIntent -AdapterName vmNIC01, vmNIC02 -Management -Compute -AdapterPropertyOverrides $AdapterOverride
    }
}

# - Validate Intent Deployment - #
Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-NetIntent
    }

Invoke-Command -ComputerName $servers -ScriptBlock {
Get-NetIntentStatus -ClusterName $ClusterName -Name Cluster_ComputeStorage
}

## - Enable Storage Spaces Direct - ##
Enable-ClusterStorageSpacesDirect -CacheState Disabled -CimSession $ClusterName -PoolFriendlyName "S2D on $ClusterName"

Get-StoragePool -CimSession $session

## - Create Cluster Shared Volumes - ##
$VolumeName = Volume01
New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS `
    -StoragePoolFriendlyName S2D* -Size 1TB -FriendlyName $VolumeName `
    -ResiliencySettingName Mirror -ProvisioningType Thin

## - Register Windows Admin Center - ##


### Register Azure Stack HCI with Azure ###

# Install NuGet and download the Azure Module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)) {
    Install-Module -Name Az.StackHCI -Force
}

# - Login to Azure and Download Az Module - #
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


# - Get AZSHCI Registration - #
Invoke-Command -ComputerName azshci1 -ScriptBlock {
    Get-AzureStackHCI
}

# - Create Resources in Azure - #

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

# - Register Cluster - #
Register-AzStackHCI -SubscriptionId $subscriptionID -ComputerName $ClusterName -Region "eastus" -ResourceName $ClusterName -ResourceGroupName $ResourceGroupName



## - Validate Azure Stack HCI Deployment - ##






