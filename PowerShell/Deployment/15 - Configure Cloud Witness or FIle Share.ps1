$ClusterName = "AzSHCI-Cluster"

# Configure Witness
$WitnessServer = "DC"

# Create new directory
$WitnessName = $ClusterName + "Witness"
Invoke-Command -ComputerName $WitnessServer -ScriptBlock `
{ New-Item -Path C:\Shares -Name $using:WitnessName -ItemType Directory }
$accounts = @()
$accounts += "Dell\$ClusterName$"
$accounts += "Dell\Domain Admins"
New-SmbShare -Name $WitnessName -Path "C:\Shares\$WitnessName" `
    -FullAccess $accounts -CimSession $WitnessServer

# Set NTFS permissions 
Invoke-Command -ComputerName $WitnessServer -ScriptBlock `
{ (Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl }



Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\$WitnessServer\$WitnessName"



#--------------------------

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


