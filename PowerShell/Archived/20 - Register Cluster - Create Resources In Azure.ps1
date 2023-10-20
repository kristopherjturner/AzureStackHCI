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