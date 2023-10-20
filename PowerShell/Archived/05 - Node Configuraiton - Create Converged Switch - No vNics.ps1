# Define servers as variable
$Servers = "AzSHCI1"

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