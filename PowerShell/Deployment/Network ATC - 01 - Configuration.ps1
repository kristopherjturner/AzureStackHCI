$Servers = "AzSHCI1", "AzSHCI2", "AzSHCI3", "AzSHCI4"


#  Disable Network Direct Adapter Property - For Virtual Machines Only
Invoke-Command -ComputerName $servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -eq "Virtual Machine") {
        $AdapterOverride = New-NetIntentAdapterPropertyOverrides
        $AdapterOverride.NetworkDirect = 0
        Add-NetIntent -Name ConvergedIntent -AdapterName vmNIC01, vmNIC02 -Management -Compute -AdapterPropertyOverrides $AdapterOverride
    }
}

### - For multi-node deployments - ###
# Fully Converged Intent
Add-NetIntent -Name ConvergedIntent -Management -Compute -Storage -AdapterName pNIC01, pNIC02, pNIC03, pNIC04

# Converged Compute & Storage, Management on Separate NICs
Add-NetIntent -Name Mgmt -Management -AdapterName pNIC01, pNIC02
Add-NetIntent -Name Compute_Storage -Compute -Storage -AdapterName pNIC03, pNIC04

# Management Intent, Storage Intent, and Compute Intent
Add-NetIntent -Name Mgmt -Management -AdapterName pNIC01
Add-NetIntent -Name Compute -Compute -AdapterName pNIC0
Add-NetIntent -Name Storage -Storage -AdapterName pNIC03, pNIC04


### - For single-node deployments - ###
Add-NetIntent -Name ConvergedIntent -Management -Compute -ClusterName AzSHCI-Cluster -AdapterName pNIC01, pNIC02