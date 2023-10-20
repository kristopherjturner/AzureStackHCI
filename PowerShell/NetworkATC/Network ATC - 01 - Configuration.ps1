$Servers = "AzSHCI1", "AzSHCI2", "AzSHCI3", "AzSHCI4"

## Rename Network Adapters
Invoke-Command -ComputerName $Servers -ScriptBlock {
    if ((Get-ComputerInfo).CsSystemFamily -eq "Virtual Machine") {
    Rename-NetAdapter -Name "Ethernet" -NewName "MGT01"
    Rename-NetAdapter -Name "Ethernet 2" -NewName "MGMT02"
    Rename-NetAdapter -Name "Ethernet 3" -NewName "SMB01"
    Rename-NetAdapter -Name "Ethernet 4" -NewName "SMB02"
    }
}

## Verify Network Adapters
    Invoke-Command -ComputerName $Servers -ScriptBlock {
    Get-NetAdapter
    }


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








---------------------------------------------------------------------------------------------

$clusname = Get-Cluster
$clusternodes = Get-ClusterNode    
$intents = Get-NetIntent -ClusterName $clusname

foreach ($intent in $intents)
{
    Remove-NetIntent -Name $intent.IntentName -ClusterName $clusname
}

foreach ($intent in $intents)
{
    foreach ($clusternode in $clusternodes)
    {
        Remove-VMSwitch -Name "*$($intent.IntentName)*" -ComputerName $clusternode -ErrorAction SilentlyContinue -Force
    }
}

foreach ($clusternode in $clusternodes)
{    
    New-CimSession -ComputerName $clusternode -Name $clusternode
    $CimSession = Get-CimSession
    Get-NetQosTrafficClass -CimSession $CimSession | Remove-NetQosTrafficClass -CimSession $CimSession
    Get-NetQosPolicy -CimSession $CimSession | Remove-NetQosPolicy -Confirm:$false -CimSession $CimSession
    Get-NetQosFlowControl -CimSession $CimSession | Disable-NetQosFlowControl -CimSession $CimSession
    Get-CimSession | Remove-CimSession
}



##  Or

    <#
            Invoke-Command -ComputerName $servers[0] -ScriptBlock {
                $intents = Get-NetIntent
                foreach ($intent in $intents){
                    Remove-NetIntent -Name $intent.IntentName
                }
            }
            #>