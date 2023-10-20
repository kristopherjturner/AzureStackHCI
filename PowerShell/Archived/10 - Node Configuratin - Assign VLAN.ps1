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