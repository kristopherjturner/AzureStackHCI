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