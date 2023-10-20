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