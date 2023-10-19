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