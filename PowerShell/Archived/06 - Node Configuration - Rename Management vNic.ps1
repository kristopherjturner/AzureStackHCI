$vSwitchName = "Management Team"
Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName `
    -NewName Management -CimSession $Servers