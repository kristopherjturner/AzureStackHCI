Get-NetIPAddress -CimSession $Servers -InterfaceAlias vEthernet* `
    -AddressFamily IPv4 | Sort-Object IPAddress |  `
    Select-Object IPAddress, InterfaceAlias, PSComputerName