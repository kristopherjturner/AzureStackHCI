$Servers = "AzSHCI1"

Invoke-Command ($Servers) {
    # Retrieve any existing virtual disks and storage pools and remove
    Update-StorageProviderCache
    Get-StoragePool | Where-Object IsPrimordial -eq $false | `
        Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
    Get-StoragePool | Where-Object IsPrimordial -eq $false | `
        Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
    Get-StoragePool | Where-Object IsPrimordial -eq $false | `
        Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
    
    # Reset the disks
    Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
    
    # Prepare the disks
    Get-Disk | Where-Object Number -ne $null | Where-Object IsBoot -ne $true | `
        Where-Object IsSystem -ne $true | Where-Object PartitionStyle -ne RAW | `
        ForEach-Object {
        $_ | Set-Disk -isoffline:$false
        $_ | Set-Disk -isreadonly:$false
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
        $_ | Set-Disk -isreadonly:$true
        $_ | Set-Disk -isoffline:$true
    }
    Get-Disk | Where-Object Number -ne $Null | Where-Object IsBoot -ne $True | `
        Where-Object IsSystem -ne $True | Where-Object PartitionStyle -eq RAW | `
        Group-Object -NoElement -Property FriendlyName
} | Sort-Object -Property PsComputerName, Count