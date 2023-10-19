# Install Features
$Servers="AzSHCI1"

# Install Hyper-V using DISM if Install-WindowsFeature fails
# If nested virtualization is not enabled, Install-WindowsFeature fails
Invoke-Command -ComputerName $servers -ScriptBlock {
    $Result = Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if ($result.ExitCode -eq "failed") {
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    }
}

# Define and install features
Install-WindowsFeature -Name "BitLocker", "RSAT-Feature-Tools-BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Storage-Replica", "RSAT-Clustering-PowerShell", "NetworkATC", "Storage-Replica" "NetworkHUD", "System-Insights", "RSAT-System-Insights",
Invoke-Command -ComputerName $servers -ScriptBlock { Install-WindowsFeature -Name $using:features -IncludeAllSubFeature -IncludeManagementTools }

# Restart and wait for computers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force
Start-Sleep 20 # Allow time for reboots to complete fully
Foreach ($Server in $Servers) {
    do { $Test = Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM }while ($test.TcpTestSucceeded -eq $False)
}