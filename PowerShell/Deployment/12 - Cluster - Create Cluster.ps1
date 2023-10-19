$ClusterName = "AzSHCI-Cluster"
$Servers = "AzSHCI1"
$ClusterIP = "10.0.0.111"

# Test Cluster first
Test-Cluster -Node $servers -Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration", "Hyper-V Configuration"

# Traditional Cluster with Static IP
# New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
# Cluster with IP from DHCP
# New-Cluster -Name $ClusterName -Node $servers
# Cluster with Distributed Domain Name
New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"