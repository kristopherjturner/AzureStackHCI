$ClusterName = "AzSHCI-Cluster"
Enable-ClusterStorageSpacesDirect -PoolFriendlyName "S2D on $ClusterName" -CimSession $ClusterName

