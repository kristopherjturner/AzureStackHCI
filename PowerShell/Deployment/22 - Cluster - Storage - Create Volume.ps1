$ClusterName = "AzSHCI-Cluster"
New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS `
    -StoragePoolFriendlyName S2D* -Size 1TB -FriendlyName "Volume02" `
    -ResiliencySettingName Mirror -ProvisioningType Thin