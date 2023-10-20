$ClusterName = "AzSHCI-Cluster"

# Install NuGet and download the Azure Module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)) {
    Install-Module -Name Az.StackHCI -Force
}