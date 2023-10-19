# Select context if more available
$context = Get-AzContext -ListAvailable

# Check if multiple subscriptions are available and choose preferred subscription
if (($context).count -gt 1) {
    $context = $context | Out-GridView -OutputMode Single
    $context | Set-AzContext
}
# Load subscription ID into variable
$subscriptionID = $context.subscript