<#
.SYNOPSIS
Start or Stop AKS Cluster using PowerShell
.PARAMETER Action
Specify "start" or "stop"
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("start", "stop")]
    [string]$Action
)

# ===============================
# Variables
# ===============================
$resourceGroup = "ram_rg"
$clusterName   = "ramaks"

Write-Host "Performing '$Action' operation on AKS cluster '$clusterName' in RG '$resourceGroup'..."

# ===============================
# Authenticate (Azure DevOps handles this automatically if Service Connection is used)
# ===============================
try {
    az account show > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Logging in to Azure..."
        az login --service-principal `
            --username $env:servicePrincipalId `
            --password $env:servicePrincipalKey `
            --tenant $env:tenantId
    }
}
catch {
    Write-Host "⚠️ Azure authentication failed. Ensure service connection is configured."
    exit 1
}

# ===============================
# Start / Stop the AKS Cluster
# ===============================
if ($Action -eq "stop") {
    Write-Host "⏹️ Stopping AKS cluster '$clusterName'..."
    az aks stop --name $clusterName --resource-group $resourceGroup
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ AKS cluster '$clusterName' stopped successfully."
    } else {
        Write-Host "❌ Failed to stop AKS cluster. Check logs."
        exit 1
    }
}
elseif ($Action -eq "start") {
    Write-Host "▶️ Starting AKS cluster '$clusterName'..."
    az aks start --name $clusterName --resource-group $resourceGroup
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ AKS cluster '$clusterName' started successfully."
    } else {
        Write-Host "❌ Failed to start AKS cluster. Check logs."
        exit 1
    }
}
