<#Grab the local vault credentials & use them to authenticate to get KV secret. Store the ClientID/Client secret in a local KeyVault named "AZKvClientID"/"AZKvSecret" 

Args:
    [string]$keyVault - Valid KeyVault name
    [string]$secretName - Valid secret in the KeyVault
        
Returns:
    [Object JSON]$AZvaultSecret - used to authenticate into another service
    #$AZvaultSecret.SecretValue
#> 

function Use_KeyVault_Password {
    param (
        [string]$keyVault,
        [string]$secretName
    )
    #check to see if the arguments are empty
    #grab the local vault credentials to authenticate
    $tenantID = " "
    try {
        # Retrieve Service Principal secrets
        $clientSecret = Get-Secret -Name "Secret"
        $clientID = Get-Secret -Name "ClientID" -AsPlainText
        Write-Output "Got: $clientID & the secret"
        if (-not $clientSecret -or -not $clientID) {
            Write-Error "Failed to retrieve client secret or client ID."
            Exit 1
        }
    }
    catch {
        Write-Error "Error retrieving secrets: $_"
        Exit 1
    }

    # Authenticate to Azure
    try {
        $credential = New-Object System.Management.Automation.PSCredential($clientID, $clientSecret)
        Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $tenantID
        Write-Output "Connected to Azure"
    }
    catch {
        Write-Error "Failed to connect to Azure: $_"
        Exit 1
    }

    # Retrieve the secret from the Key Vault
    try {
        $AZvaultSecret = Get-AzKeyVaultSecret -VaultName $keyVault -Name $secretName
        Write-Output "Got Vault secret"
        return $AZvaultSecret.SecretValue
    }
    catch {
        Write-Error "Failed to retrieve secret from Key Vault: $_"
        Exit 1
    }
}

Export-ModuleMember -Function Use_KeyVault_Password
