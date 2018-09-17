Add-Type -Path ".\Tools\Microsoft.IdentityModel.Clients.ActiveDirectory\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

#
# Authorization &amp; resource Url
#
$tenantId = "yourtenant.onmicrosoft.com" # or GUID "01234567-89AB-CDEF-0123-456789ABCDEF"
$clientId = "FEDCBA98-7654-3210-FEDC-BA9876543210"
$keyvault = "yourkeyvaultname"
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
$resource = "https://vault.azure.net" 

#
# Authorization Url
#
$authUrl = "https://login.microsoftonline.com/$tenantId/" 

#
# Create AuthenticationContext for acquiring token 
# 
$authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext $authUrl

#
# Acquire the authentication result
#
$platformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList "Always"
$authResult = $authContext.AcquireTokenAsync($resource, $clientId, $redirectUri, $platformParameters).Result

if ($null -ne $authResult.AccessToken) {
    #
    # Compose the access token type and access token for authorization header
    #
    $headerParams = @{'Authorization' = "$($authResult.AccessTokenType) $($authResult.AccessToken)"}

    #
    # Create Key Vault Key
    #
    $body = '
      {
        "kty": "RSA",
        "attributes": {
          "enabled": true
        }
      }'
    $url = "https://$keyvault.vault.azure.net/keys/TestKey/create?api-version=2016-10-01"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")
    $result.Content

    #
    # Get Key Vault Key
    #
    $url = "https://$keyvault.vault.azure.net/keys/TestKey?api-version=2016-10-01"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)
    $result.Content

    #
    # Create Key Vault Secret
    #
    $body = '
      {
        "value": "Pa$$w0rd",
        "attributes": {
          "enabled": true
        }
      }'
    $url = "https://$keyvault.vault.azure.net/secrets/TestSecret?api-version=2016-10-01"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method PUT -Body $body -ContentType "application/json")
    $result.Content
    
    #
    # Get Key Vault Secret
    #
    $url = "https://$keyvault.vault.azure.net/secrets/TestSecret?api-version=2016-10-01"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)
    $result.Content
    
    Write-Output "Secret: $secret"
}
else {
    Write-Host "ERROR: No Access Token"
}
