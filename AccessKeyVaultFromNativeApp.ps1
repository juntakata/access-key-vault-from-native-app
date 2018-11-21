Add-Type -Path ".\Tools\Microsoft.IdentityModel.Clients.ActiveDirectory\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

<# 
    .Synopsis
    Gets an access token for user

    .Description
    This function returns a string with the access token for Key Vault.

    .Parameter TenantDomain
    The domain name of the tenant you want the token for.

    .Parameter clientId
    The client id of the application you want the token for.

    .Parameter redirectUri
    The redirect uri of the application.

    .Example
    $accessToken = Get-KeyVaultUserAccessToken -tenantId "contoso.onmicrosoft.com" -clientId "FEDCBA98-7654-3210-FEDC-BA9876543210" -redirectUri "urn:ietf:wg:oauth:2.0:oob"
#>
Function Get-KeyVaultUserAccessToken {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$tenantId,
        
        [parameter(Mandatory=$true)]
        [string]$clientId,

        [parameter(Mandatory=$true)]
        [string]$redirectUri
    )
    
    $resource = "https://vault.azure.net"
    $authUrl = "https://login.microsoftonline.com/$tenantId/"

    $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext $authUrl
    $platformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList "Always"
    $authResult = $authContext.AcquireTokenAsync($resource, $clientId, $redirectUri, $platformParameters).Result

    if ($null -ne $authResult.AccessToken) {
        return $authResult.AccessToken
    }
    else {
        return $null
    }
}

<# 
    .Synopsis
    Create a new Key Vault key

    .Description
    This function create a new key and returns a result.

    .Parameter accessToken
    The access token for this operation

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of key you want to create.

    .Example
    $key = Create-KeyVaultKey -accessToken $accessToken -vaultName "MyKeyVault" -keyName "testkey"
#>
Function Create-KeyVaultKey {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$keyName        
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}

    $body = '
      {
        "kty": "RSA",
        "attributes": {
          "enabled": true
        }
      }'
    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/create?api-version=7.0"

    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")

    return $result.Content
}

<# 
    .Synopsis
    Create a new Key Vault key

    .Description
    This function create a new key and returns a result.

    .Parameter accessToken
    The access token for this operation

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of key you want to create.

    .Example
    $key = Get-KeyVaultKey -accessToken $accessToken -vaultName "MyKeyVault" -keyName "testkey"
#>
Function Get-KeyVaultKey {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$keyName        
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)

    return $result.Content | ConvertFrom-Json
}

<# 
    .Synopsis
    Create a new Key Vault secret

    .Description
    This function create a new secret and returns a result.

    .Parameter accessToken
    The access token for this operation

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of secret you want to create.

    .Parameter secretValue
    The value of secret you want to create.

    .Example
    $secret = Create-KeyVaultSecret -accessToken $accessToken -vaultName "MyKeyVault" -secretName "testkey" -secretValue "Pa$$w0rd"
#>
Function Create-KeyVaultSecret {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$secretName,

        [parameter(Mandatory=$true)]
        [string]$secretValue   
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}

    $body = "
      {
        `"value`": `"$secretValue`",
        `"attributes`": {
          `"enabled`": true
        }
      }"
    $url = "https://" + $vaultName + ".vault.azure.net/secrets/" + $secretName + "?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method PUT -Body $body -ContentType "application/json")

    return $result.Content
}

<# 
    .Synopsis
    Get a Key Vault secret

    .Description
    This function gets a secret.

    .Parameter accessToken
    The access token for this operation.

    .Parameter vaultName
    The name of the key container.

    .Parameter secretName
    The name of secret you want to get.

    .Example
    $secret = Get-KeyVaultSecret -accessToken $accessToken -vaultName "MyKeyVault" -secretName "TestSecret"
#>
Function Get-KeyVaultSecret {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$secretName        
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}

    $url = "https://" + $vaultName + ".vault.azure.net/secrets/" + $secretName + "?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)

    return $result.Content
}

<# 
    .Synopsis
    Encrypt a value with Key Vault key

    .Description
    This function encrypts a given value with Key Vault key.

    .Parameter accessToken
    The access token for this operation.

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of the key.

    .Parameter keyVersion
    The version of the key.

    .Parameter value
    The value you want to encrypt.

    .Example
    $result = Encrypt-KeyVaultData -accessToken $accessToken -vaultName "MyKeyVault" -keyName "TestKey" -keyVersion "xxx" -value "5ka5IVsnGrzufA"
#>
Function Encrypt-KeyVaultData {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$keyName,
        
        [parameter(Mandatory=$false)]
        [string]$keyVersion,

        [parameter(Mandatory=$true)]
        [byte[]]$plainByteArray
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}
    $base64String = [Convert]::ToBase64String($plainByteArray)
    $body = "
      {
        `"alg`": `"RSA-OAEP`",
        `"value`": `"$base64String`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/encrypt?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")

    return $result.Content | ConvertFrom-Json
}

<# 
    .Synopsis
    Encrypt a value with Key Vault key

    .Description
    This function encrypts a given value with Key Vault key.

    .Parameter accessToken
    The access token for this operation.

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of the key.

    .Parameter keyVersion
    The version of the key.

    .Parameter value
    The value you want to encrypt.

    .Example
    $result = Encrypt-KeyVaultDataLocally -accessToken $accessToken -vaultName "MyKeyVault" -keyName "TestKey" -keyVersion "xxx" -value "5ka5IVsnGrzufA"
#>
Function Encrypt-KeyVaultDataLocal {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [byte[]]$modulus,
        
        [parameter(Mandatory=$true)]
        [byte[]]$exponent,

        [parameter(Mandatory=$true)]
        [byte[]]$plainByteArray
    )
    
    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus = $modulus
    $rsaParams.Exponent = $exponent

    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.ImportParameters($rsaParams)
    $encryptedByte = $rsa.Encrypt($plainByteArray, $true)

    return [Convert]::ToBase64String($encryptedByte).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

<# 
    .Synopsis
    Decrypt a value with Key Vault key

    .Description
    This function decrypts a given value with Key Vault key.

    .Parameter accessToken
    The access token for this operation.

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of key.

    .Parameter keyVersion
    The version of the key.

    .Parameter plainByteArray
    The value you want to decrypt.

    .Example
    $result = Decrypt-KeyVaultData -accessToken $accessToken -vaultName "MyKeyVault" -keyName "TestKey" -keyVersion "xxx" -value "si3nw3ngsef3
#>
Function Decrypt-KeyVaultData {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$keyName,
        
        [parameter(Mandatory=$false)]
        [string]$keyVersion,

        [parameter(Mandatory=$true)]
        [string]$value
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}

    $body = "
      {
        `"alg`": `"RSA-OAEP`",
        `"value`": `"$value`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/decrypt?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")
    if ($null -ne $result)
    {
        $result = ($result | ConvertFrom-Json)
        $base64value = $result.value
        $missingCharacters = $base64value.Length % 4
        if($missingCharacters -gt 0)
        {
          $missingString = New-Object System.String -ArgumentList @( '=', $missingCharacters )
          $base64value = $base64value + $missingString       
        }

        $value = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($base64value))
        $result.value = $value
        return $result
    }
    else {
        return $null
    }
}

<# 
    .Synopsis
    Sign a value with Key Vault key

    .Description
    This function signs a given value with Key Vault key.

    .Parameter accessToken
    The access token for this operation.

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of the key.

    .Parameter keyVersion
    The version of they key.

    .Parameter value
    The value you want to sign.

    .Example
    $result = Sign-KeyVaultData -accessToken $accessToken -vaultName "MyKeyVault" -keyName "TestKey" -keyVersion "xxx" -value byte[]
#>
Function Sign-KeyVaultData {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$keyName,
        
        [parameter(Mandatory=$false)]
        [string]$keyVersion,

        [parameter(Mandatory=$true)]
        [byte[]]$digest
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}
    $base64String = [Convert]::ToBase64String($digest)

    $body = "
      {
        `"alg`": `"RS256`",
        `"value`": `"$base64String`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/sign?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")

    return $result.Content | ConvertFrom-Json
}

<# 
    .Synopsis
    Verify a signature with Key Vault key

    .Description
    This function verifies a given signature with Key Vault key.

    .Parameter accessToken
    The access token for this operation.

    .Parameter vaultName
    The name of the key container.

    .Parameter keyName
    The name of the key.

    .Parameter keyVersion
    The version of the key.

    .Parameter value
    The value you want to verify.

    .Parameter digest
    The digest you want to compare.

    .Example
    $result = Verify-KeyVaultValue -accessToken $accessToken -vaultName "MyKeyVault" -keyName "TestKey" -keyVersion "xxx" -value "5ka5IVsnGrzufA"
#>
Function Verify-KeyVaultData {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$accessToken,
        
        [parameter(Mandatory=$true)]
        [string]$vaultName,

        [parameter(Mandatory=$true)]
        [string]$keyName,
        
        [parameter(Mandatory=$false)]
        [string]$keyVersion,

        [parameter(Mandatory=$true)]
        [string]$value,

        [parameter(Mandatory=$true)]
        [byte[]]$digest
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}
    $base64String = [Convert]::ToBase64String($digest)

    $body = "
      {
        `"alg`": `"RS256`",
        `"digest`": `"$base64String`",
        `"value`": `"$value`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/verify?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")

    return $result.Content | ConvertFrom-Json
}


$accessToken = Get-KeyVaultUserAccessToken -tenantId "yourtenant.onmicrosoft.com" -clientId "FEDCBA98-7654-3210-FEDC-BA9876543210" -redirectUri "urn:ietf:wg:oauth:2.0:oob"


$key = Create-KeyVaultKey -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -keyName "testkey"
$key = Get-KeyVaultKey -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -keyName "testkey"


$secret = Create-KeyVaultSecret -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -secretName "testsecret" -secretValue 'Pa$$w0rd'
$secret = Get-KeyVaultSecret -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -secretName "testsecret"


$value = "Hello World!"
$plainByteArray = [System.Text.Encoding]::Unicode.GetBytes($value)


$base64value = $key.key.n
$missingCharacters = $base64value.Length % 4
if($missingCharacters -gt 0)
{
  $missingString = New-Object System.String -ArgumentList @( '=', $missingCharacters )
  $base64value = $base64value + $missingString       
}
$modulus = [Convert]::FromBase64String($base64value.Replace('-', '+').Replace('_', '/'))


$base64value = $key.key.e
$missingCharacters = $base64value.Length % 4
if($missingCharacters -gt 0)
{
  $missingString = New-Object System.String -ArgumentList @( '=', $missingCharacters )
  $base64value = $base64value + $missingString       
}
$exponent = [Convert]::FromBase64String($base64value.Replace('-', '+').Replace('_', '/'))


$encryptText = Encrypt-KeyVaultDataLocal -modulus $modulus -exponent $exponent -plainByteArray $plainByteArray

$encryptResult = Encrypt-KeyVaultData -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -keyName "TestKey" -keyVersion "" -plainByteArray $plainByteArray
$decryptResult = Decrypt-KeyVaultData -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -keyName "TestKey" -keyVersion "" -value $encryptResult.value

If ($value -eq $decryptResult.value) {
    Write-Host "Encryption and decryption worked succesfully!"
}
else {
    Write-Host "Something went wrong..."
}


$sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$hash = $sha256.ComputeHash($plainByteArray)

$signResult = Sign-KeyVaultData -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -keyName "TestKey" -keyVersion "" -digest $hash
$verifyResult = Verify-KeyVaultData -accessToken $accessToken -vaultName "keyvlt-prod-kv1" -keyName "TestKey" -keyVersion "" -value $signResult.value -digest $hash

If ($verifyResult.value -eq "true") {
    Write-Host "Sign and verify worked succesfully!"
}
else {
    Write-Host "Something went wrong..."
}
