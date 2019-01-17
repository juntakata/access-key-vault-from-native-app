Add-Type -Path ".\Tools\Microsoft.IdentityModel.Clients.ActiveDirectory\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

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

Function Create-KeyVaultRsaKey {
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
    if ($null -ne $result)
    {
        return $result.Content | ConvertFrom-Json
    }
    else {
        return $null
    }
}

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
    if ($null -ne $result)
    {
        return $result.Content | ConvertFrom-Json
    }
    else {
        return $null
    }
}

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
    if ($null -ne $result)
    {
        return $result.Content | ConvertFrom-Json
    }
    else {
        return $null
    }
}

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
    if ($null -ne $result)
    {
        return $result.Content | ConvertFrom-Json
    }
    else {
        return $null
    }
}

Function Encrypt-KeyVaultplainByteArrayRsaOaep {
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
    $base64 = [Convert]::ToBase64String($plainByteArray)
    $base64Url = Convert-FromBase64ToBase64Url($base64)
    $body = "
      {
        `"alg`": `"RSA-OAEP`",
        `"value`": `"$base64Url`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/encrypt?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")
    if ($null -ne $result)
    {
        return ($result.Content | ConvertFrom-Json).value
    }
    else {
        return $null
    }
}

Function Encrypt-KeyVaultplainByteArrayRsaOaepLocal {
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

    $base64 = [convert]::ToBase64String($encryptedByte)
    $base64Url = Convert-FromBase64ToBase64Url($base64)
    return $base64Url
}

Function Decrypt-KeyVaultplainByteArrayRsaOaep {
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
        [string]$cipherBase64Url
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}

    $body = "
      {
        `"alg`": `"RSA-OAEP`",
        `"value`": `"$cipherBase64Url`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/decrypt?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")
    if ($null -ne $result)
    {
        $result = ($result | ConvertFrom-Json)
        $base64 =  Convert-FromBase64UrlToBase64($result.value)

        return [Convert]::FromBase64String($base64)
    }
    else {
        return $null
    }
}

Function Sign-KeyVaultplainByteArrayRsa256 {
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
        [byte[]]$digestByteArray
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}
    $base64 = [Convert]::ToBase64String($digestByteArray)
    $base64Url = Convert-FromBase64ToBase64Url($base64)

    $body = "
      {
        `"alg`": `"RS256`",
        `"value`": `"$base64Url`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/sign?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")
    if ($null -ne $result)
    {
        return ($result.Content | ConvertFrom-Json).value
    }
    else {
        return $null
    }
}

Function Verify-KeyVaultplainByteArrayRsa256 {
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
        [string]$signatureBase64Url,

        [parameter(Mandatory=$true)]
        [byte[]]$digestByteArray
    )
    
    $headerParams = @{'Authorization' = "Bearer $accessToken"}
    $digestBase64 = [Convert]::ToBase64String($digestByteArray)
    $digestBase64Url = Convert-FromBase64ToBase64Url($digestBase64)
    $body = "
      {
        `"alg`": `"RS256`",
        `"digest`": `"$digestBase64Url`",
        `"value`": `"$signatureBase64Url`"
      }"

    $url = "https://" + $vaultName + ".vault.azure.net/keys/" + $keyName + "/" + $keyVersion + "/verify?api-version=7.0"
    $result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method POST -Body $body -ContentType "application/json")
    if ($null -ne $result)
    {
        return ($result.Content | ConvertFrom-Json).value
    }
    else {
        return $null
    }
}

Function Verify-KeyVaultplainByteArrayRsa256Local {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [byte[]]$modulus,
        
        [parameter(Mandatory=$true)]
        [byte[]]$exponent,

        [parameter(Mandatory=$true)]
        [byte[]]$plainByteArray,

        [parameter(Mandatory=$true)]
        [string]$signatureBase64Url
    )
    
    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus = $modulus
    $rsaParams.Exponent = $exponent

    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.ImportParameters($rsaParams)

    $sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $base64 = Convert-FromBase64UrlToBase64($signatureBase64Url)
    $byteArray = [convert]::FromBase64String($base64)
    $result = $rsa.VerifyData($plainByteArray, $sha256, $byteArray)

    return $result
}

Function Convert-FromBase64UrlToBase64 {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$base64Url
    )

    $missingCharacters = $base64Url.Length % 4
    if($missingCharacters -gt 0)
    {
        $missingString = New-Object System.String -ArgumentList @( '=', $missingCharacters )
        $base64Url = $base64Url + $missingString       
    }
    $base64 = $base64Url.Replace('-', '+').Replace('_', '/')
    
    return $base64
}

Function Convert-FromBase64ToBase64Url {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$base64
    )

    $base64Url = $base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    return $base64Url
}

#
# Get Access token
#
$accessToken = Get-KeyVaultUserAccessToken `
            -tenantId "jutakata02.onmicrosoft.com" `
            -clientId "b10aaa97-2d73-46b2-900d-626b2e90581e" `
            -redirectUri "urn:ietf:wg:oauth:2.0:oob"

#
# Create and get key 
#
$keyCreate = Create-KeyVaultRsaKey `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey"

$keyGet = Get-KeyVaultKey `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey"

Write-Host "key: " $keyGet.key

#
# Create and get secret
#
$secretCreate = Create-KeyVaultSecret `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -secretName "testsecret" `
            -secretValue 'Pa$$w0rd'

$secretGet = Get-KeyVaultSecret `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -secretName "testsecret"

Write-Host "Secret: " $secretGet.value

#
# Encrypt and decrypt via Key Vault
#
$plainString = "Hello World!"
$plainByteArray = [System.Text.Encoding]::Unicode.GetBytes($plainString)

$encryptResult = Encrypt-KeyVaultplainByteArrayRsaOaep `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -plainByteArray $plainByteArray

$decryptResult = Decrypt-KeyVaultplainByteArrayRsaOaep `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -cipherBase64Url $encryptResult

If ($plainString -eq [System.Text.Encoding]::Unicode.GetString($decryptResult)) {
    Write-Host "Encryption and decryption worked successfully!"
}
else {
    Write-Host "Something went wrong..."
}

#
# Encrypt and decrypt locally
#
$plainString = "Hello World!"
$plainByteArray = [System.Text.Encoding]::Unicode.GetBytes($plainString)

$key = Get-KeyVaultKey `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey"

$modulusBase64 = Convert-FromBase64UrlToBase64($key.key.n)
$modulus = [Convert]::FromBase64String($modulusBase64)

$exponentBase64 = Convert-FromBase64UrlToBase64($key.key.e)
$exponent = [Convert]::FromBase64String($exponentBase64)

$encryptResult = Encrypt-KeyVaultplainByteArrayRsaOaepLocal `
            -modulus $modulus `
            -exponent $exponent `
            -plainByteArray $plainByteArray

$decryptResult = Decrypt-KeyVaultplainByteArrayRsaOaep `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -cipherBase64Url $encryptResult

If ($plainString -eq [System.Text.Encoding]::Unicode.GetString($decryptResult)) {
    Write-Host "Local encryption and decryption worked successfully!"
}
else {
    Write-Host "Something went wrong..."
}

#
# Sign and verify via Key Vault
#
$plainString = "Hello World!"
$plainByteArray = [System.Text.Encoding]::Unicode.GetBytes($plainString)

$sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$hash = $sha256.ComputeHash($plainByteArray)

$signResult = Sign-KeyVaultplainByteArrayRsa256 `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -digestByteArray $hash

$verifyResult = Verify-KeyVaultplainByteArrayRsa256 `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -signatureBase64Url $signResult `
            -digestByteArray $hash

If ($verifyResult) {
    Write-Host "Signing and verification worked successfully!"
}
else {
    Write-Host "Something went wrong..."
}

#
# Sign and verify locally
#
$plainString = "Hello World!"
$plainByteArray = [System.Text.Encoding]::Unicode.GetBytes($plainString)

$sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$hash = $sha256.ComputeHash($plainByteArray)

$signResult = Sign-KeyVaultplainByteArrayRsa256 `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -digestByteArray $hash
            
$key = Get-KeyVaultKey `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey"

$modulusBase64 = Convert-FromBase64UrlToBase64($key.key.n)
$modulus = [Convert]::FromBase64String($modulusBase64)

$exponentBase64 = Convert-FromBase64UrlToBase64($key.key.e)
$exponent = [Convert]::FromBase64String($exponentBase64)

$verifyResult = Verify-KeyVaultplainByteArrayRsa256Local `
            -modulus $modulus `
            -exponent $exponent `
            -plainByteArray $plainByteArray `
            -signatureBase64Url $signResult

If ($verifyResult) {
    Write-Host "Local signing and verification worked successfully!"
}
else {
    Write-Host "Something went wrong..."
}
