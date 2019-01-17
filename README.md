# access-key-vault-from-native-app

Shows how to access Azure Key Vault from PowerShell

## アクセス トークン取得のためのアプリケーション設定手順

まずは、Azure AD 上にネイティブ アプリケーションを登録します。すでに登録済みの場合、作成済みのアプリについて同様の設定を実施済みかご確認ください。

1. Azure ポータルに管理者でサインインします。
2. [Azure Active Directory] を開きます。
3. [アプリの登録] を選択します。
4. [+ 新しいアプリケーションの登録] を選択します。
5. 名前に任意のものを入力し、アプリケーションの種類は [ネイティブ] を設定します。
6. サインオン URL にはアプリの応答 URL (urn:ietf:wg:oauth:2.0:oob) を設定します。
7. アプリを作成したら、そのアプリのアプリケーション ID をメモします。
8. [設定] を選択し、[必要なアクセス許可] を選択します。
9. [+ 追加] から [Azure Key Vault] を選択します。
10. [Have full access to the Azure Key Vault service] を選択して保存を押下します。

続いて、キー コンテナーを作成します。

1. Azure ポータルに管理者でサインインします。
2. [キー コンテナー] を開きます。
3. [+ 追加] から keyvlt-prod-kv1 という名前でキーコンテナーを作成します。
4. 有効なサブスクリプションとリソース グループを選択します。
5. アクセス ポリシーにスクリプトを実行する管理者の名前があることを確認します。
6. アクセス ポリシーにスクリプトを実行する管理者の名前を選択します。
7. [キーのアクセス許可] を選択し、すべての項目にチェックをつけます。
8. [OK] を押し、キー コンテナーを作成します。

## アプリの実行

まず、GetAdModuleByNuget.ps1 を実行します。実行すると Tools フォルダーができ、フォルダー内に必要なモジュールが配置されます。本スクリプトは、もう一つの AccessKeyVaultFromNativeApp.ps1 の実行に必要なモジュールを取得してくるためのものです。この状態で、事前に内容を貴社に合わせておいた AccessKeyVaultFromNativeApp.ps1 を実行します。

本スクリプトでは以下の操作を順に行っています。

- Key Vault アクセス用のアクセストークンの取得 (Get-KeyVaultUserAccessToken)
- キー (RSA) の作成 (Create-KeyVaultRsaKey)
- キーの読み取り (Get-KeyVaultKey)
- シークレットの作成 (Create-KeyVaultSecret)
- シークレットの読み取り (Get-KeyVaultSecret)
- RSA-OAEP を用いた Key Vault 側での暗号化 (Encrypt-KeyVaultDataRsaOaep)
- RSA-OAEP を用いたローカルでの暗号化 (Encrypt-KeyVaultDataRsaOaepLocal)
- RSA-OAEP を用いた Key Vault 側での復号 (Decrypt-KeyVaultDataRsaOae)
- RSA256 を用いた Key Vault 側での署名 (Sign-KeyVaultDataRsa256)
- RSA256 を用いた Key Vault での署名検証 (Verify-KeyVaultDataRsa256)
- RSA256 を用いたローカルでの署名検証 (Verify-KeyVaultDataRsa256Local)

それぞれの詳細は以下のとおりです。

### Key Vault アクセス用のアクセストークンの取得 (Get-KeyVaultUserAccessToken)

NuGet から取得したモジュールの AcquireTokenAsync メソッドを用いてユーザー認証を行い、アクセストークンを取得します。-clientId に、上記手順で作成したアプリケーション ID を指定します。

```powershell
$accessToken = Get-KeyVaultUserAccessToken `
            -tenantId "yourtenant.onmicrosoft.com" `
            -clientId "FEDCBA98-7654-3210-FEDC-BA9876543210" `
            -redirectUri "urn:ietf:wg:oauth:2.0:oob"
```

### キー (RSA) の作成 (Create-KeyVaultRsaKey)

キーの作成要求は以下のとおりです。アクセス トークンに加えて、Key Vault 名、作成したいキーの名前を指定します。これにより kty として RSA を指定したキーが作られます。

```powershell
$keyCreate = Create-KeyVaultRsaKey `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey"
```

以下の要求を送信しています。

```json
POST https://{vaultName}.vault.azure.net/keys/{keyName}/create?api-version=7.0

{
  "kty": "RSA",
  "attributes": {
    "enabled": true
  }
}
```

### キーの読み取り (Get-KeyVaultKey)

キーの読み取りを行うには以下のようにします。アクセス トークンに加えて、Key Vault 名、キーの名前を指定します。

```powershell
$keyGet = Get-KeyVaultKey `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey"
```

得られる応答は以下のようになります。

```json
{
    "key": {
        "kid": "https://{vaultName}.vault.azure.net/keys/{keyName}/25f66f574aa64bc5829139082e3ace63",
        "kty": "RSA",
        "key_ops": [
            "encrypt",
            "decrypt",
            "sign",
            "verify",
            "wrapKey",
            "unwrapKey"
        ],
        "n": "tuCbLWITBYLVGnXbFjFv{省略}I3cmkCCDKvKxkZbm_x6Q",
        "e": "AQAB"
    },
    "attributes": {
        "enabled": true,
        "created": 1536834933,
        "updated": 1536834933,
        "recoveryLevel": "Purgeable"
    }
}
```

### シークレットの作成 (Create-KeyVaultSecret)

シークレットの作成要求は以下のとおりです。

```powershell
$secretCreate = Create-KeyVaultSecret `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -secretName "testsecret" `
            -secretValue 'Pa$$w0rd'
```

以下の要求を送信しています。

```json
POST https://{vaultName}.vault.azure.net/secrets/{secretName}?api-version=7.0

{
  "value": "Pa$$w0rd",
  "attributes": {
    "enabled": true
  }
}
```

### シークレットの読み取り (Get-KeyVaultSecret)

以下に用にすることで、指定したシークレットを読み取り可能です。アクセストークンに加え、Key Vault 名、シークレットの名前を指定します。

```powershell
$secretGet = Get-KeyVaultSecret `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -secretName "testsecret"
```

得られる応答 (読み取り結果) は以下のようになります。

```json
{
    "value": "Pa$$w0rd",
    "id": "https://{vaultName}.vault.azure.net/secrets/{secretName}/886048f39c0d48c59bf66b25a4a0305c",
    "attributes": {
        "enabled": true,
        "created": 1536834955,
        "updated": 1536834955,
        "recoveryLevel": "Purgeable"
    }
}
```

### RSA-OAEP を用いた Key Vault 側での暗号化 (Encrypt-KeyVaultDataRsaOaep)

Hello World! という文字列をバイト列に変換し、暗号化 (RSA-OAEP) します。Key Vault が保持している公開鍵を用いて暗号化を要求します。アクセストークンに加え、Key Vault 名、キー名、バージョン、暗号化したいバイト列を渡します。結果は、Base64url 形式で返されます。

```powershell
$plainString = "Hello World!"
$plainByteArray = [System.Text.Encoding]::Unicode.GetBytes($plainString)

$encryptResult = Encrypt-KeyVaultDataRsaOaep `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -plainByteArray $plainByteArray
```

### RSA-OAEP を用いたローカルでの暗号化 (Encrypt-KeyVaultDataRsaOaepLocal)

Hello World! という文字列をバイト列に変換し、暗号化します。Key Vault から取得した RSA の公開鍵 (modulus と exponent) を用いてローカルで暗号化 (RSA-OAEP) しています。結果は、Base64url 形式で返されます。

```powershell
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

$encryptResult = Encrypt-KeyVaultDataRsaOaepLocal `
            -modulus $modulus `
            -exponent $exponent `
            -plainByteArray $plainByteArray
```

### RSA-OAEP を用いた Key Vault 側での復号 (Decrypt-KeyVaultDataRsaOae)

```powershell
$decryptResult = Decrypt-KeyVaultDataRsaOaep `
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
```

### RSA256 を用いた Key Vault 側での署名 (Sign-KeyVaultDataRsa256)

Key Vault が保持する秘密鍵を用いて、バイト列 (Hello World!) のハッシュ (SHA-256) に署名します。事前にハッシュを求め、得られたダイジェストをアクセストークン、Key Vault 名、キー名、バージョンと共に渡します。結果が Base64url として得られます。

```powershell
$plainString = "Hello World!"
$plainByteArray = [System.Text.Encoding]::Unicode.GetBytes($plainString)

$sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$hash = $sha256.ComputeHash($plainByteArray)

$signResult = Sign-KeyVaultDataRsa256 `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey" `
            -keyVersion "" `
            -digestByteArray $hash
```

### RSA256 を用いた Key Vault での署名検証 (Verify-KeyVaultDataRsa256)

Key Vault が保持する公開鍵を用いて、署名を検証します。アクセストークン、Key Vault 名、キー名、バージョンと共に、Base64url の署名文字列、比較したいダイジェストを渡します。結果が true/false として得られます。

```powershell
$verifyResult = Verify-KeyVaultDataRsa256 `
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
```

### RSA256 を用いたローカルでの署名検証 (Verify-KeyVaultDataRsa256Local)

Key Vault から取得した公開鍵を用いて、ローカルで署名を検証します。RSA の modulus と exponent、検証したいバイト列、Base64url の署名文字列を渡します。結果が true/false として得られます。

```powershell
$key = Get-KeyVaultKey `
            -accessToken $accessToken `
            -vaultName "keyvlt-prod-kv1" `
            -keyName "testkey"

$modulusBase64 = Convert-FromBase64UrlToBase64($key.key.n)
$modulus = [Convert]::FromBase64String($modulusBase64)

$exponentBase64 = Convert-FromBase64UrlToBase64($key.key.e)
$exponent = [Convert]::FromBase64String($exponentBase64)

$verifyResult = Verify-KeyVaultDataRsa256Local `
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
```
