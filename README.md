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

NuGet から取得したモジュールの AcquireTokenAsync メソッドを用いてユーザー認証を行い、アクセストークンを取得します。

```powershell
$accessToken = Get-KeyVaultUserAccessToken `
            -tenantId "yourtenant.onmicrosoft.com" `
            -clientId "FEDCBA98-7654-3210-FEDC-BA9876543210" `
            -redirectUri "urn:ietf:wg:oauth:2.0:oob"
```

### Key Vault キーの作成と読み取り

キーの作成要求は以下のとおりです。

```
POST https://yourkeyvaultname.vault.azure.net//keys/ContosoFirstKey/create?api-version=2016-10-01
Authorization: Bearer eyJ0eXAiOi{省略}3lISmxZIn0.eyJhdWQiOi{省略}joiMS4wIn0.FDlzA1xpic{省略}Nj_6yECdIw
```

以下の Body を POST で送信しています。

```json
{
  "kty": "RSA",
  "attributes": {
    "enabled": true
  }
}
```

得られる応答 (読み取り結果) は以下のようになります。

```json
{
    "key": {
        "kid": "https://yourkeyvaultname.vault.azure.net/keys/TestKey/25f66f574aa64bc5829139082e3ace63",
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

### Key Vault シークレットの作成と読み取り

シークレットの作成要求は以下のとおりです。

```
PUT https://yourkeyvaultname.vault.azure.net//secrets/SQLPassword?api-version=2016-10-01 
Authorization: Bearer eyJ0eXAiOi{省略}3lISmxZIn0.eyJhdWQiOi{省略}joiMS4wIn0.FDlzA1xpic{省略}Nj_6yECdIw
```

以下の Body を PUT で送信しています。

```json
{
  "value": "Pa$$w0rd",
  "attributes": {
    "enabled": true
  }
}
```

得られる応答 (読み取り結果) は以下のようになります。

```json
{
    "value": "Pa$$w0rd",
    "id": "https://yourkeyvaultname.vault.azure.net/secrets/TestSecret/886048f39c0d48c59bf66b25a4a0305c",
    "attributes": {
        "enabled": true,
        "created": 1536834955,
        "updated": 1536834955,
        "recoveryLevel": "Purgeable"
    }
}
```