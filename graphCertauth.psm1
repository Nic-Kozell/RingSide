<#
 .Synopsis
  Returns JWT token

 .Description
  Returns JWT for a given resource with a certificate stored in Azure Key vault

 .Parameter TenantName
  ex. contoso.onmicrosoft.com

 .Parameter AppId
  UUID of the Azure AD app reg

 .Parameter vaultName
  Name of the Azure Key Vault 

 .Parameter CertName
  Secretname of the certificate in Azure Key Vault

 .Parameter ResourceUri
  ex. https://graph.microsoft.com/.default
  
 .Example
       $authParams = @{
        TenantName=$HomeTenant
        AppId=$clientId
        vaultName=$vaultName
        CertName=$CertName
        ResourceUri="https://graph.microsoft.com/.default"
    }
    $Token = Get-GraphTokenCert @authParams
#>

function Get-GraphTokenCert {
    param (
        [Parameter (Mandatory = $true)][String]$TenantName,
        [Parameter (Mandatory = $true)][String]$AppId,
        [Parameter (Mandatory = $true)][String]$vaultName,
        [Parameter (Mandatory = $true)][String]$CertName,
        [Parameter (Mandatory = $true)][String]$ResourceUri
    )

    try {
        $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $CertName
        $secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $cert.Name
        $secretValueText = '';
        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
        try {
            $secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
        }
        $secretByte = [Convert]::FromBase64String($secretValueText)
        $Certificate = new-object System.Security.Cryptography.X509Certificates.X509Certificate2($secretByte, "", "Exportable,PersistKeySet")
    }
    catch {
        Write-Error "Issue getting or using the certificate: " $_
        exit
    }

$scope = $ResourceUri

if($TenantName -eq "oregoness.onmicrosoft.us"){
    $Url = "https://login.microsoftonline.us/$TenantName/oauth2/v2.0/token"
}else{
    $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token"
}

# Create base64 hash of certificate
$CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

# Create JWT timestamp for expiration
$StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
$JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
$JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

# Create JWT validity start timestamp
$NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
$NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

# Create JWT header
$JWTHeader = @{
    alg = "RS256"
    typ = "JWT"
    # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
    x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
}

# Create JWT payload
$JWTPayLoad = @{
    # What endpoint is allowed to use this JWT
    aud = $Url

    # Expiration timestamp
    exp = $JWTExpiration

    # Issuer = your application
    iss = $AppId

    # JWT ID: random guid
    jti = [guid]::NewGuid()

    # Not to be used before
    nbf = $NotBefore

    # JWT Subject
    sub = $AppId
}

# Convert header and payload to base64
$JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
$EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

$JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
$EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

# Join header and Payload with "." to create a valid (unsigned) JWT
$JWT = $EncodedHeader + "." + $EncodedPayload

# Get the private key object of your certificate
$PrivateKey = $Certificate.PrivateKey

# Define RSA signature and hashing algorithm
$RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
$HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

# Create a signature of the JWT
$Signature = [Convert]::ToBase64String(
    $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
) -replace '\+','-' -replace '/','_' -replace '='


# Join the signature to the JWT with "."
$JWT = $JWT + "." + $Signature

# Create a hash with body parameters
$Body = @{
    client_id = $AppId
    client_assertion = $JWT
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    scope = $Scope
    grant_type = "client_credentials"

}

    

# Use the self-generated JWT as Authorization
$Header = @{
    Authorization = "Bearer $JWT"
}

# Splat the parameters for Invoke-Restmethod for cleaner code
$PostSplat = @{
    ContentType = 'application/x-www-form-urlencoded'
    Method = 'POST'
    Body = $Body
    Uri = $Url
    Headers = $Header
    # scope = $Scope
}
$Request = Invoke-RestMethod @PostSplat
return $Request
}

Export-ModuleMember -Function *
