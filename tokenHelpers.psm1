#region Functions
################################################################################
##                              Helper Functions                              ##
################################################################################

$script:tokens = @{
    "aad-ode" = @{}
    "aad-dhsoha" = @{}
    "aad-odot" = @{}
    "aad-doc" = @{}
    "aad-pers" = @{}
    "aad-osp" = @{}
    "aad-oya" = @{}
    "aad-oregon" = @{}
    "aad-ess" = @{}
    "aad-gov" = @{}
}
function Epoch { ([DateTimeOffset]([DateTime]::UtcNow)).ToUnixTimeSeconds() }
try {
    $TenantInfo = Get-Content './tenant_config_json.json' | ConvertFrom-Json
    }catch{
        write-warning "Error getting tenant info $_"
    }

# Import-Module ./graphCertauth.psm1
function RefreshJwtToken {
    param (
        [string]$TenantAlias
    )
    $authParams = @{
        TenantName=$TenantInfo."$TenantAlias".TenantName
        AppId=$TenantInfo."$TenantAlias".ClientId
        vaultName=$vaultName
        CertName=$TenantInfo."$TenantAlias".CertName
        ResourceUri=$TenantInfo."$TenantAlias".ResourceUri
    }
    $Token = Get-GraphTokenCert @authParams
    $script:tokens."$TenantAlias" =@{
        token_type = $token.token_type
        token_expires = ([DateTimeOffset]([DateTime]::UtcNow)).AddSeconds(3500).ToUnixTimeSeconds()
        access_token = $token.access_token
    }
}

function IsTokenExpired {
    param (
        [string]$TenantAlias
    )

    if (-not $script:tokens."$TenantAlias") {
        throw "`$tokenInfo is null, Call RefreshJwtToken first."
    }
    # Check if it's good for more than the next ten seconds
    return $script:tokens."$TenantAlias".token_expires -lt (Epoch - 10)
}

function RefreshIfExpired {
    # Parameter help description
    param(
        [string]$TenantAlias
    )
    # Get the token if you don't have one
    if (-not $script:tokens."$TenantAlias") {
        RefreshJwtToken $TenantAlias
    }
    # Refresh it if it's too old
    if (IsTokenExpired $TenantAlias) {
        RefreshJwtToken $TenantAlias
    }
}

function Invoke-GraphCall {
    param (
        [String]
        $TenantContext,
        $Method = 'GET',
        $Uri,
        [object]$Headers,
        [object]$Body,
        [bool]$Force = $false
    )
    RefreshIfExpired $TenantContext 
    if ($Method.toUpper() -eq 'DELETE' -and -not $uri.EndsWith('$ref') -and $Force -eq $False){
        throw "`$ref was missing from the URI and would have deleted the user... let's try again shall we?"
    }
        # if((get-mgcontext).TenantId -ne $TenantInfo."$TenantContext".TenantId){
            $token = $script:tokens."$TenantContext"
            if($TenantContext -eq 'aad-gov'){$graphEnv='USGov'}else{$graphEnv='Global'}
            $Graph = Connect-MgGraph -AccessToken $(ConvertTo-SecureString -String $token.access_token -AsPlainText -Force) -Environment $graphEnv
            if($Graph -notmatch "^Welcome"){ 
                Write-Warning "Unable to connect to graph $graph"
                return
            }
        # }
            $params = @{
                Method = $Method
                Uri = "$graphUri$Uri"
                Body = $body ??= ''
                Headers= $Headers ??= @{'Content-Type'='application/json'}
            }
            $response = Invoke-MgGraphRequest @params
    return $response        
}

function DoWithRetry {
    param (
        [ScriptBlock]
        $Command,
        $RetryLimit=5,
        $Backoff=2,
        [ref]
        $ErrorVariable,
        [switch]
        $WriteToErrorStream,
        $ArgumentList
    )
    begin {
        function GetBackoffTime {
            # Binary exponential backoff 
            # if you've retried 100 times, do something else, this ain't happenin
            param ([ValidateRange(0,100)] $retries, $backoff=2)
            if ($retries -eq 0 -or $backoff -eq 0) { return 0 }
            [Math]::Pow($backoff, $retries)
        }
    }
    process {
        $retries   = 0
        $threshold = $RetryLimit
        $backoff   = $Backoff
        $tryAgain = $true

        $_Errors = @()
        RefreshIfExpired
        :tryloop
        do {
            if ($threshold -le $retries) { break tryloop }
        
            $timeout = GetBackoffTime -retries $retries
            if ($timeout) { 
                Write-Debug "Waiting $timeout seconds after failure"
                Start-Sleep -Seconds $timeout
            }
        
            try {
                & $Command @ArgumentList
                                          
                $tryAgain = $false
            }
            catch {
                $_Errors += $_
                if ($WriteToErrorStream) {
                    Write-Error $_
                }
                $retries++
            }
        } while ($tryAgain)

        if ($ErrorVariable) {
            $ErrorVariable.Value = $_Errors
        }
    }
}

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
#endregion Functions
Export-ModuleMember -Function *
