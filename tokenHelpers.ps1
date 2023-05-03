#region Functions
################################################################################
##                              Helper Functions                              ##
################################################################################
new-variable -scope script -name tokens -force

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
$TenantInfo = Get-Content '.\tenant_config_json.json' | ConvertFrom-Json
Import-Module ./graphCertauth.psm1
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

    if (-not $tokens."$TenantAlias") {
        throw "`$tokenInfo is null, Call RefreshJwtToken first."
    }
    # Check if it's good for more than the next ten seconds
    return $tokens."$TenantAlias".token_expires -lt (Epoch - 10)
}

function RefreshIfExpired {
    # Parameter help description
    param(
        [string]$TenantAlias
    )
    # Get the token if you don't have one
    if (-not $tokens."$TenantAlias") {
        RefreshJwtToken $TenantAlias
    }
    # Refresh it if it's too old
    if (IsTokenExpired $TenantAlias) {
        RefreshJwtToken $TenantAlias
    }
}

function WrapGraphCall {
    [CmdletBinding()]
    param (
        [String]
        $TenantContext,
        $Method = 'GET',
        $Uri
    )
    begin {
        $ctx = $TenantContext
        RefreshIfExpired -TenantAlias $ctx
        $token = $tokens."$ctx"
        if($_ -eq 'aad-gov'){$graphEnv='USGov'}else{$graphEnv='Global'}
        Connect-MgGraph -AccessToken $(ConvertTo-SecureString -String $token.access_token -AsPlainText -Force) -Environment $graphEnv
    }
    process {
        $response = Invoke-MgGraphRequest -Method $Method -Uri $Uri
    }
    end{
        return $response
    }
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
#endregion Functions