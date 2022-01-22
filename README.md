# AzureRT 

Powershell module implementing various cmdlets to interact with Azure and Azure AD from an offensive perspective.
Helpful utilities dealing with access token based authentication, easily switching from `Az` to `AzureAD` and `az cli` interfaces, easy to use pre-made attacks such as Runbook-based command execution and more.

---

## Installation

This module depends on Powershell `Az` and `AzureAD` modules pre-installed. `az cli` is optional and not required. 
Before one starts crafting around Azure, following commands may be used to prepare one's offensive environment:

```
Install-Module Az -Force -Confirm -AllowClobber
Install-Module AzureAD -Force -Confirm -AllowClobber
Install-Module MSOnline -Force -Confirm -AllowClobber
Install-Module AzureADPreview -Force -Confirm -AllowClobber
```

Even though only first two modules are required by `AzureRT`, its good to have others pre-installed too.

Then to load this module, one simply types:

```
PS> . .\AzureRT.ps1
```

---

## Batteries Included

The module will be gradually receiving next tools and utilities, naturally categorised onto subsequent kill chain phases. 

Every cmdlet has a nice help message detailing parameters, description and example usage:

```
PS C:\> Get-Help Connect-ART

NAME
    Connect-ART

SYNTAX
    Connect-ART [-AccessToken <String>] [-KeyVaultAccessToken <String>] [-SubscriptionId <String>] [-TokenFromAzCli] [<CommonParameters>]

    Connect-ART -Username <String> -Password <String> [<CommonParameters>]

DESCRIPTION
    Invokes Connect-AzAccount to authenticate current session to the Azure Portal via provided Access Token or credentials.
    Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

[...]
```


Currently, following batteries are included:

### Authentication & Token mechanics 

- **`Get-ARTWhoami`** - Displays our authentication context on Azure, AzureAD and on AZ CLI interfaces.

- **`Connect-ART`** - Invokes `Connect-AzAccount` to authenticate current session to the Azure Portal via provided Access Token or credentials. Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

- **`Connect-ARTAD`** - Invokes `Connect-AzureAD` to authenticate current session to the Azure Active Directory via provided Access Token or credentials. Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

- **`Connect-ARTADServicePrincipal`** - Invokes `Connect-AzAccount` to authenticate current session to the Azure Portal via provided Access Token or credentials. Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token. Then it creates self-signed PFX certificate and associates it with Service Principal for authentication. Afterwards, authenticates as that Service Principal to AzureAD and deassociates that certificate to cleanup

- **`Get-ARTAccessTokenAzCli`** - Acquires access token from az cli, via `az account get-access-token`

- **`Get-ARTAccessTokenAz`** - Acquires access token from Az module, via `Get-AzAccessToken` .

- **`Get-ARTAccessTokenAzureAD`** - Gets an access token from Azure Active Directory. Authored by [Simon Wahlin, @SimonWahlin ](https://blog.simonw.se/getting-an-access-token-for-azuread-using-powershell-and-device-login-flow/)

- **`Parse-JWTtokenRT`** - Parses input JWT token and prints it out nicely.

- **`Remove-ARTServicePrincipalKey`** - Performs cleanup actions after running `Connect-ARTADServicePrincipal`


### Recon and Situational Awareness

- **`Get-ARTResource`** - Authenticates to the https://management.azure.com using provided Access Token and pulls accessible resources and permissions that token Owner have against them.

- **`Get-ARTRolePermissions`** - Displays all granted permissions on a specified Azure RBAC role.

- **`Get-ARTADRolePermissions`** - Displays all granted permissions on a specified Azure AD role.

- **`Get-ARTAzRoleAssignment`** - Displays a bit easier to read representation of assigned Azure RBAC roles to the currently used Principal.

- **`Get-ARTKeyVaultSecrets`** - Lists all available Azure Key Vault secrets. This cmdlet assumes that requesting user connected to the Azure AD with KeyVaultAccessToken (scoped to https://vault.azure.net) and has "Key Vault Secrets User" role assigned (or equivalent).


### Privilege Escalation

- **`Add-ARTUserToGroup`** - Adds a specified Azure AD User to the specified Azure AD Group.

- **`Add-ARTUserToRole`** - Adds a specified Azure AD User to the specified Azure AD Role.


### Lateral Movement

- **`Invoke-ARTAutomationRunbook`** - Creates an Automation Runbook under specified Automation Account and against selected Worker Group. That Runbook will contain Powershell commands to be executed on all the affected Azure VMs.


---

### ☕ Show Support ☕

This and other projects are outcome of sleepless nights and **plenty of hard work**. If you like what I do and appreciate that I always give back to the community,
[Consider buying me a coffee](https://github.com/sponsors/mgeeky) _(or better a beer)_ just to say thank you! 💪 

---

```
Mariusz Banach / mgeeky, (@mariuszbit)
<mb [at] binary-offensive.com>
```