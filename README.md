# AzureRT 

Powershell module implementing various cmdlets to interact with Azure and Azure AD from an offensive perspective.

Helpful utilities dealing with access token based authentication, switching from `Az` to `AzureAD` and `az cli` interfaces, easy to use pre-made attacks such as Runbook-based command execution and more.

---

## The Most Valuable Cmdlets

This toolkit brings lots of various cmdlets. This section highlights the most important & useful ones.

Typical Red Team / audit workflow starting with stolen credentials can be summarised as follows:

```
Credentials Stolen -> Authenticate to Azure/AzureAD -> find whether they're valid -> find out what you can do with them
```

The below cmdlets are precisely suited to help you follow this sequence:

1. **`Connect-ART`** - Offers various means to authenticate to Azure - credentials, PSCredential, token

2. **`Connect-ARTAD`** - Offers various means to authenticate to Azure AD - credentials, PSCredential, token

3. **`Get-ARTWhoami`** - When you authenticate - run this to check _whoami_ and validate your access

4. **`Get-ARTAccess`** - Then, when you know you have access - find out what you can do & what's possible by performing Azure situational awareness

5. **`Get-ARTADAccess`** - Similarly you can find out what you can do scoped to Azure AD.


---

## Use Cases

Cmdlets implemented in this module came helpful in following use & attack scenarios:

- Juggling with access tokens from `Az` to `AzureAD` and back again.
- Nicely print authentication context (aka _whoami_) in `Az`,  `AzureAD`, `Microsoft.Graph` and `az cli` at the same time
- Display available permissions granted to the user on a target Azure VM
- Display accessible Azure Resources along with permissions we have against them
- Easily read all accessible _Azure Key Vault_ secrets
- Authenticate as a Service Principal to leverage _Privileged Role Administrator_ role assigned to that Service Principal
- Execute attack against Azure Automation via malicious Runbook

---

## Installation

This module depends on Powershell `Az` and `AzureAD` modules pre-installed. `Microsoft.Graph` and `az cli` are optional but nonetheless really useful. 
Before one starts crafting around Azure, following commands may be used to prepare one's offensive environment:

```
Install-Module Az -Force -Confirm -AllowClobber -Scope CurrentUser
Install-Module AzureAD -Force -Confirm -AllowClobber -Scope CurrentUser
Install-Module Microsoft.Graph -Force -Confirm -AllowClobber -Scope CurrentUser # OPTIONAL
Install-Module MSOnline -Force -Confirm -AllowClobber -Scope CurrentUser        # OPTIONAL
Install-Module AzureADPreview -Force -Confirm -AllowClobber -Scope CurrentUser  # OPTIONAL
Install-Module AADInternals -Force -Confirm -AllowClobber -Scope CurrentUser    # OPTIONAL

Import-Module Az
Import-Module AzureAD
```

Even though only first two modules are required by `AzureRT`, its good to have others pre-installed too.

Then to load this module, simply type:

```
PS> . .\AzureRT.ps1
```

And you're good to go.

Or you can let **AzureRT** to install and import all the dependencies:

```
PS> . .\AzureRT.ps1
PS> Import-ARTModules
```


---

## Batteries Included

The module will be gradually receiving next tools and utilities, naturally categorised onto subsequent kill chain phases. 

Every cmdlet has a nice help message detailing parameters, description and example usage:

```
PS C:\> Get-Help Connect-ART
```

**Currently, following utilities are included:**


### Authentication & Token mechanics 

- **`Get-ARTWhoami`** - Displays _and validates_ our authentication context on `Azure`, `AzureAD`, `Microsoft.Graph` and on `AZ CLI` interfaces.

- **`Connect-ART`** - Invokes `Connect-AzAccount` to authenticate current session to the Azure Portal via provided Access Token or credentials. Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

- **`Connect-ARTAD`** - Invokes `Connect-AzureAD` (and optionally `Connect-MgGraph`) to authenticate current session to the Azure Active Directory via provided Access Token or credentials. Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token.

- **`Connect-ARTADServicePrincipal`** - Invokes `Connect-AzAccount` to authenticate current session to the Azure Portal via provided Access Token or credentials. Skips the burden of providing Tenant ID and Account ID by automatically extracting those from provided Token. Then it creates self-signed PFX certificate and associates it with Service Principal for authentication. Afterwards, authenticates as that Service Principal to AzureAD and deassociates that certificate to cleanup

- **`Get-ARTAccessTokenAzCli`** - Acquires access token from az cli, via `az account get-access-token`

- **`Get-ARTAccessTokenAz`** - Acquires access token from Az module, via `Get-AzAccessToken` .

- **`Get-ARTAccessTokenAzureAD`** - Gets an access token from Azure Active Directory. Authored by [Simon Wahlin, @SimonWahlin ](https://blog.simonw.se/getting-an-access-token-for-azuread-using-powershell-and-device-login-flow/)

- **`Get-ARTAccessTokenAzureADCached`** - Attempts to retrieve locally cached AzureAD access token (https://graph.microsoft.com), stored after `Connect-AzureAD` occurred.

- **`Remove-ARTServicePrincipalKey`** - Performs cleanup actions after running `Connect-ARTADServicePrincipal`


### Recon & Situational Awareness

- **`Get-ARTAccess`** - Performs Azure Situational Awareness.

- **`Get-ARTADAccess`** - Performs Azure AD Situational Awareness.

- **`Get-ARTTenants`** - List Tenants available for the currently authenticated user (or the one based on supplied Access Token)

- **`Get-ARTDangerousPermissions`** - Analyzes accessible Azure Resources and associated permissions user has on them to find all the Dangerous ones that could be abused by an attacker.

- **`Get-ARTResource`** - Authenticates to the https://management.azure.com using provided Access Token and pulls accessible resources and permissions that token Owner have against them.

- **`Get-ARTRoleAssignment`** - Displays a bit easier to read representation of assigned Azure RBAC roles to the currently used Principal.

- **`Get-ARTADRoleAssignment`** - Displays Azure AD Role assignments on a current user or on all Azure AD users.

- **`Get-ARTADScopedRoleAssignment`** - Displays Azure AD Scoped Role assignments on a current user or on all Azure AD users, associated with Administrative Units

- **`Get-ARTRolePermissions`** - Displays all granted permissions on a specified Azure RBAC role.

- **`Get-ARTADRolePermissions`** - Displays all granted permissions on a specified Azure AD role.

- **`Get-ARTADDynamicGroups`** - Displays Azure AD Dynamic Groups along with their user Membership Rules, members count and current user membership status

- **`Get-ARTApplication`** - Lists Azure AD Enterprise Applications that current user is owner of (or all existing when -All used) along with their owners and Service Principals

- **`Get-ARTApplicationProxy`** - Lists Azure AD Enterprise Applications that have Application Proxy setup.

- **`Get-ARTApplicationProxyPrincipals`** - Displays users and groups assigned to the specified Application Proxy application.

- **`Get-ARTStorageAccountKeys`** - Displays all the available Storage Account keys.

- **`Get-ARTKeyVaultSecrets`** - Lists all available Azure Key Vault secrets. This cmdlet assumes that requesting user connected to the Azure AD with KeyVaultAccessToken (scoped to https://vault.azure.net) and has "Key Vault Secrets User" role assigned (or equivalent).

- **`Get-ARTAutomationCredentials`** - Lists all available Azure Automation Account credentials and attempts to pull their values (unable to pull values!).

- **`Get-ARTAutomationRunbookCode`** - Invokes REST API method to pull specified Runbook's source code.

- **`Get-ARTAzVMPublicIP`** - Retrieves Azure VM Public IP address

- **`Get-ARTResourceGroupDeploymentTemplate`** - Displays Resource Group Deployment Template JSON based on input parameters, or pulls all of them at once.

- **`Get-ARTAzVMUserDataFromInside`** - Retrieves Azure VM User Data from inside of a VM by reaching to Instance Metadata endpoint.


### Privilege Escalation

- **`Add-ARTADGuestUser`** - Sends Azure AD Guest user invitation e-mail, allowing to expand access to AAD tenant for the external attacker & returns Invite Redeem URL used to easily accept the invitation.

- **`Set-ARTADUserPassword`** - Abuses `Authentication Administrator` Role Assignment to reset other non-admin users password.

- **`Add-ARTUserToGroup`** - Adds a specified Azure AD User to the specified Azure AD Group.

- **`Add-ARTUserToRole`** - Adds a specified Azure AD User to the specified Azure AD Role.

- **`Add-ARTADAppSecret`** - Add client secret to the Azure AD Applications. Authored by [Nikhil Mittal, @nikhil_mitt](https://twitter.com/nikhil_mitt)


### Lateral Movement

- **`Invoke-ARTAutomationRunbook`** - Creates an Automation Runbook under specified Automation Account and against selected Worker Group. That Runbook will contain Powershell commands to be executed on all the affected Azure VMs.

- **`Invoke-ARTRunCommand`** - Abuses `virtualMachines/runCommand` permission against a specified Azure VM to run custom Powershell command.

- **`Update-ARTAzVMUserData`** - Modifies Azure VM User Data script through a direct API invocation.

- **`Invoke-ARTCustomScriptExtension`** - Creates new or modifies Azure VM Custom Script Extension leading to remote code execution.


### Misc

- **`Get-ARTTenantID`** - Retrieves Current user's Tenant ID or Tenant ID based on Domain name supplied.

- **`Get-ARTPRTToken`** - Retrieves Current user's PRT (Primary Refresh Token) value using [Dirk-Jan Mollema's ROADtoken](https://github.com/dirkjanm/ROADtoken)

- **`Get-ARTPRTNonce`** - Retrieves Current user's PRT (Primary Refresh Token) nonce value

- **`Get-ARTUserId`** - Acquires current user or user specified in parameter ObjectId via `Az` module

- **`Get-ARTSubscriptionId`** - Helper that collects current Subscription ID.

- **`Parse-JWTtokenRT`** - Parses input JWT token and prints it out nicely.

- **`Invoke-ARTGETRequest`** - Takes Access Token and invokes GET REST method API request against a specified URI. It also verifies whether provided token has required audience set.

- **`Import-ARTModules`** - Installs & Imports required & optional Powershell modules for Azure Red Team activities


---

### ☕ Show Support ☕

This and other projects are outcome of sleepless nights and **plenty of hard work**. If you like what I do and appreciate that I always give back to the community,
[Consider buying me a coffee](https://github.com/sponsors/mgeeky) _(or better a beer)_ just to say thank you! 💪 

---

```
Mariusz Banach / mgeeky, (@mariuszbit)
<mb [at] binary-offensive.com>
```
