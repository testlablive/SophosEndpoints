[![Build status](https://ci.appveyor.com/api/projects/status/btgp1wgt0uwmnafl/branch/master?svg=true
)](https://ci.appveyor.com/api/projects/status/btgp1wgt0uwmnafl/branch/master)

# SophosEndpoints

SophosEndpoints is a module to access updated information from the Office 365 IP Address and URL web service. It will create, update, or delete networks and web protection exceptions in Sophos UTM with these data to prioritize Microsoft 365 Urls for better access to the service.

## Creating and maintaining ressources in Sophos UTM

In order to create and maintain the networks and web protection exception in the Sophos UTM you need to create a local user account in the Sophos and create an API key mapped to this user.

```powershell
# This will create networks and an exception for the Office 365 tenant 'testlab'. The results will be logged and saved at C:\Set-EndpointsInUtm.log
Set-EndpointsInUtm -UtmApiUrl "https://sophos.testlab.live:4444/api" -UtmApiKey "kjAHGansdzyPdsYhmILKgOWsh" -TenantName testlab -LogFilePath "C:\Set-EndpointsInUtm.log"
```

If you run the above cmdlet again, it will compare the existing ressources in Sophos UTM and update them.

You can automate this by creating a scheduled task.

For detailed information on how to configure the Sophos UTM and the scheduled task visit [testlab.live/auto-update-sophos-utm-with-microsoft-endpoints](https://www.testlab.live/auto-update-sophos-utm-with-microsoft-endpoints/)

## Initial SophosEndpoints setup

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the SophosEndpoints folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)

    #Simple alternative, if you have PowerShell 5, or the PowerShellGet module:
        Install-Module SophosEndpoints

# Import the module.
    Import-Module SophosEndpoints    # Alternatively, Import-Module \\Path\To\SophosEndpoints
```

