##################################################################################################################
### Global constants
##################################################################################################################

$baseServiceUrl = "https://endpoints.office.com/endpoints/Worldwide/?ClientRequestId={b10c5ed1-bad1-445f-b386-b919946339a7}"
$exceptionUrl = "/objects/http/exception/"
$networkUrl = "/objects/network/network/"
$commentIp = " autocreated on " + (Get-Date).ToString("yyyy-MM-dd")
$commentException = " autocreated on " + (Get-Date).ToString("yyyy-MM-dd")
$tokenBase64 = [Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes("token:" + "dummytoken"))
$log = ""
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

##################################################################################################################
### Functions to interact with sophos
##################################################################################################################

function Add-NetToUtm
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $netToAdd
    )

    $body = $netToAdd | convertto-json -compress
    $response = Invoke-RestMethod -Uri $networkUrl -Method Post -Headers $headers -Body $body | convertto-json
    return (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + " - Adding Net:`r`n" + $response
}

function Get-ExceptionFromUtm
{
    $excList = Invoke-RestMethod -Uri $exceptionUrl -Method Get -Headers $headers

    $exc = $excList | Where-Object {$_.comment -like $UtmExceptionPrefix + '*' -and $_.name -like $UtmExceptionPrefix + '*'}

    return $exc
}

function Get-NetsFromUtm
{
    $utmNetList = Invoke-RestMethod -Uri $networkUrl -Method Get -Headers $headers
    $m365NetList = $utmNetList | Where-Object {$_.comment -like $UtmIpPrefix + '*' -and $_.name -like $UtmIpPrefix + '*'}

    return $m365NetList;
}

function Remove-NetFromUtm
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $netToDelete
    )

    $networkUrlDel = $networkUrl + $netToDelete._ref
    $response = Invoke-RestMethod -Uri $networkUrlDel -Method Delete -Headers $headers | convertto-json
    return (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + " - Deleting Net:`r`n" + $response 
}

function Set-ExceptionInUtm
{
    param(
        [Parameter(Mandatory = $false)]
        [Object[]] $inUtm,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $inWeb
    )

    if($null -eq $inUtm)
    {
        return Set-ExceptionPost -exception $inWeb
    }
    else {
        return Set-ExceptionPatch -inUtm $inUtm -inWeb $inWeb
    }
}

function Set-ExceptionPatch
{
    param(
        [Parameter(Mandatory = $false)]
        [Object[]] $inUtm,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $inWeb
    )

    $exceptionUrlPatch = $exceptionUrl + $inUtm._ref
    $body = $inWeb | convertto-json
    $response = Invoke-RestMethod -Uri $exceptionUrlPatch -Method Patch -Headers $headers -Body $body | convertto-json
    return (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + " - Patching existing Exception:`r`n" + $response
}

function Set-ExceptionPost
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $exception
    )

    $body = $exception | convertto-json -compress
    $response = Invoke-RestMethod -Uri $exceptionUrl -Method Post -Headers $headers -Body $body | convertto-json
    return (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + " - Creating Exception:`r`n" + $response
}

function Set-NetsInUtm
{
    param(
        [Parameter(Mandatory = $false)]
        [Object[]] $inUtm,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $inWeb
    )
    
    if ($null -ne $inUtm)
    {
        $input = [System.Linq.Enumerable]::ToList([psobject[]]$inUtm)
    }
    $difference = [System.Linq.Enumerable]::ToList([psobject[]]$inWeb)
    $diffs = Compare-Object -ReferenceObject $input -DifferenceObject $difference -IncludeEqual -Property @('address', 'netmask') -PassThru
    $toDelete = $diffs | Where-Object {$_.SideIndicator -eq "<="} | Select-Object -Property * -ExcludeProperty SideIndicator
    $toAdd = $diffs | Where-Object {$_.SideIndicator -eq "=>"} | Select-Object -Property * -ExcludeProperty SideIndicator

    foreach($netAdd in $toAdd)
    {
        return Add-NetToUtm -netToAdd $netAdd
        Start-Sleep -Seconds 1
    }
    
    foreach($netDelete in $toDelete)
    {
        return Remove-NetFromUtm -netToDelete $netDelete
        Start-Sleep -Seconds 1
    }
}

function Set-EndpointsInUtm
{
    <#
 
    .SYNOPSIS 
    Set networks and web protection exception in Sophos UTM for Microsoft 365 connectivity
 
    .DESCRIPTION 
    This function will access updated information from the Office 365 IP Address and URL web service.
    It will create, update, or delete networks and web protection exceptions in Sophos UTM with these
    data to prioritize Microsoft 365 Urls for better access to the service.
 
    .PARAMETER Instance 
    The service instance inside Microsoft 365.
 
    .PARAMETER ClientRequestId 
    The client request id to connect to the web service to query up to date Urls.

    .PARAMETER UtmApiUrl
    The URL of the Sophos UTM Api.

    .PARAMETER UtmApiKey
    The Api Key for the Sophos UTM.

    .PARAMETER UtmIpPrefix
    The prefix for naming new networks in the Sophos UTM.

    .PARAMETER UtmExceptionPrefix
    The prefix for naming new exception in the Sophos UTM.

    .PARAMETER UtmExceptionDisabledChecks
    The checks that will be disabled in the web protection exception.
 
    .PARAMETER TenantName 
    The tenant name to replace wildcard Urls in the webservice.
 
    .PARAMETER ServiceAreas 
    The service areas to filter endpoints by in the webservice.
 
    .PARAMETER LogFilePath 
    The file to print the logs to.
    
    .EXAMPLE 
    Set-EndpointsInUtm -UtmApiUrl "https://sophos.testlab.live:4444/api" -UtmApiKey "kjAHGansdzyPdsYhmILKgOWsh" -TenantName testlab -LogFilePath "Set-EndpointsInUtm.log"
    
    .EXAMPLE 
    Set-EndpointsInUtm -ClientRequestId b10c5ed1-bad1-445f-b386-b919946339a7 -UtmIpPrefix "O365 Network" -UtmExceptionPrefix "O365 Exception" -UtmApiUrl "https://sophos.testlab.live:4444/api" -UtmApiKey "kjAHGansdzyPdsYhmILKgOWsh"
 
    .EXAMPLE 
    Set-EndpointsInUtm -UtmApiUrl "https://sophos.testlab.live:4444/api" -UtmApiKey "kjAHGansdzyPdsYhmILKgOWsh" -TenantName testlab -UtmExceptionDisabledChecks @('av', 'cache', 'certcheck', 'certdate', 'check_max_download', 'content_removal', 'contenttype_blacklist', 'extensions', 'log_access', 'log_blocked', 'patience', 'ssl_scanning', 'url_filter', 'user_auth')
    
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Worldwide', 'Germany', 'China', 'USGovDoD', 'USGovGCCHigh')]
        [String] $Instance = "Worldwide",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [guid] $ClientRequestId = [guid]::NewGuid(),

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $UtmApiUrl = "https://sophos:4444/api",

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $UtmApiKey,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String] $UtmIpPrefix = 'Microsoft365 Net',

        [Parameter(Mandatory = $false)]
        [String] $UtmExceptionPrefix = 'Microsoft365 Exception',

        [Parameter(Mandatory = $false)]
        [ValidateSet('av', 'cache', 'certcheck', 'certdate', 'check_max_download', 'content_removal', 'contenttype_blacklist', 'extensions', 'log_access', 'log_blocked', 'patience', 'ssl_scanning', 'url_filter', 'user_auth')]
        [string[]] $UtmExceptionDisabledChecks = @('ssl_scanning', 'user_auth'),

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $TenantName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Exchange', 'Skype', 'SharePoint', 'Common')]
        [string[]] $ServiceAreas,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $LogFilePath
    )

    # Update constants
    $script:baseServiceUrl = "https://endpoints.office.com/endpoints/$Instance/?ClientRequestId={$ClientRequestId}"
    $script:exceptionUrl = $UtmApiUrl + "/objects/http/exception/"
    $script:networkUrl = $UtmApiUrl + "/objects/network/network/"
    $script:commentIp = $UtmIpPrefix + " autocreated on " + (Get-Date).ToString("yyyy-MM-dd")
    $script:commentException = $UtmExceptionPrefix + " autocreated on " + (Get-Date).ToString("yyyy-MM-dd")
    $script:tokenBase64 = [Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes("token:" + $UtmApiKey))
    $script:log = ""

    $script:headers.add("Accept", "application/json")
    $script:headers.add("Content-Type", "application/json")
    $script:headers.add("X-Restd-Err-Ack", "all")
    $script:headers.add("Authorization","Basic " + $tokenBase64)

    # Retrieve the list of nets from sophos
    $netsSophos = Get-NetsFromUtm

    # Retrieve the list of nets from web
    $endpoints = Get-Content -Raw -Path endpoints.json | ConvertFrom-Json
    $ips = Get-Ips $endpoints
    $netsWeb = Get-NetsFromWeb $ips | convertto-json | convertfrom-json

    # Update nets in sophos
    if ($null -eq $netsSophos)
    {
        $log += Set-NetsInUtm -inWeb $netsWeb
    }
    else
    {
        $log += Set-NetsInUtm -inUtm $netsSophos -inWeb $netsWeb
    }

    # Retrieve web protection exception from sophos
    $excSophos = Get-ExceptionFromUtm

    # Retrieve host list from web
    $excWeb = Get-ExceptionFromWeb $endpoints

    # Update web protection exception in sophos
    if ($null -eq $excSophos)
    {
        $log += Set-ExceptionInUtm -inWeb $excWeb
    }
    else
    {
        $log += Set-ExceptionInUtm -inUtm $excSophos -inWeb $excWeb
    }

    # Write Logfile
    if ($LogFilePath)
    {
        $log | Out-File -FilePath $LogFilePath -Append -Encoding ascii
    }
}

##################################################################################################################
### Functions to get and filter endpoints
##################################################################################################################

function Get-Endpoints
{
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Worldwide', 'Germany', 'China', 'USGovDoD', 'USGovGCCHigh')]
        [String] $Instance = "Worldwide",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [guid] $ClientRequestId = [guid]::NewGuid()
    )

    $baseServiceUrl = "https://endpoints.office.com/endpoints/$Instance/?ClientRequestId={$ClientRequestId}"
    $url = $baseServiceUrl
    if ($TenantName)
    {
        $url += "&TenantName=$TenantName"
    }
    if ($ServiceAreas)
    {
        $url += "&ServiceAreas=" + ($ServiceAreas -Join ",")
    }
    return Invoke-RestMethod -Uri $url
}

function Get-ExceptionFromWeb
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [psobject[]] $endpoints
    )
    $urls = Get-Urls $endpoints
    
    $domains = @()
    foreach($url in $urls)
    {
        $domains = $domains += Get-Regex $url
    }

    $exception = [ordered]@{aaa = @();
        comment = $commentException;
        domains = $domains;
        endpoints_groups = @();
        name = $UtmExceptionPrefix + " - All Hosts";
        networks = @();
        operator = "AND";
        skiplist = $UtmExceptionDisabledChecks;
        sp_categories = @();
        status = $true;
        tags = @();
        user_agents = @()}

    return $exception
}

function Get-Ips
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [psobject[]] $endpoints
    )

    return $endpoints | Where-Object { $_.category -in @("Optimize", "Allow")} | Where-Object { $_.ips } | ForEach-Object { $_.ips } | Sort-Object -Unique
}

function Get-NetsFromWeb
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [psobject[]] $ips
    )

    $nets = @()
    foreach($ip in $ips)
    {
        if ($ip -match "\.")
        {
            $address = $ip.split('/')[0]
            $netmask = $ip.split('/')[1]

            $nets = $nets += [ordered]@{address = $address;
                address6 = "";
                comment = $commentIp;
                interface = "";
                name = $UtmIpPrefix + " - " + $address;
                netmask = $netmask;
                netmask6 = 0;
                resolved = $true;
                resolved6 = $false}
        }
    }

    return $nets
}

function Get-Regex
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Fqdn
    )

    return "^https?://" + $Fqdn.Replace(".", "\.").Replace("*", "[A-Za-z0-9.-]*")
}

function Get-Urls
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [psobject[]] $endpoints
    )

    return $endpoints | Where-Object { $_.category -in @("Optimize", "Allow")} | Where-Object { $_.urls } | ForEach-Object { $_.urls } | Sort-Object -Unique
}

##################################################################################################################
### Initialize connection
##################################################################################################################

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Might be needed to resolve 'could not establish trust relationship for the SSL/TLS secure channel' errors
# when attempting to authenticate to the UTM
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
        if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                delegate
                (
                Object obj,
                X509Certificate certificate,
                X509Chain chain,
                SslPolicyErrors errors
                )
                {
                    return true;
                };
            }
        }
    }
"@
Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Ignore()

# Sets the TLS level to match sophos
$AllProtocols = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols