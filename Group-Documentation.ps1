<#
.SYNOPSIS
GCD - Group Centric Documentation will create a summary of assignments to entra groups.

.DESCRIPTION
ATTENTION: This is a v1.0 script. As such, bugs should be expected, please report them to me via GitHub or X (aka Twitter).

This script was made, because Intune is missing a crucial point of view right now. Its impossible to figure out, what exactly is assigned to a group!
For more details visit https://manima.de/2023/10/group-centric-documentation-for-intune-part-1

.PARAMETER WorkingDirectory
Provide a folder that will be used as work directory. This will also be the output folder for any files.

.PARAMETER LogDirectory
Provide a folder where log files will be put. 
ATTENTION: No error handling is currently implemented, so no logs to write just yet!

.PARAMETER TenantAPIToUse
This can either be '/v1.0' or '/beta' - by default the script will use beta, as some assignments are not yet available in v1.0.
ATTENTION: You should never have to change this, because /v1.0 does not contain each request used.

.PARAMETER CertificateThumbprint
Currently this script only supports the usage of certificates to connect to graph. Please provide the thumbprint of the certificate used.

.PARAMETER ClientID
Currently this script only supports the usage of a custom app registration. Please provide the client ID of the app registration.

.PARAMETER TenantID
Provide the tenant ID.

.PARAMETER MultiFileResult
Switch that lets you decide if the output should be one file or multiple files.
ATTENTION: This will use the group name as filename. Thus, the filename needs to be sanitized and might miss crucial letters.

.PARAMETER ConvertToMermaid
Not implemented yet!

.EXAMPLE
Group-Documentation.ps1 -CertificateThumbprint 'afb945e0d88e2b1f70b8ffa501144f3a5cef8dee' -ClientID '22bcb6ed-c278-443a-aa17-01e9f478318d' -TenantID 'd73eed9c-6ef6-45dc-9813-0061b0b8730d' -MultiFileResult
This would connect to graph using the provided parameters. The output would create multiple JSON files, one for each group, containing found assignments.

.EXAMPLE
Connect-MgGraph -Scopes DeviceManagementApps.Read.All,DeviceManagementConfiguration.Read.All,DeviceManagementServiceConfig.Read.All,Group.Read.All
.\Group-Documentation.ps1 -WorkingDirectory C:\temp\ -LogDirectory C:\temp\logs -TenantAPIToUse "/v1.0"
This would connect to the Graph API frist using the v1.0 interface and the minimum scopes required forthis script to run. 
This is useful, if you didn't set up your own application but instead rely on the Microsoft Graph Command Line Tools.

.NOTES
    Version: 1.0
    Versionname: F.O.C.U.S.
    Intial creation date: 18.08.2023
    Last change date: 31.10.2023
    Latest changes: https://github.com/MHimken/GroupCentricDocumentation/blob/master/README.md

    Currently being worked on (aka TODO):
        * Add more information about groups
            * Membership count (https://graph.microsoft.com/beta/groups/5e8cb718-fb72-4ef0-9e0d-3e43d232780f/transitiveMembers/$count)
            * Creation Date
        * Make visualization happen using Mermaid
        * Improve error reporting
        * Handle Error in Line 222 (Get-MgGroup) to accomodate for the group not existing anymore (catch the error)
        ... more at my blog!
#>
[CmdletBinding()]
param(
    [System.IO.DirectoryInfo]$WorkingDirectory = 'C:\GroupDocumentation\',
    [System.IO.DirectoryInfo]$LogDirectory = "$WorkingDirectory\Logs\",
    [string]$TenantAPIToUse = '/beta',
    [string]$CertificateThumbprint,
    [string]$ClientID,
    [string]$TenantID,
    [switch]$MultiFileResult,
    [switch]$ConvertToMermaid
)
#Prepare folders and files
$Script:TimeStampStart = Get-Date
$Script:DateTime = Get-Date -Format ddMMyyyy_hhmmss
if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
$LogPrefix = 'GCD_'
$LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $DateTime)

$Script:PathToScript = if ( $PSScriptRoot ) { 
    # Console or VS Code debug/run button/F5 temp console
    $PSScriptRoot 
} else {
    if ( $psISE ) { Split-Path -Path $psISE.CurrentFile.FullPath }
    else {
        if ($profile -match 'VScode') { 
            # VS Code "Run Code Selection" button/F8 in integrated console
            Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
        } else { 
            Write-Output 'unknown directory to set path variable. exiting script.'
            exit
        } 
    } 
}

#Prepare arraylists - these are needed to multiple purposes
$Script:ResultArray = [System.Collections.ArrayList]::new()
$Script:GroupCache = [System.Collections.ArrayList]::new()
$Script:Filters = [System.Collections.ArrayList]::new()
$Script:StaticObjects = [System.Collections.ArrayList]::new()
$Script:BatchRequests = [System.Collections.ArrayList]::new()
$Script:BatchRequestsAnalyze = [System.Collections.ArrayList]::new()

$CurrentLocation = Get-Location
Set-Location $Script:PathToScript
function Write-Log {
    <#
    .DESCRIPTION
        This is a modified version of Ryan Ephgrave's script
    .LINK
        https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')][int]$Type
    )
    $Time = Get-Date -Format 'HH:mm:ss.ffffff'
    $Date = Get-Date -Format 'MM-dd-yyyy'
    if (-not($Component)) { $Component = 'Runner' }
    if (-not($Type)) { $Type = 1 }
    $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
    if ($Verbose) {
        switch ($Type) {
            1 { Write-Host $Message }
            2 { Write-Warning $Message }
            3 { Write-Error $Message }
            default { Write-Host $Message }
        }        
    }
}
function Get-nextLinkData {
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $nextLink = ''
        $nextLink = $Request.'@odata.nextLink'
    }
    return $Results
}
function Add-BatchRequestObjectToQueue {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body
    )
    $ID = $Script:BatchRequests.count
    $BatchObject = [PSCustomObject]@{
        id      = $ID
        method  = $Method
        URL     = $URL
        headers = $Headers
        body    = $Body
    }
    $Script:BatchRequests.add($BatchObject) | Out-Null
}
function Invoke-BatchRequest {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body,
        [switch]$SendNow
    )
    Add-BatchRequestObjectToQueue -Method $method -URL $URL -Headers $Headers -Body $Body
    if ($Script:BatchRequests.count -eq 20 -or $SendNow) {
        $BatchRequestBody = [PSCustomObject]@{requests = $Script:BatchRequests }
        $JSONRequests = $BatchRequestBody | ConvertTo-Json -Depth 10        
        $Results = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $JSONRequests -ContentType 'application/json' -ErrorAction Stop
        $Script:BatchRequestsAnalyze = $Script:BatchRequests
        $Script:BatchRequests = [System.Collections.ArrayList]::new()
    }
    return $Results
}
function Add-NewFilterToCache {
    param(
        [string]$FilterID,
        [string]$FilterName
    )
    $Script:Filters.add([PSCustomObject]@{
            FilterID   = $FilterID
            Filtername = $FilterName
        }) | Out-Null
}
function Add-NewGroupToResults {
    param(
        [string]$GroupID,
        [string]$GroupName
    )
    $Script:ResultArray.add([PSCustomObject]@{
            GroupID     = $GroupID
            DisplayName = $GroupName
            Assignments = [System.Collections.ArrayList]@{}
        }) | Out-Null
}
function Register-GroupInResults {
    param (
        [string]$GroupID,
        [string]$OdataType
    )
    if ($OdataType) {
        switch ($OdataType) {
            "#microsoft.graph.allLicensedUsersAssignmentTarget" { $GroupName = 'All users'; $GroupID = 'acacacac-9df4-4c7d-9d50-4ef0226f57a9' }
            "#microsoft.graph.allDevicesAssignmentTarget" { $GroupName = 'All devices'; $GroupID = 'adadadad-808e-44e2-905a-0b7873a8a531' }
        }
        $GroupIDToReturn = $GroupID
    }
    if ($GroupID -notin $Script:ResultArray.GroupID) {
        if ($GroupID) {
            $GroupName = ($Script:GroupCache | Where-Object { $_.GroupID -eq $GroupID }).GroupName
        }
        if (-not($GroupName)) {
            $GroupName = (Get-MgGroup -GroupId ($GroupID)).DisplayName
        }
        Add-NewGroupToResults -GroupID $GroupID -GroupName $GroupName
    }
    return $GroupIDToReturn
}
function Find-FilterInCache {
    param (
        [string]$FilterID
    )
    $FilterName = ($Script:Filters | Where-Object { $_.FilterID -eq $FilterID }).FilterName
    if (-not($FilterName)) {
        $FilterName = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$FilterID/?`$select=displayName,id").displayname
        Add-NewFilterToCache -FilterID $FilterID -FilterName $FilterName
    }
    return $FilterName
}
function Add-NewObjectToGroupInResults {
    param(
        $GroupID,
        $ObjectName,
        $ObjectType,
        $ObjectID,
        $AssignmentIntent,
        $GroupModeOData,
        $GroupMode,
        $FilterIntent,
        $FilterID,
        $OdataType
    )
    if (-not($OdataType)) {
        Register-GroupInResults -GroupID $GroupID
    } else {
        $GroupID = Register-GroupInResults -OdataType $OdataType
    }
    if (-not($FilterID -eq '00000000-0000-0000-0000-000000000000')) {
        $FilterName = if ($FilterID) { Find-FilterInCache -FilterID $FilterID }
    } else {
        $FilterID = $null
    }
    $GroupMode = if ($GroupModeOData) { Get-GroupMode -GroupMode $GroupModeOData }
    ($Script:ResultArray | Where-Object { $_.GroupID -eq $GroupID }).Assignments.add([PSCustomObject]@{
            ObjectName       = $ObjectName
            ObjectType       = $ObjectType
            ObjectID         = $ObjectID
            AssignmentIntent = $AssignmentIntent
            GroupMode        = $GroupMode
            FilterIntent     = $FilterIntent
            FilterID         = $FilterID
            FilterName       = $FilterName
        }
    ) | Out-Null
}
function Initialize-Data {
    <#
    .NOTES
    * Adds static group with ID to the result array (All Users and All Devices)
    * Adds all groups with IDs to a local cache (this runs very quick even with thousands of groups it shouldn't be an issue)
    * Adds all currently available filters to filter cache (because there's a maximum of 200, this shouldn't impact perfomance)
    * Add static default deviceEnrollmentConfigurations to a cache
    #>
    Add-NewGroupToResults -GroupID 'acacacac-9df4-4c7d-9d50-4ef0226f57a9' -GroupName 'All users'
    Add-NewGroupToResults -GroupID 'adadadad-808e-44e2-905a-0b7873a8a531' -GroupName 'All devices'
    $groupsAll = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/groups/?$select=id,displayName,createdDateTime&$top=999'
    if ($groupsAll.'@odata.nextLink') {
        $groupsAll = Get-nextLinkData -OriginalObject $groupsAll
    }
    $groupsAll.value | ForEach-Object { $Script:GroupCache.add([PSCustomObject]@{
                GroupID         = $_.id
                GroupName       = $_.displayName
                CreatedDateTime = $_.createdDateTime
            }
        ) | Out-Null
    }
    (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$FilterID/?`$select=displayName,id").value | ForEach-Object {
        Add-NewFilterToCache -FilterID $_.id -FilterName $_.displayName
    }
    $Script:StaticObjects.add([PSCustomObject]@{
            Identifier = '#microsoft.graph.deviceEnrollmentLimitConfiguration'
            ObjectName = 'Default Enrollment Limit Configuration'
            GroupName  = 'All devices'
            GroupID    = 'adadadad-808e-44e2-905a-0b7873a8a531'
        }) | Out-Null
    $Script:StaticObjects.add([PSCustomObject]@{
            Identifier = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'
            ObjectName = 'Default Platform Restriction Configuration'
            GroupName  = 'All devices'
            GroupID    = 'adadadad-808e-44e2-905a-0b7873a8a531'
        }) | Out-Null
    $Script:StaticObjects.add([PSCustomObject]@{
            Identifier = '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration'
            ObjectName = 'Default Hello for Business Configuration'
            GroupName  = 'All devices'
            GroupID    = 'adadadad-808e-44e2-905a-0b7873a8a531'
        }) | Out-Null
    $Script:StaticObjects.add([PSCustomObject]@{
            Identifier = '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration'
            ObjectName = 'Default Enrollment Status Page'
            GroupName  = 'All devices'
            GroupID    = 'adadadad-808e-44e2-905a-0b7873a8a531'
        }) | Out-Null

}
function Convert-ObjectTypesMermaid {
    param(
        [string]$ObjectType
    )
    switch ($ObjectType) {
        '#microsoft.graph.androidManagedAppProtection' { $Result = "Apps" }
        '#microsoft.graph.configurationPolicies' { $Result = "Configuration" }
        '#microsoft.graph.deviceCompliancePolicy' { $Result = "Compliance" }
        '#microsoft.graph.deviceEnrollmentLimitConfiguration' { $Result = "Other" }
        '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration' { $Result = "Other" }
        '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration' { $Result = "Other" }
        '#microsoft.graph.deviceHealthScript' { $Result = "Scripts" }
        '#microsoft.graph.deviceManagementScript' { $Result = "" }
        '#microsoft.graph.iosManagedAppProtection' { $Result = "" }
        '#microsoft.graph.iosMobileAppConfiguration' { $Result = "" }
        '#microsoft.graph.iosTrustedRootCertificate' { $Result = "" }
        '#microsoft.graph.iosVppApp' { $Result = "Apps" }
        '#microsoft.graph.macOSCompliancePolicy' { $Result = "" }
        '#microsoft.graph.macOSDeviceFeaturesConfiguration' { $Result = "" }
        '#microsoft.graph.macOSEndpointProtectionConfiguration' { $Result = "" }
        '#microsoft.graph.macOSGeneralDeviceConfiguration' { $Result = "" }
        '#microsoft.graph.macOSLobApp' { $Result = "" }
        '#microsoft.graph.macOSMicrosoftEdgeApp' { $Result = "" }
        '#microsoft.graph.macOSOfficeSuiteApp' { $Result = "" }
        '#microsoft.graph.macOSSoftwareUpdateConfiguration' { $Result = "" }
        '#microsoft.graph.macOsVppApp' { $Result = "" }
        '#microsoft.graph.mdmWindowsInformationProtectionPolicy' { $Result = "" }
        '#microsoft.graph.officeSuiteApp' { $Result = "Apps" }
        '#microsoft.graph.targetedManagedAppConfiguration' { $Result = "" }
        '#microsoft.graph.win32LobApp' { $Result = "Apps" }
        '#microsoft.graph.windows10CompliancePolicy' { $Result = "" }
        '#microsoft.graph.windows10CustomConfiguration' { $Result = "" }
        '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration' { $Result = "" }
        '#microsoft.graph.windows10GeneralConfiguration' { $Result = "" }
        '#microsoft.graph.windows10PkcsCertificateProfile' { $Result = "" }
        '#microsoft.graph.windows81TrustedRootCertificate' { $Result = "" }
        '#microsoft.graph.windowsDomainJoinConfiguration' { $Result = "" }
        '#microsoft.graph.windowsDriverUpdateProfiles' { $Result = "" }
        '#microsoft.graph.windowsHealthMonitoringConfiguration' { $Result = "" }
        '#microsoft.graph.windowsIdentityProtectionConfiguration' { $Result = "" }
        '#microsoft.graph.windowsManagedAppProtection' { $Result = "Other" }
        '#microsoft.graph.windowsMicrosoftEdgeApp' { $Result = "Apps" }
        '#microsoft.graph.windowsUpdateForBusinessConfiguration' { $Result = "Configuration" }
        '#microsoft.graph.winGetApp' { $Result = "Apps" }
        default { $Result = $false }
    }
    return $Result
}
function Test-BaselineTemplate {
    <#
    .NOTES
    The Apps for Enterprise and Edge Baseline aren't actually a baselines, but are created as configurationPolicy and will therefore be caught 
    somewhere else. 'Intents' are not just security baselines. They're basically everything that could be called "template". BitLocker and 
    imported firewall rules are such an example.
    #>
    param(
        $templateID
    )
    switch ($templateID) {
        "034ccd46-190c-4afc-adf1-ad7cc11262eb" { $Result = @{exists = $true; ObjectType = "SecurityBaseline" } }
        "4356d05c-a4ab-4a07-9ece-739f7c792910" { $Result = @{exists = $true; ObjectType = "ImportedFirewallRule" } }
        "d1174162-1dd2-4976-affc-6667049ab0ae" { $Result = @{exists = $true; ObjectType = "BitLockerOld" } }
        "2209e067-9c8c-462e-9981-5a8c79165dcc" { $Result = @{exists = $true; ObjectType = "DefenderForEndpoint" } }
        "cef15778-c3b9-4d53-a00a-042929f0aad0" { $Result = @{exists = $true; ObjectType = "W365Security" } }
        #"" { $Result = @{exists = $true; name = "BitLockerTemplateOld" } }
        default { $Result = @{exists = $false; ObjectType = "" } }
    }
    return $Result
}
function Get-GroupMode {
    <#
    .NOTES
    These are the currently known GroupMode Types.
    All Users and All Devices cannot be excluded and should not exist
    #>
    param(
        $GroupMode
    )
    switch ($GroupMode) {
        "#microsoft.graph.groupAssignmentTarget" { return [string]"Included" }
        "#microsoft.graph.allLicensedUsersAssignmentTarget" { return [string]"Included" }
        "#microsoft.graph.allDevicesAssignmentTarget" { return [string]"Included" }
        "#microsoft.graph.exclusionGroupAssignmentTarget" { return [string]"Excluded" }
        default { return $false }
    }
}
#Get content functions
function Get-AppRelations {
    <#
    .NOTES
    Apps can includes filters, but not necessarily
    #>
    $AllApps = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceAppManagement/mobileApps/?`$top=999&`$select=displayname,id&`$filter=isassigned eq true&`$expand=assignments(`$select=id,intent,target)"
    $AllApps = Get-nextLinkData -OriginalObject $AllApps
    #Add apps to ResultArray
    foreach ($App in $AllApps.value) {
        if (-not($App.assignments)) {
            #Write-Log!
            continue
        }
        foreach ($Assignment in $App.assignments) {
            $params = @{
                GroupID          = $Assignment.target.groupId
                ObjectName       = $App.DisplayName
                ObjectType       = $App.'@odata.type'
                ObjectID         = $App.id
                AssignmentIntent = $Assignment.Intent
                GroupModeOData   = $Assignment.target.'@odata.type'
                FilterIntent     = $Assignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID         = $Assignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($Assignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $Assignment.target.'@odata.type'
            }
        }
    }
}
function Get-DeviceEnrollmentConfigurationRelations {
    $DefaultAssignmentCounter = 0
    $AllDeviceEnrollmentConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/deviceEnrollmentConfigurations/?`$select=displayname,id&`$top=999&`$expand=assignments"
    $AllDeviceEnrollmentConfiguration = Get-nextLinkData -OriginalObject $AllDeviceEnrollmentConfiguration
    foreach ($DeviceEnrollmentConfiguration in $AllDeviceEnrollmentConfiguration.value) {
        #TODO maybe parallelize this for speed
        #$DeviceEnrollmentAssignments = 
        if (-not($DeviceEnrollmentConfiguration.assignments)) {
            #Write-Log!
            continue
        }
        if ($DeviceEnrollmentConfiguration.DisplayName -eq 'All users and all devices') {
            $ObjectName = ($Script:StaticObjects | Where-Object { $_.Identifier -eq $DeviceEnrollmentConfiguration.'@odata.type' }).ObjectName
        } else {
            $ObjectName = $DeviceEnrollmentConfiguration.DisplayName
        }
        foreach ($DeviceEnrollmentAssignment in $DeviceEnrollmentConfiguration.assignments) {
            $params = @{
                GroupID        = $DeviceEnrollmentAssignment.target.groupId
                ObjectName     = $ObjectName
                ObjectType     = $DeviceEnrollmentConfiguration.'@odata.type'
                ObjectID       = $DeviceEnrollmentConfiguration.id
                GroupModeOData = $DeviceEnrollmentAssignment.target.'@odata.type'#'Included' #This is fixed and cannot be changed
                FilterIntent   = $DeviceEnrollmentAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $DeviceEnrollmentAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($DeviceEnrollmentAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $DeviceEnrollmentAssignment.target.'@odata.type'
            }
        }
        
    }
    if ($DefaultAssignmentCounter -ge 5) {
        Write-Log -Message 'This component exceeded the expected four default DeviceEnrollmentConfigurations! Please contact the author of this script with this info!' -Component 'DeviceEnrollmentConfigurationRelations' -Type 2
    }
    <# Enrollment
    https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations
    Relevante Informationen
    id
    displayName
    Typ - siehe:    
    #microsoft.graph.deviceEnrollmentLimitConfiguration
    #microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration
    #microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration
    #microsoft.graph.windows10EnrollmentCompletionPageConfiguration
    https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/0e0b9342-8bef-463c-a42b-ff781f8b56d0_Windows10EnrollmentCompletionPageConfiguration/assignments
    #microsoft.graph.deviceComanagementAuthorityConfiguration
    #>
}
function Get-DeviceConfigurationRelations {
    <#
    .NOTES
    We need to add something to handle filters, excludes
    filters should be part of the target property
    #>
    $AllDeviceConfiguration = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/deviceConfigurations/?`$select=displayname,id&`$top=999&`$expand=assignments"
    $AllDeviceConfiguration = Get-nextLinkData -OriginalObject $AllDeviceConfiguration
    foreach ($DeviceConfiguration in $AllDeviceConfiguration.value) {  
        if (-not($DeviceConfiguration.assignments)) {
            #Write-Log!
            continue
        }
        foreach ($DeviceConfigurationAssignment in $DeviceConfiguration.assignments) {
            $params = @{
                GroupID          = $DeviceConfigurationAssignment.target.groupId
                ObjectName       = $DeviceConfiguration.DisplayName
                ObjectType       = $DeviceConfiguration.'@odata.type'
                ObjectID         = $DeviceConfiguration.id
                AssignmentIntent = $DeviceConfigurationAssignment.Intent
                GroupModeOData   = $DeviceConfigurationAssignment.target.'@odata.type'
                FilterIntent     = $DeviceConfigurationAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID         = $DeviceConfigurationAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($DeviceConfigurationAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $DeviceConfigurationAssignment.target.'@odata.type'
            }            
        }
    }

    <# Device
    https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/691c1591-52f2-45bd-aa02-c6f0714d02cf/assignments
    Relevante Informationen
    id
    displayName
    Typ - siehe:
    #microsoft.graph.windowsUpdateForBusinessConfiguration
    #microsoft.graph.iosTrustedRootCertificate
    #microsoft.graph.iosUpdateConfiguration
    #microsoft.graph.macOSDeviceFeaturesConfiguration
    #microsoft.graph.macOSGeneralDeviceConfiguration
    #microsoft.graph.macOSEndpointProtectionConfiguration
    #microsoft.graph.macOSSoftwareUpdateConfiguration
    #microsoft.graph.windowsDomainJoinConfiguration
    #microsoft.graph.windowsHealthMonitoringConfiguration
    #microsoft.graph.windows10CustomConfiguration
    #microsoft.graph.windows81TrustedRootCertificate
    #microsoft.graph.windowsIdentityProtectionConfiguration
    #microsoft.graph.windows10CustomConfiguration
    #microsoft.graph.windows10PkcsCertificateProfile
    #microsoft.graph.windows10GeneralConfiguration
    #microsoft.graph.windowsUpdateForBusinessConfiguration
    #microsoft.graph.windowsUpdateForBusinessConfiguration
    #microsoft.graph.windows10CustomConfiguration
    #microsoft.graph.windows10GeneralConfiguration
    #microsoft.graph.windows10EndpointProtectionConfiguration
    #microsoft.graph.windows81SCEPCertificateProfile
    #microsoft.graph.windows10VpnConfiguration
    #>
}
function Get-ScriptRelations {
    $AllScripts = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/deviceManagementScripts/?`$select=displayname,id&`$top=999&`$expand=assignments"
    $AllScripts = Get-nextLinkData -OriginalObject $AllScripts
    foreach ($Script in $AllScripts.value) {
        if (-not($Script.assignments)) {
            continue
        }
        foreach ($ScriptAssignment in $Script.assignments) {
            $params = @{
                GroupID        = $ScriptAssignment.target.groupId
                ObjectName     = $Script.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-shared-devicemanagementscript-create?view=graph-rest-beta#request
                ObjectType     = '#microsoft.graph.deviceManagementScript' 
                ObjectID       = $Script.id
                GroupModeOData = $ScriptAssignment.target.'@odata.type'
                FilterIntent   = $ScriptAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $ScriptAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($ScriptAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $ScriptAssignment.target.'@odata.type'
            }
        }
    }
    #https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts
    #https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/893a7230-e904-4bd1-a757-1d1db25a0eda/assignments
}
function Get-Remediations {
    $AllRemediations = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/deviceHealthScripts/?`$select=displayname,id&`$top=999&`$expand=assignments"
    foreach ($Remediation in $AllRemediations.value) {
        if (-not($Remediation.assignments)) {
            continue
        }
        foreach ($RemediationAssignment in $Remediation.assignments) {
            $params = @{
                GroupID        = $RemediationAssignment.target.groupId
                ObjectName     = $Remediation.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-devicehealthscript?view=graph-rest-beta
                ObjectType     = '#microsoft.graph.deviceHealthScript' 
                ObjectID       = $Remediation.id
                GroupModeOData = $RemediationAssignment.target.'@odata.type'
                FilterIntent   = $RemediationAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $RemediationAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($RemediationAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $RemediationAssignment.target.'@odata.type'
            }
        }
    }
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts
    #https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/02a4e7e8-195a-4824-8044-08b3a7f2d555/assignments    
}
function Get-DeviceComplianceRelations {
    $AllDeviceCompliancePolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/deviceCompliancePolicies/?`$select=displayname,id&`$top=999&`$expand=assignments"
    $AllDeviceCompliancePolicies = Get-nextLinkData -OriginalObject $AllDeviceCompliancePolicies
    foreach ($DeviceCompliancePolicy in $AllDeviceCompliancePolicies.value) {
        if (-not($DeviceCompliancePolicy.assignments)) {
            continue
        }
        foreach ($DeviceCompliancePolicyAssignment in $DeviceCompliancePolicy.assignments) {
            $params = @{
                GroupID        = $DeviceCompliancePolicyAssignment.target.groupId
                ObjectName     = $DeviceCompliancePolicy.displayName
                ObjectType     = $DeviceCompliancePolicy.'@odata.type'
                ObjectID       = $DeviceCompliancePolicy.id
                GroupModeOData = $DeviceCompliancePolicyAssignment.target.'@odata.type'
                FilterIntent   = $DeviceCompliancePolicyAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $DeviceCompliancePolicyAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($DeviceCompliancePolicyAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $DeviceCompliancePolicyAssignment.target.'@odata.type'
            }
        }
    }
    #https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies
    #https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/b800eaad-28b7-466e-a261-58f0ae66a43c/assignments 
}
function Get-ComplianceRelations {
    $AllCompliancePolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/compliancePolicies/?`$select=name,id&`top=999&`$expand=assignments"
    $AllCompliancePolicies = Get-nextLinkData -OriginalObject $AllCompliancePolicies
    foreach ($CompliancePolicy in $AllCompliancePolicies.value) {
        if (-not($CompliancePolicy.assignments)) {
            continue
        }
        foreach ($CompliancePolicyAssignment in $CompliancePolicy.assignments) {
            $params = @{
                GroupID        = $CompliancePolicyAssignment.target.groupId
                ObjectName     = $CompliancePolicy.name
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0&viewFallbackFrom=graph-rest-beta&tabs=powershell
                ObjectType     = '#microsoft.graph.deviceCompliancePolicy'
                ObjectID       = $CompliancePolicy.id
                GroupModeOData = $CompliancePolicyAssignment.target.'@odata.type'
                FilterIntent   = $CompliancePolicyAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $CompliancePolicyAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($CompliancePolicyAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $CompliancePolicyAssignment.target.'@odata.type'
            }
        }
    }
    #https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies
    #https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/b800eaad-28b7-466e-a261-58f0ae66a43c/assignments 
}
function Get-DriverUpdateRelations {
    <#
    .NOTES
    These are limited to 200 results.
    #>
    $AllDriverUpdatePolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/windowsDriverUpdateProfiles/?`$select=displayname,id&`$top=200&`$expand=assignments"
    $AllDriverUpdatePolicies = Get-nextLinkData -OriginalObject $AllDriverUpdatePolicies
    foreach ($DriverUpdatePolicy in $AllDriverUpdatePolicies.value) {
        if (-not($DriverUpdatePolicy.assignments)) {
            continue
        }
        foreach ($DriverUpdatePolicyAssignment in $DriverUpdatePolicy.assignments) {
            $params = @{
                GroupID        = $DriverUpdatePolicyAssignment.target.groupId
                ObjectName     = $DriverUpdatePolicy.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-softwareupdate-windowsdriverupdateprofile-list?view=graph-rest-beta
                ObjectType     = '#microsoft.graph.windowsDriverUpdateProfiles'
                ObjectID       = $DriverUpdatePolicy.id
                GroupModeOData = $DriverUpdatePolicyAssignment.target.'@odata.type'
                FilterIntent   = $DriverUpdatePolicyAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $DriverUpdatePolicyAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($DriverUpdatePolicyAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $DriverUpdatePolicyAssignment.target.'@odata.type'
            }
        }
    }
}
function Get-FeatureUpdateRelations {
    $AllFeatureUpdatePolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/windowsFeatureUpdateProfiles/?`$select=displayname,id&`$expand=assignments"
    $AllFeatureUpdatePolicies = Get-nextLinkData -OriginalObject $AllFeatureUpdatePolicies
    foreach ($FeatureUpdatePolicy in $AllFeatureUpdatePolicies.value) {
        if (-not($FeatureUpdatePolicy.assignments)) {
            continue
        }
        foreach ($FeatureUpdatePolicyAssignment in $FeatureUpdatePolicy.assignments) {
            $params = @{
                GroupID        = $FeatureUpdatePolicyAssignment.target.groupId
                ObjectName     = $FeatureUpdatePolicy.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0&viewFallbackFrom=graph-rest-beta&tabs=powershell
                ObjectType     = '#microsoft.graph.deviceCompliancePolicy'
                ObjectID       = $FeatureUpdatePolicy.id
                GroupModeOData = $FeatureUpdatePolicyAssignment.target.'@odata.type'
                FilterIntent   = $FeatureUpdatePolicyAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $FeatureUpdatePolicyAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($FeatureUpdatePolicyAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $FeatureUpdatePolicyAssignment.target.'@odata.type'
            }
        }
    }    
}
function Get-IntentRelations {
    <#
    .NOTES
    This is slow if there are many baselines, because we need to catch the assignments - once for each "intent" aka baseline
    This should also catch disk encryption policies that are old.
    #>
    $AllIntents = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/intents/?`$select=id,displayName,templateId&`$top=999&`$filter=isAssigned eq true"
    $AllIntents = Get-nextLinkData -OriginalObject $AllIntents
    for ($i = 0; $i -lt $AllIntents.value.count; $i++) {
        #This function is a check for known template types and will return the object types accordingly along with it
        if (-not($(Test-BaselineTemplate -templateID $AllIntents.value[$i].templateId).exists)) {
            continue
        }
        $params = @{
            Method = "GET"
            URL    = "/deviceManagement/intents/$($AllIntents.value[$i].id)/assignments"
        }
        if ($AllIntents.value.count - $i -gt 1) {
            $IntentAssignments = Invoke-BatchRequest @params
        } else {
            $IntentAssignments = Invoke-BatchRequest -SendNow @params
        }
        if ($IntentAssignments) {
            foreach ($IntentAssignment in $IntentAssignments.responses) {
                foreach ($Target in $IntentAssignment.body.value.target) {
                    if (-not($Target.groupId)) {
                        continue
                    }
                    $params = @{
                        GroupID        = $Target.groupId
                        ObjectName     = $AllIntents.value[$IntentAssignment.id].displayname
                        #Apparently there are no different ObjectTypes for intents
                        ObjectType     = (Test-BaselineTemplate -templateID ($AllIntents.value[$IntentAssignment.id]).templateId).ObjectType
                        ObjectID       = $AllIntents.value[$IntentAssignment.id].id
                        GroupModeOData = $Target.'@odata.type'
                        FilterIntent   = $Target.deviceAndAppManagementAssignmentFilterType
                        FilterID       = $Target.deviceAndAppManagementAssignmentFilterId
                    } 
                    if ($Target.groupId) {
                        Add-NewObjectToGroupInResults @params
                    } else {
                        Add-NewObjectToGroupInResults @params -OdataType $Target.'@odata.type'
                    }
                }
            }
            $Script:BatchRequestsAnalyze = [System.Collections.ArrayList]::new()
        }
    }
    #GET https://graph.microsoft.com/beta/deviceManagement/intents/?$expand=assignments
}
function Get-ConfigurationPoliciesRelations {
    $AllconfigurationPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/configurationPolicies?`$select=id,name&`$top=999&`$expand=assignments"
    $AllconfigurationPolicies = Get-nextLinkData -OriginalObject $AllconfigurationPolicies
    foreach ($configurationPolicy in $AllconfigurationPolicies.value) {
        if (-not($configurationPolicy.assignments)) {
            continue
        }
        foreach ($configurationPolicyAssignment in $configurationPolicy.assignments) {
            $params = @{
                GroupID        = $configurationPolicyAssignment.target.groupId
                ObjectName     = $configurationPolicy.name
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0&viewFallbackFrom=graph-rest-beta&tabs=powershell
                ObjectType     = '#microsoft.graph.configurationPolicies'
                ObjectID       = $configurationPolicy.id
                GroupModeOData = $configurationPolicyAssignment.target.'@odata.type'
                FilterIntent   = $configurationPolicyAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $configurationPolicyAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($configurationPolicyAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $configurationPolicyAssignment.target.'@odata.type'
            }
        }
    }    

    #https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$select=id,name&$top=999&$filter=templateReference/TemplateFamily eq 'endpointSecurityAntivirus'&$expand=assignments 

    #https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$select=id,name&$filter=(technologies eq 'configManager' and creationSource eq 'SccmAV' or creationSource eq 'WindowsSecurity')
    #https://graph.microsoft.com/beta/deviceManagement/templates?$filter=templateType eq 'SecurityTemplate'

    #https://graph.microsoft.com/beta/deviceManagement/windowsMalwareOverview
    #https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates?$top=500&$filter=lifecycleState%20eq%20%27active%27
}
function Get-AppProtectionPolicyRelations {
    <#
    .NOTES
    This requires multiple requests, each for another OS - iosManagedAppProtections, androidManagedAppProtections, windowsInformationProtectionPolicies
    Additionally, there's targetedManagedAppConfigurations (this is done in Get-AppConfigurationPolicyRelations) and mdmWindowsInformationProtectionPolicies
    https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies - will give us all policies, but no assignments
    #>
    $AlliOSappProtections = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceAppManagement/iosManagedAppProtections/?`$select=displayname,id&`$expand=assignments"
    $AlliOSappProtections = Get-nextLinkData -OriginalObject $AlliOSappProtections
    foreach ($iOSAppProtection in $AlliOSappProtections.value) {
        if (-not($iOSAppProtection.assignments)) {
            continue
        }
        foreach ($iOSAppProtectionAssignment in $iOSAppProtection.assignments) {
            $params = @{
                GroupID        = $iOSAppProtectionAssignment.target.groupId
                ObjectName     = $iOSAppProtection.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-mam-targetedmanagedapppolicyassignment-get?view=graph-rest-1.0&tabs=http
                ObjectType     = '#microsoft.graph.iosManagedAppProtection' 
                ObjectID       = $iOSAppProtection.id
                GroupModeOData = $iOSAppProtectionAssignment.target.'@odata.type'
                FilterIntent   = $iOSAppProtectionAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $iOSAppProtectionAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($iOSAppProtectionAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $iOSAppProtectionAssignment.target.'@odata.type'
            }
        }
    }
    $AllAndroidappProtections = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceAppManagement/androidManagedAppProtections/?`$select=displayname,id&`$expand=assignments"
    $AllAndroidappProtections = Get-nextLinkData -OriginalObject $AllAndroidappProtections
    foreach ($AndroidAppProtection in $AllAndroidappProtections.value) {
        if (-not($AndroidAppProtection.assignments)) {
            continue
        }
        foreach ($AndroidAppProtectionAssignment in $AndroidAppProtection.assignments) {
            $params = @{
                GroupID        = $AndroidAppProtectionAssignment.target.groupId
                ObjectName     = $AndroidAppProtection.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-mam-targetedmanagedapppolicyassignment-get?view=graph-rest-1.0&tabs=http
                ObjectType     = '#microsoft.graph.androidManagedAppProtection' 
                ObjectID       = $AndroidAppProtection.id
                GroupModeOData = $AndroidAppProtectionAssignment.target.'@odata.type'
                FilterIntent   = $AndroidAppProtectionAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $AndroidAppProtectionAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($AndroidAppProtectionAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $AndroidAppProtectionAssignment.target.'@odata.type'
            }
        }
    }
    $windowsManagedAppProtections = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceAppManagement/windowsManagedAppProtections/?`$select=displayname,id&`$expand=assignments"
    $windowsManagedAppProtections = Get-nextLinkData -OriginalObject $windowsManagedAppProtections
    foreach ($windowsManagedAppProtection in $windowsManagedAppProtections.value) {
        if (-not($windowsManagedAppProtection.assignments)) {
            continue
        }
        foreach ($windowsManagedAppProtectionAssignment in $windowsManagedAppProtection.assignments) {
            $params = @{
                GroupID        = $windowsManagedAppProtectionAssignment.target.groupId
                ObjectName     = $windowsManagedAppProtection.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-mam-targetedmanagedapppolicyassignment-get?view=graph-rest-1.0&tabs=http
                ObjectType     = '#microsoft.graph.windowsManagedAppProtection' 
                ObjectID       = $windowsManagedAppProtection.id
                GroupModeOData = $windowsManagedAppProtectionAssignment.target.'@odata.type'
                FilterIntent   = $windowsManagedAppProtectionAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $windowsManagedAppProtectionAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($windowsManagedAppProtectionAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $windowsManagedAppProtectionAssignment.target.'@odata.type'
            }
        }
    }
    $mdmwipProtectionPolicies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceAppManagement/mdmWindowsInformationProtectionPolicies/?`$select=displayname,id&`$expand=assignments"
    $mdmwipProtectionPolicies = Get-nextLinkData -OriginalObject $mdmwipProtectionPolicies
    foreach ($mdmwipProtectionPolicy in $mdmwipProtectionPolicies.value) {
        if (-not($mdmwipProtectionPolicy.assignments)) {
            continue
        }
        foreach ($mdmwipProtectionPolicyAssignment in $mdmwipProtectionPolicy.assignments) {
            $params = @{
                GroupID        = $mdmwipProtectionPolicyAssignment.target.groupId
                ObjectName     = $mdmwipProtectionPolicy.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/intune-mam-targetedmanagedapppolicyassignment-get?view=graph-rest-1.0&tabs=http
                ObjectType     = '#microsoft.graph.mdmWindowsInformationProtectionPolicy' 
                ObjectID       = $mdmwipProtectionPolicy.id
                GroupModeOData = $mdmwipProtectionPolicyAssignment.target.'@odata.type'
                FilterIntent   = $mdmwipProtectionPolicyAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $mdmwipProtectionPolicyAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($mdmwipProtectionPolicyAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $mdmwipProtectionPolicyAssignment.target.'@odata.type'
            }
        }
    }   
}
function Get-AppConfigurationPolicyRelations {
    $AllAppConfigurationDeviceConfigurations = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceAppManagement/mobileAppConfigurations/?`$select=displayname,id&`$expand=assignments"
    $AllAppConfigurationDeviceConfigurations = Get-nextLinkData -OriginalObject $AllAppConfigurationDeviceConfigurations
    foreach ($AppConfigurationDeviceConfiguration in $AllAppConfigurationDeviceConfigurations.value) {
        if (-not($AppConfigurationDeviceConfiguration.assignments)) {
            continue
        }
        foreach ($AppConfigurationDeviceConfigurationAssignment in $AppConfigurationDeviceConfiguration.assignments) {
            $params = @{
                GroupID        = $AppConfigurationDeviceConfigurationAssignment.target.groupId
                ObjectName     = $AppConfigurationDeviceConfiguration.displayName
                ObjectType     = $AppConfigurationDeviceConfiguration.'@odata.type'
                ObjectID       = $AppConfigurationDeviceConfiguration.id
                GroupModeOData = $AppConfigurationDeviceConfigurationAssignment.target.'@odata.type'
                FilterIntent   = $AppConfigurationDeviceConfigurationAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $AppConfigurationDeviceConfigurationAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($AppConfigurationDeviceConfigurationAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $AppConfigurationDeviceConfigurationAssignment.target.'@odata.type'
            }
        }
    }
    $AllAppConfigurationConfigurations = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceAppManagement/targetedManagedAppConfigurations/?`$select=displayname,id&`$expand=assignments"
    $AllAppConfigurationConfigurations = Get-nextLinkData -OriginalObject $AllAppConfigurationConfigurations
    foreach ($AllAppConfigurationConfiguration in $AllAppConfigurationConfigurations.value) {
        if (-not($AllAppConfigurationConfiguration.assignments)) {
            continue
        }
        foreach ($AllAppConfigurationConfigurationAssignment in $AllAppConfigurationConfiguration.assignments) {
            $params = @{
                GroupID        = $AllAppConfigurationConfigurationAssignment.target.groupId
                ObjectName     = $AllAppConfigurationConfiguration.displayName
                #No @odata.type is returned - but it should. See https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-targetedmanagedappconfiguration?view=graph-rest-1.0
                ObjectType     = '#microsoft.graph.targetedManagedAppConfiguration'
                ObjectID       = $AllAppConfigurationConfiguration.id
                GroupModeOData = $AllAppConfigurationConfigurationAssignment.target.'@odata.type'
                FilterIntent   = $AllAppConfigurationConfigurationAssignment.target.deviceAndAppManagementAssignmentFilterType
                FilterID       = $AllAppConfigurationConfigurationAssignment.target.deviceAndAppManagementAssignmentFilterId
            } 
            if ($AllAppConfigurationConfigurationAssignment.target.groupId) {
                Add-NewObjectToGroupInResults @params
            } else {
                Add-NewObjectToGroupInResults @params -OdataType $AllAppConfigurationConfigurationAssignment.target.'@odata.type'
            }
        }
    }
    #https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations
    #https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations 
}
function Get-eSIMCellularProfileRelations {
    <#
    .NOTES
    This is a stub, because I don't have an eSim to create such a profile - therefore don't know how such an object would look
    #>
    #GET https://graph.microsoft.com/beta/deviceManagement/embeddedSIMActivationCodePools?$select=id,displayName,activationCodeCount&$expand=assignments
    return
}
function Get-iOSAppProvisioningProfilesRelations {
    <#
    .NOTES
    This is a stub, because I don't have a LoB iOS app to test this with
    #>
    #https://graph.microsoft.com/beta/deviceAppManagement/iosLobAppProvisioningConfigurations
}
function Get-SModePoliciesRelations {
    <#
    .NOTES
    This is a stub, because I don't have a Windows device that has S-Mode enabled
    #>    
    #https://graph.microsoft.com/beta/deviceAppManagement/wdacSupplementalPolicies
}
function Get-ManagedEBookRelations {
    <#
    .NOTES
    This is a stub, because I don't have ABM set up to deploy an EBook
    #> 
    #https://graph.microsoft.com/beta/deviceAppManagement/managedEBooks
}
# End of content gathering functions
function Get-ConfigurationRelations {
    <#
    .NOTES
    Wrap up function. This function wraps up related functions into one call, that could be used elsewhere
    #>
    Get-DeviceEnrollmentConfigurationRelations
    Get-DeviceConfigurationRelations
    Get-ConfigurationPoliciesRelations
    Get-IntentRelations
}
function Start-GatherInformation {
    Get-AppRelations 
    Get-ConfigurationRelations
    Get-ScriptRelations
    Get-Remediations
    Get-DeviceComplianceRelations
    Get-ComplianceRelations
    Get-DriverUpdateRelations
    Get-FeatureUpdateRelations
    Get-AppProtectionPolicyRelations
    Get-AppConfigurationPolicyRelations
}

#Start Coding!
#Quick exit if no Graph connection can be established
if ($null -eq $(Get-mgcontext)) {
    if (-not($CertificateThumbprint)) {
        Write-Log -Message 'No certificate thumbpring was provided - this is currently a requirement. Exiting' -Component 'GFDCore' -Type 3
        exit 1
    }
    if (-not($ClientID)) {
        Write-Log -Message 'No (app) client ID was provided - this is currently a requirement. Exiting' -Component 'GFDCore' -Type 3
        exit 1
    }
    if (-not($TenantID)) {
        Write-Log -Message 'No tenant ID was provided - this is currently a requirement. Exiting' -Component 'GFDCore' -Type 3
        exit 1
    }
    #Prepare Graph-Session
    Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientID -TenantId $TenantID
}
#Prepare some data that is expected in every environment
Initialize-Data
#Getting Information
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
Start-GatherInformation
$Stopwatch.Stop()
$Stopwatch.Elapsed
#Export data to Json
if ($MultiFileResult) {
    foreach ($Group in $Script:ResultArray) {
        #Sanitize Group name
        $GroupName = $Group.DisplayName
        $GroupNameSanitized = $GroupName -replace "[$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+", "_"
        $TargetPath = "$WorkingDirectory$GroupNameSanitized.json"
        $Group | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $TargetPath -Force
    }
} else {
    $TargetPath = "$WorkingDirectory`GCD_AllGroups.json"
    $Script:ResultArray | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $TargetPath -Force
}


if ($ConvertToMermaid) {
    <#Mindmap Template Mermaid
mindmap
  root((mindmap))
    Origins
      Long history
      ::icon(fa fa-book)
      Popularisation
        British popular psychology author Tony Buzan
    Research
      On effectiveness<br/>and features
      On Automatic creation
        Uses
            Creative techniques
            Strategic planning
            Argument mapping
    Tools
      Pen and paper
      Mermaid
#>
    foreach ($Group in $Script:ResultArray) {
        $ObjectTypes = Convert-ObjectTypesMermaid
        $Diskpart = @"
mindmap
root(($($Group.DisplayName)))
    Origins
    Long history
    ::icon(fa fa-book)
    Popularisation
        British popular psychology author Tony Buzan
    Research
    On effectiveness<br/>and features
    On Automatic creation
        Uses
            Creative techniques
            Strategic planning
            Argument mapping
    Tools
    Pen and paper
    Mermaid
"@
    }
}

Disconnect-MgGraph | Out-Null
Set-Location $CurrentLocation