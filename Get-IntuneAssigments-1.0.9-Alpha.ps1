#Requires -Version 7.1

<#PSScriptInfo
.VERSION 1.0.9-Alpha
.AUTHOR Divesh Kerai, Grok 3 (xAI) (based on original code by Amir Joseph Sayes)
.TAGS Intune Configuration Management Microsoft Graph Azure
.EXTERNALMODULEDEPENDENCIES 
Microsoft.Graph.Authentication
Microsoft.Graph.Beta.DeviceManagement
Microsoft.Graph.Beta.Groups
Microsoft.Graph.Beta.Devices.CorporateManagement
Microsoft.Graph.Beta.DeviceManagement.Enrollment
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
- Created by Divesh Kerai and Grok 3 (xAI), heavily adapted and reused existing code from original code
by Amir Joseph Sayes (GitHub: https://github.com/amirjs, Website: https://amirsayes.co.uk)
- Added HTML output support
- VERSION 1.0.9-Alpha - adapted from original code Author to add HTML and CSV output support
#>

<#
.SYNOPSIS
    Retrieves all Intune Configuration Profile assignments and exports to CSV or HTML.

.DESCRIPTION
    This script retrieves assignments and filters for various Intune configuration types including:
    - Device Configuration Profiles
    - Device Management Configuration Policies
    - Compliance Policies
    - Security Baselines
    - Administrative Templates
    - App Protection Policies
    - Apps Assignments
    - Windows Information Protection Policies
    - Remediation Scripts
    - Device Management Scripts
    - Autopilot Profiles (v1)    
- Shows included and excluded groups for each assignment
- Displays filter information if configured
- Export results to CSV or HTML
- Filter by specific Azure AD group

.PARAMETER OutputFile
    Path to export the results as CSV or HTML. If not specified, results will be displayed in console.

.PARAMETER OutputFormat
    Format for the output file. Options are 'CSV' or 'HTML'. Default is 'CSV'.

.PARAMETER GroupName
    Name of the Azure AD group to filter assignments. Only assignments that include or exclude this group will be returned.

.EXAMPLE
    Get-IntuneAssignments
    Returns all Intune configuration assignments and displays them in the console.

.EXAMPLE
    Get-IntuneAssignments -OutputFile "C:\temp\assignments.html" -OutputFormat HTML
    Retrieves all assignments and exports them to a styled HTML file.

.EXAMPLE
    Get-IntuneAssignments -GroupName "Pilot Users" -OutputFile "C:\temp\assignments.csv"
    Returns assignments that include or exclude the specified group and exports to CSV.

.NOTES
    Version:        1.0.10
    Author:         Amir Joseph Sayes
    Company:        amirsayes.co.uk
    Creation Date:  2025-05-02
    Requirements:   
    - PowerShell 7.1 or higher
    - Microsoft Graph PowerShell SDK modules
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "HTML")]
    [string]$OutputFormat = "CSV",
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName
)

#region Support Functions

function ConvertTo-HtmlReport {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Results,
        [string]$GroupName
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $htmlHeader = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>Intune Assignments Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #2c3e50;
            text-align: center;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #34495e;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .profile-type-autopilot {
            color: #2980b9;
            font-weight: bold;
        }
        .profile-type-compliance {
            color: #27ae60;
            font-weight: bold;
        }
        .profile-type-configuration {
            color: #8e44ad;
            font-weight: bold;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <h1>Intune Assignments Report</h1>
    <p><strong>Generated:</strong> $timestamp</p>
    <p><strong>Group Filter:</strong> $(if ($GroupName) { $GroupName } else { 'None' })</p>
    <p><strong>Total Policies:</strong> $($Results.Count)</p>
    <table>
        <tr>
            <th>Policy Name</th>
            <th>Profile Type</th>
            <th>Included Groups</th>
            <th>Excluded Groups</th>
        </tr>
"@
    
    $htmlRows = foreach ($result in $Results) {
        $profileClass = switch -Regex ($result.ProfileType) {
            "Autopilot" { "profile-type-autopilot" }
            "Compliance" { "profile-type-compliance" }
            "Configuration" { "profile-type-configuration" }
            default { "" }
        }
        @"
        <tr>
            <td>$($result.DisplayName)</td>
            <td class='$profileClass'>$($result.ProfileType)</td>
            <td>$($result.IncludedGroups -join '; ')</td>
            <td>$($result.ExcludedGroups -join '; ')</td>
        </tr>
"@
    }
    
    $htmlFooter = @"
    </table>
    <div class='footer'>
        <p>Generated by Get-IntuneAssignments v1.0.10 | Author: Amir Joseph Sayes | &copy; 2025 amirsayes.co.uk</p>
    </div>
</body>
</html>
"@
    
    return $htmlHeader + ($htmlRows -join '') + $htmlFooter
}

function Get-IntuneAppProtectionAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $AppProtectionPolicy = Get-MgBetaDeviceAppManagementManagedAppPolicy -Filter "displayName eq '$displayName'"
    } else {
        $AppProtectionPolicy = Get-MgBetaDeviceAppManagementManagedAppPolicy -All
    }

    foreach ($policy in $AppProtectionPolicy) {        
        $assignments = $null
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        if ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.androidManagedAppProtection") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.iosManagedAppProtection") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.windowsInformationProtectionAppLockerFileProtection") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionAppLockerFileProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.windowsManagedAppProtections") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections('$($policy.Id)')/assignments"
        } elseif ($policy.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.targetedManagedAppConfiguration") {
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations('$($policy.Id)')/assignments"            
        } else {
            Write-Output "No App Protection Policy assignment found for $($policy.displayName)"
            continue
        }

        $assignments = Invoke-MgGraphRequest -Uri $uri -Headers @{ConsistencyLevel = "eventual"} -ContentType "application/json"

        foreach ($assignment in $assignments.value) {
            if ($groupId -and $assignment.target.groupId -ne $groupId) {
                continue
            }

            if ($assignment.target.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget") {
                $CurrentincludedGroup = (Get-MgBetaGroup -GroupId $($assignment.target.groupId)).DisplayName
                if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.target.'@odata.type' -eq "#microsoft.graph.exclusionGroupAssignmentTarget") {
                $excludedGroups += (Get-MgBetaGroup -GroupId $($assignment.target.groupId)).DisplayName
            } elseif ($assignment.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget") {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget") {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.target.deviceAndAppManagementAssignmentFilterId) -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.target.deviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                ProfileType = $policy.AdditionalProperties.'@odata.type' -replace '^#microsoft\.graph\.', ''
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneManagedDeviceAppAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $MobileApps = Get-MgBetaDeviceAppManagementMobileApp -Filter "displayName eq '$displayName'" -ErrorAction SilentlyContinue
    } else {
        $MobileApps = Get-MgBetaDeviceAppManagementMobileApp -All -ErrorAction SilentlyContinue
    }

    if ($null -eq $MobileApps) {
        return
    }

    foreach ($app in $MobileApps) {
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($app.Id)')/assignments"
        try {
            $assignmentsResult = Invoke-MgGraphRequest -Uri $uri -Method Get -Headers @{ConsistencyLevel = "eventual"} -ErrorAction Stop
            $assignments = $assignmentsResult.value
        } catch {
            continue
        }

        if ($null -eq $assignments -or $assignments.Count -eq 0) {
            continue
        }

        $includedGroups = @()
        $hasMatchingAssignment = $false

        foreach ($assignment in $assignments) {
            $CurrentFilterName = $null
            $CurrentIncludedGroup = $null
            $isMatch = $false

            if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                if ($groupId) {
                    if ($assignment.target.groupId -eq $groupId) {
                        $groupInfo = Get-MgBetaGroup -GroupId $assignment.target.groupId -ErrorAction SilentlyContinue
                        $CurrentIncludedGroup = if ($groupInfo) { $groupInfo.DisplayName } else { "Group ID: $($assignment.target.groupId) (Not Found/No Access)" }
                        $isMatch = $true
                    } else {
                        continue
                    }
                } else {
                    $groupInfo = Get-MgBetaGroup -GroupId $assignment.target.groupId -ErrorAction SilentlyContinue
                    $CurrentIncludedGroup = if ($groupInfo) { $groupInfo.DisplayName } else { "Group ID: $($assignment.target.groupId) (Not Found/No Access)" }
                    $isMatch = $true
                }

                if ($isMatch) {
                    if ($assignment.target.deviceAndAppManagementAssignmentFilterId -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $filterInfo = Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -ErrorAction SilentlyContinue
                        $CurrentFilterName = if ($filterInfo) { " | Filter: $($filterInfo.DisplayName)" } else { " | Filter ID: $($assignment.target.deviceAndAppManagementAssignmentFilterId) (Not Found/No Access)" }
                    } else {
                        $CurrentFilterName = " | No Filter"
                    }
                }
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                if (-not $groupId) {
                    $CurrentIncludedGroup = "All Devices"
                    $isMatch = $true
                    if ($assignment.target.deviceAndAppManagementAssignmentFilterId -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $filterInfo = Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -ErrorAction SilentlyContinue
                        $CurrentFilterName = if ($filterInfo) { " | Filter: $($filterInfo.DisplayName)" } else { " | Filter ID: $($assignment.target.deviceAndAppManagementAssignmentFilterId) (Not Found/No Access)" }
                    } else {
                        $CurrentFilterName = " | No Filter"
                    }
                } else {
                    continue
                }
            } elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                if (-not $groupId) {
                    $CurrentIncludedGroup = "All Users"
                    $isMatch = $true
                    if ($assignment.target.deviceAndAppManagementAssignmentFilterId -and $assignment.target.deviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                        $filterInfo = Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $assignment.target.deviceAndAppManagementAssignmentFilterId -ErrorAction SilentlyContinue
                        $CurrentFilterName = if ($filterInfo) { " | Filter: $($filterInfo.DisplayName)" } else { " | Filter ID: $($assignment.target.deviceAndAppManagementAssignmentFilterId) (Not Found/No Access)" }
                    } else {
                        $CurrentFilterName = " | No Filter"
                    }
                } else {
                    continue
                }
            }

            if ($isMatch -and $CurrentIncludedGroup) {
                $includedGroups += $CurrentIncludedGroup + $CurrentFilterName
                $hasMatchingAssignment = $true
            }
        }

        if ($hasMatchingAssignment) {
            [PSCustomObject]@{
                DisplayName = $app.DisplayName
                ProfileType = "Mobile App Deployment"
                IncludedGroups = $includedGroups
                ExcludedGroups = $null
            }
        }
    }
}

function Get-IntuneDeviceManagementSecurityBaselineAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $SecurityBaseline = Get-MgBetaDeviceManagementIntent -Filter "displayName eq '$displayName'" -ExpandProperty assignments
    } else {
        $SecurityBaseline = Get-MgBetaDeviceManagementIntent -All -ExpandProperty assignments
    }

    foreach ($baseline in $SecurityBaseline) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $baseline.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $baseline.DisplayName
                TemplateName = (Get-MgBetaDeviceManagementTemplate -DeviceManagementTemplateId $baseline.TemplateId).DisplayName
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceCompliancePolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $CompliancePolicy = Get-MgBetaDeviceManagementDeviceCompliancePolicy -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $CompliancePolicy = Get-MgBetaDeviceManagementDeviceCompliancePolicy -All -ExpandProperty "assignments"
    }

    foreach ($policy in $CompliancePolicy) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $policy.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allApolloDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaApolloDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                ProfileType = $policy.AdditionalProperties.'@odata.type' -replace '^#microsoft\.graph\.', ''
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceConfigurationAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $DeviceConfiguration = Get-MgBetaDeviceManagementDeviceConfiguration -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $DeviceConfiguration = Get-MgBetaDeviceManagementDeviceConfiguration -All -ExpandProperty "assignments"
    }

    foreach ($config in $DeviceConfiguration) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $config.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $config.DisplayName
                ProfileType = $config.AdditionalProperties.'@odata.type' -replace '^#microsoft\.graph\.', ''
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceManagementConfigurationPolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $ConfigurationPolicy = Get-MgBetaDeviceManagementConfigurationPolicy -Filter "name eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $ConfigurationPolicy = Get-MgBetaDeviceManagementConfigurationPolicy -All -ExpandProperty "assignments"
    }

    foreach ($policy in $ConfigurationPolicy) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $policy.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.Name
                ProfileType = "Device Management Configuration Policy"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceConfigurationAdministrativeTemplatesAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $AdministrativeTemplate = Get-MgBetaDeviceManagementGroupPolicyConfiguration -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $AdministrativeTemplate = Get-MgBetaDeviceManagementGroupPolicyConfiguration -All -ExpandProperty "assignments"
    }

    foreach ($template in $AdministrativeTemplate) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $template.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                $CurrentincludedGroup = "All Devices"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                $CurrentincludedGroup = "All Users"
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $template.DisplayName
                ProfileType = "AdministrativeTemplates"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneRemediationScriptAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $RemediationScript = Get-MgBetaDeviceManagementDeviceHealthScript -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $RemediationScript = Get-MgBetaDeviceManagementDeviceHealthScript -All -ExpandProperty "assignments"
    }

    foreach ($script in $RemediationScript) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $script.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $script.DisplayName
                ProfileType = "Remediation Script"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneAutopilotProfileAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $AutopilotProfile = Get-MgBetaDeviceManagementWindowsAutopilotDeploymentProfile -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $AutopilotProfile = Get-MgBetaDeviceManagementWindowsAutopilotDeploymentProfile -All -ExpandProperty "assignments"
    }

    foreach ($profile in $AutopilotProfile) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $profile.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $profile.DisplayName
                ProfileType = "Autopilot Profile"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneDeviceManagementScriptAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $DeviceManagementScript = Get-MgBetaDeviceManagementScript -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $DeviceManagementScript = Get-MgBetaDeviceManagementScript -All -ExpandProperty "assignments"
    }

    foreach ($script in $DeviceManagementScript) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $script.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $script.DisplayName
                ProfileType = "Device Management Script"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}

function Get-IntuneWindowsInformationProtectionPolicyAssignment {
    param (
        [Parameter(Mandatory = $false)]
        [string]$displayName,
        [Parameter(Mandatory = $false)]
        [string]$groupId
    )

    if ($displayName) {
        $WIPPolicy = Get-MgBetaDeviceAppManagementMdmWindowsInformationProtectionPolicy -Filter "displayName eq '$displayName'" -ExpandProperty "assignments"
    } else {
        $WIPPolicy = Get-MgBetaDeviceAppManagementMdmWindowsInformationProtectionPolicy -All -ExpandProperty "assignments"
    }

    foreach ($policy in $WIPPolicy) {
        $includedGroups = @()
        $excludedGroups = @()
        $FilterName = @()

        $assignments = $policy.Assignments
        foreach ($assignment in $assignments) {
            if ($groupId -and $assignment.Target.AdditionalProperties.groupId -ne $groupId) {
                continue
            }

            if ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $CurrentincludedGroup = (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
                if ($($assignment.Target.DeviceAndAppManagementAssignmentFilterId) -and $assignment.Target.DeviceAndAppManagementAssignmentFilterId -ne [guid]::Empty) {
                    $FilterName = " | Filter: " + (Get-MgBetaDeviceManagementAssignmentFilter -DeviceAndAppManagementAssignmentFilterId $($assignment.Target.DeviceAndAppManagementAssignmentFilterId)).DisplayName
                } else {
                    $FilterName = " | No Filter"
                }
                $includedGroups += $CurrentincludedGroup + $FilterName
            } elseif ($assignment.Target.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                $excludedGroups += (Get-MgbetaGroup -GroupId $($assignment.Target.AdditionalProperties.groupId)).DisplayName
            }
        }

        if ($includedGroups.Count -gt 0 -or $excludedGroups.Count -gt 0) {
            [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                ProfileType = "Windows Information Protection Policy"
                IncludedGroups = $includedGroups
                ExcludedGroups = $excludedGroups
            }
        }
    }
}
#endregion

#region Module Installation
$script:GraphModuleVersion = "2.25.0"

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Beta.DeviceManagement",
    "Microsoft.Graph.Beta.Groups",
    "Microsoft.Graph.Beta.Devices.CorporateManagement",
    "Microsoft.Graph.Beta.DeviceManagement.Enrollment"
)

Write-Host "Checking required modules (version $script:GraphModuleVersion)..." -ForegroundColor Cyan
$modulesNeedingInstall = @()

foreach ($module in $requiredModules) {
    try {
        $existingModule = Get-Module -Name $module -ListAvailable | Where-Object { $_.Version -eq $script:GraphModuleVersion }
        if (-not $existingModule) {
            $modulesNeedingInstall += $module
        }
    } catch {
        Write-Warning "Error checking module $module`: $_"
    }
}

if ($modulesNeedingInstall.Count -gt 0) {
    Write-Host "The following modules need to be installed (version $script:GraphModuleVersion): $($modulesNeedingInstall -join ', ')" -ForegroundColor Yellow
    $userConsent = Read-Host "Do you want to proceed with installing the required modules? (Y/N)"
    if ($userConsent -match '^[Yy]$') {
        Write-Host "Installing required modules..." -ForegroundColor Cyan
        foreach ($module in $modulesNeedingInstall) {
            try {
                Write-Host "Installing $module version $script:GraphModuleVersion..." -ForegroundColor Yellow
                Install-Module -Name $module -RequiredVersion $script:GraphModuleVersion -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Host "Successfully installed $module" -ForegroundColor Green
            } catch {
                Write-Error "Failed to install module $module. Error: $_"
                return
            }
        }
    } else {
        Write-Host "Module installation canceled by user. Exiting script." -ForegroundColor Red
        return
    }
}

foreach ($module in $requiredModules) {
    try {
        Import-Module -Name $module -RequiredVersion $script:GraphModuleVersion -Force -ErrorAction Stop
        Write-Verbose "Successfully imported $module version $script:GraphModuleVersion"
    } catch {
        Write-Error "Failed to import module $module. Error: $_"
        return
    }
}
#endregion

try {
    if (-not (Get-MgContext)) {
        Write-Verbose "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes @(
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementApps.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementServiceConfig.Read.All",
            "Group.Read.All",
            "Directory.Read.All"
        )
    }
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    return
}

$results = @()

$groupId = $null
if ($GroupName) {
    try {
        $group = Get-MgBetaGroup -Search "displayName:$GroupName" -CountVariable c -ConsistencyLevel eventual -All     
        if (-not $group) {
            Write-Error "Group '$GroupName' not found."
            return
        }
        if ($c -gt 1) {
            Write-Host "Multiple groups found. Please select one:" -ForegroundColor Yellow
            $group | ForEach-Object { Write-Host "$($_.Id): $($_.DisplayName)" -ForegroundColor Cyan }
            $selectedGroupId = Read-Host "Enter the ID of the group you want to use"
            $groupId= ($group | Where-Object { $_.Id -eq $selectedGroupId }).Id
            $groupDisplayName= ($group | Where-Object { $_.Id -eq $selectedGroupId }).DisplayName
            if (-not $groupId) {
                Write-Error "Invalid group ID selected."
                return
            }
        } else {
            $groupId = $group.Id
            $groupDisplayName = $group.DisplayName
        }        
        Write-Host "Processing assignments for group: $groupDisplayName and ID: $groupId" -ForegroundColor Green
    } catch {
        Write-Error "Failed to get group information: $_"
        return
    }
}

$processSteps = @(
    @{ Name = "App Protection Policies"; Function = "Get-IntuneAppProtectionAssignment" },
    @{ Name = "Managed Device Apps"; Function = "Get-IntuneManagedDeviceAppAssignment" },
    @{ Name = "Security Baselines"; Function = "Get-IntuneDeviceManagementSecurityBaselineAssignment" },
    @{ Name = "Device Compliance Policies"; Function = "Get-IntuneDeviceCompliancePolicyAssignment" },
    @{ Name = "Device Configurations"; Function = "Get-IntuneDeviceConfigurationAssignment" },
    @{ Name = "Device Management Configuration Policies"; Function = "Get-IntuneDeviceManagementConfigurationPolicyAssignment" },
    @{ Name = "Administrative Templates"; Function = "Get-IntuneDeviceConfigurationAdministrativeTemplatesAssignment" },
    @{ Name = "Remediation Scripts"; Function = "Get-IntuneRemediationScriptAssignment" },
    @{ Name = "Autopilot Profiles"; Function = "Get-IntuneAutopilotProfileAssignment" },
    @{ Name = "Device Management Scripts"; Function = "Get-IntuneDeviceManagementScriptAssignment" },
    @{ Name = "Windows Information Protection Policies"; Function = "Get-IntuneWindowsInformationProtectionPolicyAssignment" }
)

foreach ($step in $processSteps) {
    Write-Host "Processing $($step.Name)..." -ForegroundColor Cyan
    try {
        $stepResults = & $step.Function -groupId $groupId
        $results += $stepResults
    } catch {
        Write-Warning "Failed to process $($step.Name): $_"
    }
}

$finalResults = @($results)
if ($finalResults.Count -gt 0) {
    Write-Host "`nPolicy Assignments:" -ForegroundColor Green
    $finalResults | Format-Table -Property DisplayName, ProfileType, 
        @{Name='IncludedGroups';Expression={$_.IncludedGroups -join '; '}},
        @{Name='ExcludedGroups';Expression={$_.ExcludedGroups -join '; '}} -Wrap -AutoSize 

    Write-Host "`nFound $($finalResults.Count) policies with assignments" -ForegroundColor Green
    Write-Host "If not all columns are visible, use -OutputFile to export to CSV or HTML" -ForegroundColor Yellow

    if ($OutputFile) {
        try {
            $directory = Split-Path -Path $OutputFile -Parent
            if (-not (Test-Path -Path $directory)) {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
            }
            
            if ($OutputFormat -eq "CSV") {
                $finalResults | Select-Object DisplayName, ProfileType, 
                    @{Name='IncludedGroups';Expression={$_.IncludedGroups -join '; '}},
                    @{Name='ExcludedGroups';Expression={$_.ExcludedGroups -join '; '}} |
                Export-Csv -Path $OutputFile -NoTypeInformation -Force
                Write-Host "Results exported to $OutputFile as CSV" -ForegroundColor Green
            } elseif ($OutputFormat -eq "HTML") {
                $htmlContent = ConvertTo-HtmlReport -Results $finalResults -GroupName $GroupName
                $htmlContent | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
                Write-Host "Results exported to $OutputFile as HTML" -ForegroundColor Green
            }
        } catch {
            Write-Error "Failed to export results to $OutputFormat`: $_"
        }
    }
} else {
    Write-Host "No policies with assignments found" -ForegroundColor Yellow
}