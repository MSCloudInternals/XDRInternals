function Set-XdrCloudAppsConfigurationSubnet {
    <#
    .SYNOPSIS
        Updates a subnet (IP range) configuration in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Updates an existing subnet configuration in Microsoft Defender for Cloud Apps.
        Subnets allow you to define IP address ranges for categorization,
        policy application, and location-based reporting.

    .PARAMETER SubnetId
        The unique identifier of the subnet to update.

    .PARAMETER Name
        The display name for the subnet.

    .PARAMETER Subnets
        An array of subnet strings in CIDR notation (e.g., "192.168.0.0/24", "10.0.0.0/8").

    .PARAMETER Category
        The category for this subnet. Valid values are:
        - Corporate (1)
        - Administrative (2)
        - Risky (3)
        - VPN (4)
        - CloudProvider (5)
        - Other (6)

    .PARAMETER Tags
        An array of tag names to associate with this subnet (e.g., "Home", "Office").

    .PARAMETER Organization
        The organization name to associate with this subnet.
        Use with -OverrideOrganization to apply.

    .PARAMETER OverrideOrganization
        When specified, overrides the organization for traffic from this subnet.

    .PARAMETER Location
        A hashtable containing location information with the following properties:
        name, latitude, longitude, countryCode, countryName, cityName, regionCode, regionName.

    .PARAMETER OverrideLocation
        When specified, overrides the geolocation for traffic from this subnet.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationSubnet -SubnetId "697e4d8a123456" -Name "Corporate Network" -Subnets @("10.0.0.0/8") -Category Corporate -Tags @("Office")
        Updates the specified subnet with a new name and category.

    .EXAMPLE
        $subnet = Get-XdrCloudAppsConfigurationSubnet | Where-Object { $_.name -eq "VPN Users" }
        Set-XdrCloudAppsConfigurationSubnet -SubnetId $subnet._id -Name "VPN Users Updated" -Subnets $subnet.subnets -Category VPN
        Gets an existing subnet and updates its name.

    .EXAMPLE
        $location = @{
            name = "United States"
            latitude = 38.8920621
            longitude = -77.0199124
            countryCode = "US"
            countryName = "United States"
        }
        Set-XdrCloudAppsConfigurationSubnet -SubnetId "697e4d8a123456" -Name "US Office" -Subnets @("192.168.1.0/24") -Category Corporate -Location $location -OverrideLocation
        Updates a subnet with custom location override.

    .OUTPUTS
        System.Object
        Returns the API response confirming the update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('_id')]
        [string]$SubnetId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [string[]]$Subnets,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Corporate', 'Administrative', 'Risky', 'VPN', 'CloudProvider', 'Other')]
        [string]$Category,

        [Parameter()]
        [string[]]$Tags,

        [Parameter()]
        [string]$Organization,

        [Parameter()]
        [switch]$OverrideOrganization,

        [Parameter()]
        [hashtable]$Location,

        [Parameter()]
        [switch]$OverrideLocation
    )

    begin {
        Update-XdrConnectionSettings

        # Map category names to numeric values
        $CategoryMap = @{
            'Corporate'      = 1
            'Administrative' = 2
            'Risky'          = 3
            'VPN'            = 4
            'CloudProvider'  = 5
            'Other'          = 6
        }
    }

    process {
        $target = "Subnet '$Name' ($SubnetId)"
        $action = "Update subnet configuration"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Updating subnet: $SubnetId"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/subnet/$SubnetId/update_rule/"

                # Build the request body
                $Body = @{
                    name     = $Name
                    subnets  = $Subnets
                    category = $CategoryMap[$Category]
                }

                if ($PSBoundParameters.ContainsKey('Tags')) {
                    $Body.tags = $Tags
                } else {
                    $Body.tags = @()
                }

                if ($PSBoundParameters.ContainsKey('Organization')) {
                    $Body.organization = $Organization
                    $Body.overrideOrganization = $OverrideOrganization.IsPresent
                } else {
                    $Body.overrideOrganization = $false
                }

                if ($PSBoundParameters.ContainsKey('Location')) {
                    $Body.location = $Location
                    $Body.overrideLocation = $OverrideLocation.IsPresent
                } else {
                    $Body.overrideLocation = $false
                }

                $BodyJson = $Body | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $BodyJson"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $BodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful update
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationSubnet" -ErrorAction SilentlyContinue
                Write-Verbose "Subnet updated successfully"

                return $result
            } catch {
                Write-Error "Failed to update subnet: $_"
            }
        }
    }

    end {
    }
}
