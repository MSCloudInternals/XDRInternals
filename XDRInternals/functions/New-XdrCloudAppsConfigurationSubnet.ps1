function New-XdrCloudAppsConfigurationSubnet {
    <#
    .SYNOPSIS
        Creates a new IP address range (subnet) in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Creates a new IP address range (subnet) in Microsoft Defender for Cloud Apps.
        IP ranges can be categorized and tagged for use in policies and reporting.

    .PARAMETER Name
        The name for the IP address range.

    .PARAMETER Subnets
        Array of IP addresses or CIDR notation ranges (e.g., "192.168.0.0/24", "10.0.0.1").

    .PARAMETER Category
        The category for the IP range. Valid values:
        - Corporate: Corporate network ranges
        - Administrative: Administrative access ranges
        - Risky: Known risky IP ranges
        - VPN: VPN exit points
        - CloudProvider: Cloud service provider ranges
        - Other: Other IP ranges

    .PARAMETER Tags
        Optional custom tags for the IP range (e.g., "Home", "Branch Office").

    .PARAMETER Organization
        Optional organization name to associate with this IP range.

    .PARAMETER Location
        Optional location hashtable with the following properties:
        - name: Location name (e.g., "United States")
        - latitude: Latitude coordinate
        - longitude: Longitude coordinate
        - countryCode: Two-letter country code (e.g., "US")
        - countryName: Full country name

    .PARAMETER Confirm
        Prompts for confirmation before creating the subnet.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrCloudAppsConfigurationSubnet -Name "Corporate HQ" -Subnets "10.0.0.0/8" -Category Corporate
        Creates a new corporate IP range for the 10.0.0.0/8 network.

    .EXAMPLE
        New-XdrCloudAppsConfigurationSubnet -Name "VPN Exit Points" -Subnets "203.0.113.0/24", "198.51.100.0/24" -Category VPN -Tags "Remote Access"
        Creates a VPN IP range with multiple subnets and a custom tag.

    .EXAMPLE
        $location = @{
            name = "Seattle Office"
            latitude = 47.6062
            longitude = -122.3321
            countryCode = "US"
            countryName = "United States"
        }
        New-XdrCloudAppsConfigurationSubnet -Name "Seattle Office" -Subnets "192.168.1.0/24" -Category Corporate -Organization "Contoso" -Location $location
        Creates an IP range with organization and location information.

    .OUTPUTS
        PSObject
        Returns the API response for the created subnet.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Subnets,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Corporate', 'Administrative', 'Risky', 'VPN', 'CloudProvider', 'Other')]
        [string]$Category,

        [Parameter()]
        [string[]]$Tags,

        [Parameter()]
        [string]$Organization,

        [Parameter()]
        [hashtable]$Location
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/subnet/create_rule/"

        # Map category names to numeric values
        $categoryMap = @{
            'Corporate'     = 1
            'Administrative' = 2
            'Risky'         = 3
            'VPN'           = 4
            'CloudProvider' = 5
            'Other'         = 6
        }

        # Build request body
        $body = @{
            name     = $Name
            subnets  = $Subnets
            category = $categoryMap[$Category]
        }

        # Add optional tags
        if ($Tags) {
            $body['tags'] = $Tags
        }

        # Add optional organization
        if ($Organization) {
            $body['overrideOrganization'] = $true
            $body['organization'] = $Organization
        }

        # Add optional location
        if ($Location) {
            $body['overrideLocation'] = $true
            $body['location'] = @{
                name        = $Location['name']
                latitude    = $Location['latitude']
                longitude   = $Location['longitude']
                countryCode = $Location['countryCode']
                countryName = $Location['countryName']
            }
        }

        $bodyJson = $body | ConvertTo-Json -Compress -Depth 5

        $target = "IP Range '$Name' ($($Subnets -join ', '))"
        $action = "Create"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Creating IP range: $Name"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for subnets
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationSubnet*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully created IP range: $Name"
                return $result
            }
            catch {
                Write-Error "Failed to create IP range '$Name': $_"
            }
        }
    }

    end {
    }
}
