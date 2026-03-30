function Set-XdrEndpointDeviceTag {
    <#
    .SYNOPSIS
        Sets, adds, or removes user-defined tags on endpoint devices in Microsoft Defender XDR.

    .DESCRIPTION
        Manages user-defined tags on one or more endpoint devices by calling the
        editMachineTags API. Only modifies UserDefinedTags; BuiltInTags and DynamicRulesTags
        are managed through separate mechanisms. Supports two modes:
        - Replace (Tags): Replaces all existing user-defined tags with the provided tags.
        - AddRemove (Add/Remove): Retrieves current user-defined tags, adds and/or removes
          the specified tags, and sets the resulting list. Both -Add and -Remove can be used
          together in a single call.

        When using -Add or -Remove, the cmdlet fetches each device's current user-defined tags
        via Get-XdrEndpointDeviceTag, modifies the list, then calls editMachineTags with the updated set.

    .PARAMETER DeviceId
        One or more device IDs (SenseMachineIds) identifying the target devices.

    .PARAMETER Tags
        Array of tag strings to set on the devices. Replaces all existing user-defined tags.

    .PARAMETER Add
        Array of tag strings to add to each device's existing user-defined tags. Duplicates are ignored.
        Can be combined with -Remove in a single call.

    .PARAMETER Remove
        Array of tag strings to remove from each device's existing user-defined tags.
        Can be combined with -Add in a single call.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .EXAMPLE
        Set-XdrEndpointDeviceTag -DeviceId "abc123" -Tags "Production", "VDI"
        Replaces all user-defined tags on the device with Production and VDI.

    .EXAMPLE
        Set-XdrEndpointDeviceTag -DeviceId "abc123" -Add "VDI"
        Adds the VDI tag to the device's existing user-defined tags without removing any.

    .EXAMPLE
        Set-XdrEndpointDeviceTag -DeviceId "abc123" -Remove "TestTag"
        Removes the TestTag from the device, keeping all other user-defined tags.

    .EXAMPLE
        Set-XdrEndpointDeviceTag -DeviceId "abc123" -Add "Production" -Remove "TestTag"
        Adds the Production tag and removes the TestTag in a single operation.

    .EXAMPLE
        Set-XdrEndpointDeviceTag -DeviceId "abc123", "def456" -Add "Production"
        Adds the Production tag to multiple devices.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess implemented in process block')]
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Replace')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$DeviceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Replace')]
        [Alias('MachineTags')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Tags,

        [Parameter(Mandatory = $false, ParameterSetName = 'AddRemove')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Add,

        [Parameter(Mandatory = $false, ParameterSetName = 'AddRemove')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Remove
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Replace' {
                # Direct replace - set exactly these tags on all devices
                $tagsJson = ConvertTo-Json -InputObject @($Tags) -Compress
                $body = @{
                    InternalMachineIds = @(0)
                    MachineTags        = $tagsJson
                    SenseMachineIds    = $DeviceId
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Devices: $($DeviceId -join ', ')", "Set tags: $($Tags -join ', ')")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/editMachineTags"
                        Write-Verbose "Setting tags on $($DeviceId.Count) device(s): $($Tags -join ', ')"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        return $result
                    } catch {
                        Write-Error "Failed to set device tags: $_"
                    }
                }
            }

            'AddRemove' {
                # Validate that at least one of -Add or -Remove was specified
                if (-not $Add -and -not $Remove) {
                    Write-Error "You must specify at least one of -Add or -Remove."
                    return
                }

                # Per-device: get current tags, add and/or remove as specified, set resulting list
                foreach ($machineId in $DeviceId) {
                    try {
                        $deviceTags = Get-XdrEndpointDeviceTag -DeviceId $machineId -Force
                        $currentTags = @($deviceTags.UserDefinedTags | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                        $updatedTags = $currentTags

                        # Add tags first
                        if ($Add) {
                            $updatedTags = @($updatedTags + $Add | Select-Object -Unique)
                        }

                        # Then remove tags
                        if ($Remove) {
                            $updatedTags = @($updatedTags | Where-Object { $_ -notin $Remove })
                        }

                        if ($updatedTags.Count -eq 0) {
                            Write-Warning "All tags will be removed from device $machineId. Device will have no user-defined tags."
                            $updatedTags = @()
                        }

                        # Build action description
                        $actions = @()
                        if ($Add) { $actions += "Add: $($Add -join ', ')" }
                        if ($Remove) { $actions += "Remove: $($Remove -join ', ')" }
                        $actionDesc = $actions -join '; '

                        $tagsJson = ConvertTo-Json -InputObject $updatedTags -Compress
                        $body = @{
                            InternalMachineIds = @(0)
                            MachineTags        = $tagsJson
                            SenseMachineIds    = @($machineId)
                        } | ConvertTo-Json -Depth 10

                        if ($PSCmdlet.ShouldProcess("Device: $machineId", "$actionDesc (current: $($currentTags -join ', '))")) {
                            $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/editMachineTags"
                            Write-Verbose "Updating tags on device $machineId - $actionDesc (current: $($currentTags -join ', ') -> result: $($updatedTags -join ', '))"
                            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                            $result
                        }
                    } catch {
                        Write-Error "Failed to update tags on device $machineId`: $_"
                    }
                }
            }
        }
    }

    end {
    }
}
