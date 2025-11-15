function Get-XdrEndpointDeviceTimeline {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$DeviceId
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $DeviceId
        https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/0654e5d8dc5fc2c9e6bc501359e9e7abad16bd72/events/
    }
    
    end {
        
    }
}