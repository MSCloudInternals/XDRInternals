function ConvertFrom-XdrDetectionSourceId {
    <#
    .SYNOPSIS
        Converts detection source IDs to display names.
    
    .DESCRIPTION
        Internal helper function that translates numeric detection source IDs
        to their corresponding display names for Microsoft Defender XDR.
    
    .PARAMETER Id
        The numeric detection source ID to translate.
    
    .EXAMPLE
        ConvertFrom-XdrDetectionSourceId -Id 4096
        Returns "Custom detection"
    
    .EXAMPLE
        1073741845 | ConvertFrom-XdrDetectionSourceId
        Returns "Scheduled detection"
    
    .OUTPUTS
        String
        Returns the display name for the detection source, or the original ID if not found.
    #>
    [OutputType([System.String])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [int]$Id
    )

    process {
        $detectionSources = @{
            0          = "3rd party"
            1          = "EDR"
            2          = "Antivirus"
            4          = "SmartScreen"
            16         = "Bitdefender"
            32         = "Custom TI"
            64         = "Ziften"
            128        = "Lookout"
            256        = "Sentinel One"
            512        = "MDO"
            1024       = "Automated investigation"
            2048       = "Microsoft Threat Experts"
            4096       = "Custom detection"
            8192       = "MDI"
            16384      = "Microsoft Cloud App Security"
            32768      = "Microsoft Defender XDR"
            65536      = "AAD Identity Protection"
            131072     = "Microsoft Application Protection and Governance"
            262144     = "Manual"
            524288     = "Data Loss Prevention"
            1048576    = "App governance Policy"
            2097152    = "App governance Detection"
            4194304    = "Microsoft Defender for Cloud"
            268435456  = "Microsoft Sentinel"
            1073741833 = "Microsoft Defender for IoT"
            1073741834 = "Microsoft Defender for Servers"
            1073741835 = "Microsoft Defender for Storage"
            1073741836 = "Microsoft Defender for DNS"
            1073741837 = "Microsoft Defender for Databases"
            1073741838 = "Microsoft Defender for Containers"
            1073741839 = "Microsoft Defender for Network"
            1073741840 = "Microsoft Defender for App Service"
            1073741841 = "Microsoft Defender for Key Vault"
            1073741842 = "Microsoft Defender for Resource Manager"
            1073741843 = "Microsoft Defender for Api Management"
            1073741844 = "NRT rules"
            1073741845 = "Scheduled detection"
            1073741846 = "Threat Intelligence"
            1073741847 = "ML detection"
            1073741848 = "Microsoft Purview Insider Risk Management"
            1073741849 = "Microsoft Threat Intelligence"
            1073741850 = "Microsoft Defender for AI Services"
            1073741851 = "Security Copilot"
        }

        if ($detectionSources.ContainsKey($Id)) {
            return $detectionSources[$Id]
        } else {
            Write-Verbose "Unknown detection source ID: $Id"
            return [string]$Id
        }
    }
}
