function Get-XdrTenantContext {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$session = $global:session,

        [Parameter()]
        [string]$headers = $global:headers
    )
    
    Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext?realTime=true" -ContentType "application/json" -WebSession $global:session -Headers $global:headers
}
