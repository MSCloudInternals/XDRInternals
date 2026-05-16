function ConvertFrom-XdrCloudAppsActivityJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Json
    )

    return $Json | ConvertFrom-Json -AsHashtable -ErrorAction Stop
}

function Read-XdrCloudAppsActivityChunkFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter()]
        [switch]$AllowPartial
    )

    try {
        return ConvertFrom-XdrCloudAppsActivityJson -Json (Get-Content -Path $File.FullName -Raw -ErrorAction Stop)
    }
    catch {
        if ($AllowPartial) {
            Write-Warning "Skipping unreadable Cloud Apps activity chunk file '$($File.Name)': $($_.Exception.Message)"
            return $null
        }

        throw
    }
}

function Get-XdrCloudAppsObjectValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Name
    )

    foreach ($currentName in $Name) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($currentName)) {
                return $InputObject[$currentName]
            }

            foreach ($key in $InputObject.Keys) {
                if ([string]$key -ceq $currentName) {
                    return $InputObject[$key]
                }
            }

            foreach ($key in $InputObject.Keys) {
                if ([string]$key -ieq $currentName) {
                    return $InputObject[$key]
                }
            }
        }
        elseif ($InputObject.PSObject.Properties[$currentName]) {
            return $InputObject.$currentName
        }
    }

    return $null
}

function Get-XdrCloudAppsActivityEventTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Activity
    )

    $timestampValue = Get-XdrCloudAppsObjectValue -InputObject $Activity -Name 'timestamp'
    if ($timestampValue) {
        $numericTimestamp = [double]$timestampValue
        if ($numericTimestamp -gt 9999999999) {
            return [DateTimeOffset]::FromUnixTimeMilliseconds([long]$numericTimestamp).UtcDateTime
        }

        return [DateTimeOffset]::FromUnixTimeSeconds([long]$numericTimestamp).UtcDateTime
    }

    $dateValue = Get-XdrCloudAppsObjectValue -InputObject $Activity -Name @('date', 'Date')
    if ($dateValue) {
        return ([datetime]$dateValue).ToUniversalTime()
    }

    return $null
}

function Get-XdrCloudAppsActivityStableKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Activity,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.SHA256]$Sha256
    )

    foreach ($name in @('_id', 'id', 'recordId')) {
        $value = Get-XdrCloudAppsObjectValue -InputObject $Activity -Name $name
        if ($value) {
            return [string]$value
        }
    }

    $stableJson = $Activity | ConvertTo-Json -Depth 20 -Compress
    return [System.BitConverter]::ToString($Sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stableJson))).Replace('-', '')
}
