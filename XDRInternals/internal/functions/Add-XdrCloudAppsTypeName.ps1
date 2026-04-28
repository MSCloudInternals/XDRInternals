function Add-XdrCloudAppsTypeName {
    <#
    .SYNOPSIS
        Adds a Cloud Apps PSTypeName to objects.

    .DESCRIPTION
        Adds a PSTypeName to one or more Cloud Apps response objects so default formatting can apply.

    .PARAMETER InputObject
        Object to tag with the provided type name.

    .PARAMETER TypeName
        PSTypeName to insert at the front of the object's type name list.

    .EXAMPLE
        $items | Add-XdrCloudAppsTypeName -TypeName XdrCloudAppsActivity

        Tags activity objects for formatting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    process {
        if ($null -eq $InputObject) {
            return
        }

        if ($InputObject -is [System.Array]) {
            foreach ($item in $InputObject) {
                if ($null -ne $item -and $item.PSObject.TypeNames[0] -ne $TypeName) {
                    $item.PSObject.TypeNames.Insert(0, $TypeName)
                }
                $item
            }
            return
        }

        if ($InputObject.PSObject.TypeNames[0] -ne $TypeName) {
            $InputObject.PSObject.TypeNames.Insert(0, $TypeName)
        }
        $InputObject
    }
}

