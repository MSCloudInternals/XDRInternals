<#
This script publishes the module to the gallery.
It expects as input an ApiKey authorized to publish the module.

Insert any build steps you may need to take before publishing it here.
#>
param (
	$ApiKey,

	$WorkingDirectory,

	$Repository = 'PSGallery',

	[switch]
	$LocalRepo,

	[switch]
	$SkipPublish,

	[switch]
	$AutoVersion,

	[switch]
	$AutoMinorVersion,

	[switch]
	$AutoMajorVersion
)

#region Handle Working Directory Defaults
if (-not $WorkingDirectory) {
	if ($env:RELEASE_PRIMARYARTIFACTSOURCEALIAS) {
		$WorkingDirectory = Join-Path -Path $env:SYSTEM_DEFAULTWORKINGDIRECTORY -ChildPath $env:RELEASE_PRIMARYARTIFACTSOURCEALIAS
	} else { $WorkingDirectory = $env:SYSTEM_DEFAULTWORKINGDIRECTORY }
}
if (-not $WorkingDirectory) { $WorkingDirectory = Split-Path $PSScriptRoot }
#endregion Handle Working Directory Defaults

# Prepare publish folder
Write-Host "Creating and populating publishing directory $($publishDir.FullName)"
$publishDir = New-Item -Path $WorkingDirectory -Name publish -ItemType Directory -Force
Copy-Item -Path "$($WorkingDirectory)\XDRInternals" -Destination $publishDir.FullName -Recurse -Force
#endregion Update the psm1 file & Cleanup

#region Updating the Module Version
if ($AutoVersion -or $AutoMinorVersion -or $AutoMajorVersion) {
	Write-Host  "Updating module version numbers."
	try { [version]$remoteVersion = (Find-Module 'XDRInternals' -Repository $Repository -ErrorAction Stop).Version }
	catch {
		throw "Failed to access $($Repository) : $_"
	}
	if (-not $remoteVersion) {
		throw "Couldn't find XDRInternals on repository $($Repository) : $_"
	}
	if ($AutoMajorVersion) {
		$newMajorNumber = $remoteVersion.Major + 1
		$newMinorNumber = 0
		$newBuildNumber = 0
	} elseif ($AutoMinorVersion) {
		$newMajorNumber = $remoteVersion.Major
		$newMinorNumber = $remoteVersion.Minor + 1
		$newBuildNumber = 0
	} else {
		$newMajorNumber = $remoteVersion.Major
		$newMinorNumber = $remoteVersion.Minor
		$newBuildNumber = $remoteVersion.Build + 1
	}

	Update-ModuleManifest -Path "$($publishDir.FullName)\XDRInternals\XDRInternals.psd1" -ModuleVersion "$($newMajorNumber).$($newMinorNumber).$($newBuildNumber)"
}
#endregion Updating the Module Version

#region Publish
if ($SkipPublish) { return }
if ($LocalRepo) {
	# Dependencies must go first
	Write-Host  "Creating Nuget Package for module: PSFramework"
	New-PSMDModuleNugetPackage -ModulePath (Get-Module -Name PSFramework).ModuleBase -PackagePath .
	Write-Host  "Creating Nuget Package for module: XDRInternals"
	New-PSMDModuleNugetPackage -ModulePath "$($publishDir.FullName)\XDRInternals" -PackagePath .
} else {
	# Publish to Gallery
	Write-Host  "Publishing the XDRInternals module to $($Repository)"
	Publish-Module -Path "$($publishDir.FullName)\XDRInternals" -NuGetApiKey $ApiKey -Force -Repository $Repository
}
#endregion Publish