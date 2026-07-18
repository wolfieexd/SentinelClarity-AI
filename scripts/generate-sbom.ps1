param(
    [string]$OutputPath = "artifacts/sentinel-sbom.cdx.json"
)

$metadata = cargo metadata --locked --format-version 1 | ConvertFrom-Json
$components = @(
    $metadata.packages | ForEach-Object {
        $component = [ordered]@{
            type = "library"
            name = $_.name
            version = $_.version
            purl = "pkg:cargo/$($_.name)@$($_.version)"
        }
        if ($_.license) {
            $component.licenses = @(@{ license = @{ name = $_.license } })
        }
        [PSCustomObject]$component
    }
)

$sbom = [ordered]@{
    bomFormat = "CycloneDX"
    specVersion = "1.5"
    version = 1
    metadata = [ordered]@{
        component = [ordered]@{
            type = "application"
            name = "SentinelClarity"
            version = ($metadata.packages | Where-Object { $_.name -eq "sentinel-cli" } | Select-Object -First 1).version
        }
    }
    components = $components
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}

$sbom | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding utf8
Write-Output "SBOM written to $OutputPath"
