#requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputDirectory = (Join-Path $PWD 'signing-output'),

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{1,62}[A-Za-z0-9]$')]
    [string] $Organization = 'Camellia Computing',

    [Parameter()]
    [ValidateRange(1, 20)]
    [int] $RootValidityYears = 10,

    [Parameter()]
    [ValidateRange(1, 36)]
    [int] $LeafValidityMonths = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'This script must run on Windows with PowerShell 7.6 or later.'
}

$requiredCommands = @(
    'New-SelfSignedCertificate',
    'Export-Certificate',
    'Export-PfxCertificate'
)
foreach ($command in $requiredCommands) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required Windows PKI command is unavailable: $command"
    }
}

$resolvedParent = Resolve-Path -LiteralPath (Split-Path -Parent $OutputDirectory)
$outputPath = Join-Path $resolvedParent.Path (Split-Path -Leaf $OutputDirectory)
if (Test-Path -LiteralPath $outputPath) {
    throw "Refusing to overwrite existing output directory: $outputPath"
}

$rootPassword = Read-Host 'Root backup PFX password' -AsSecureString
$leafPassword = Read-Host 'Code-signing PFX password' -AsSecureString

$null = New-Item -ItemType Directory -Path $outputPath
$root = $null
$leaf = $null

try {
    $root = New-SelfSignedCertificate `
        -Type Custom `
        -Subject "CN=$Organization Private Code Signing Root CA, O=$Organization" `
        -FriendlyName "$Organization Private Code Signing Root CA" `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -TextExtension @(
            '2.5.29.19={critical}{text}ca=true&pathlength=0',
            '2.5.29.15={critical}{text}keyCertSign&cRLSign&digitalSignature'
        ) `
        -NotAfter (Get-Date).AddYears($RootValidityYears) `
        -CertStoreLocation 'Cert:\CurrentUser\My'

    $leaf = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$Organization Private Code Signing, O=$Organization" `
        -FriendlyName "$Organization Private Code Signing" `
        -Signer $root `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddMonths($LeafValidityMonths) `
        -CertStoreLocation 'Cert:\CurrentUser\My'

    $rootCer = Join-Path $outputPath 'camellia-private-code-signing-root.cer'
    $rootPfx = Join-Path $outputPath 'camellia-private-code-signing-root-backup.pfx'
    $leafCer = Join-Path $outputPath 'camellia-private-code-signing-leaf.cer'
    $leafPfx = Join-Path $outputPath 'camellia-private-code-signing-leaf.pfx'

    Export-Certificate -Cert $root -FilePath $rootCer -Type CERT | Out-Null
    Export-PfxCertificate `
        -Cert $root `
        -FilePath $rootPfx `
        -Password $rootPassword `
        -ChainOption EndEntityCertOnly | Out-Null
    Export-Certificate -Cert $leaf -FilePath $leafCer -Type CERT | Out-Null
    Export-PfxCertificate `
        -Cert $leaf `
        -FilePath $leafPfx `
        -Password $leafPassword `
        -ChainOption EndEntityCertOnly | Out-Null

    Write-Host "Created private signing material in: $outputPath"
    Write-Host "Root thumbprint: $($root.Thumbprint)"
    Write-Host "Leaf thumbprint: $($leaf.Thumbprint)"
    Write-Warning 'Keep both PFX files and their passwords offline. Install only the public root CER on explicitly managed test machines.'
}
finally {
    if ($null -ne $leaf -and -not [string]::IsNullOrWhiteSpace($leaf.Thumbprint)) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($leaf.Thumbprint)" -ErrorAction SilentlyContinue
    }
    if ($null -ne $root -and -not [string]::IsNullOrWhiteSpace($root.Thumbprint)) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($root.Thumbprint)" -ErrorAction SilentlyContinue
    }
}
