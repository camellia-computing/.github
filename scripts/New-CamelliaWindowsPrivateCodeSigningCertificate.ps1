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
    'Export-PfxCertificate',
    'Get-PfxData'
)
foreach ($command in $requiredCommands) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required Windows PKI command is unavailable: $command"
    }
}

$bundleGenerator = Join-Path $PSScriptRoot 'create-github-signing-bundle.py'
$bundleGeneratorItem = Get-Item -LiteralPath $bundleGenerator -Force -ErrorAction SilentlyContinue
if ($null -eq $bundleGeneratorItem) {
    throw "The GitHub Actions bundle generator is unavailable or unsafe: $bundleGenerator"
}
if ($bundleGeneratorItem.PSIsContainer -or
    -not [string]::IsNullOrEmpty([string] $bundleGeneratorItem.LinkType)) {
    throw "The GitHub Actions bundle generator must be a regular file: $bundleGenerator"
}
$pythonCommand = Get-Command python -CommandType Application -ErrorAction SilentlyContinue
$pythonArguments = @()
if ($null -eq $pythonCommand) {
    $pythonCommand = Get-Command py -CommandType Application -ErrorAction SilentlyContinue
    $pythonArguments = @('-3')
}
if ($null -eq $pythonCommand) {
    throw 'Python 3 is required to create the standardized GitHub Actions bundle.'
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
        -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=0') `
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

    $rootConstraints = @(
        $root.Extensions | Where-Object {
            $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
        }
    )
    $rootKeyUsage = @(
        $root.Extensions | Where-Object {
            $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]
        }
    )
    $leafCodeSigningEku = @(
        $leaf.Extensions |
            Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
            } |
            ForEach-Object { $_.EnhancedKeyUsages } |
            Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }
    )
    if ($rootConstraints.Count -ne 1 -or
        -not $rootConstraints[0].CertificateAuthority -or
        $rootConstraints[0].HasPathLengthConstraint -eq $false -or
        $rootConstraints[0].PathLengthConstraint -ne 0) {
        throw 'The generated root does not have the required CA path-length-zero constraint.'
    }
    if ($rootKeyUsage.Count -ne 1 -or
        -not $rootKeyUsage[0].KeyUsages.HasFlag(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign
        ) -or
        -not $rootKeyUsage[0].KeyUsages.HasFlag(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        )) {
        throw 'The generated root does not have the required certificate/CRL signing usages.'
    }
    if ($leafCodeSigningEku.Count -ne 1) {
        throw 'The generated leaf does not have the required code-signing EKU.'
    }

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
        -ChainOption BuildChain | Out-Null
    $exportedLeafPfx = Get-PfxData -FilePath $leafPfx -Password $leafPassword
    $exportedLeaves = @($exportedLeafPfx.EndEntityCertificates | Where-Object { $_ })
    $exportedChain = @($exportedLeafPfx.OtherCertificates | Where-Object { $_ })
    if ($exportedLeaves.Count -ne 1 -or
        $exportedLeaves[0].Thumbprint -ne $leaf.Thumbprint) {
        throw 'The exported code-signing PFX does not contain the exact leaf identity.'
    }
    if ($root.Thumbprint -notin @(
        $exportedChain | ForEach-Object { $_.Thumbprint }
    )) {
        throw 'The exported code-signing PFX does not contain its private verification root.'
    }
    if (@($exportedChain | Where-Object { $_.HasPrivateKey }).Count -ne 0) {
        throw 'The exported code-signing PFX unexpectedly contains a chain private key.'
    }

    $identityPath = Join-Path $outputPath 'camellia-private-code-signing-identity.json'
    $identity = [ordered]@{
        schemaVersion = 1
        platform = 'windows'
        distributionTrust = 'private-trust'
        subject = $leaf.Subject
        issuer = $leaf.Issuer
        serialNumber = $leaf.SerialNumber
        notBefore = $leaf.NotBefore.ToUniversalTime().ToString('O')
        notAfter = $leaf.NotAfter.ToUniversalTime().ToString('O')
        certificateSha256 = $leaf.GetCertHashString(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        ).ToUpperInvariant()
        nativeSha1Thumbprint = $leaf.Thumbprint.ToUpperInvariant()
    }
    $identity |
        ConvertTo-Json |
        Set-Content -LiteralPath $identityPath -Encoding utf8NoBOM

    $bundleInputDirectory = Join-Path $outputPath '.github-actions-input'
    $bundlePasswordPath = Join-Path $bundleInputDirectory 'WINDOWS_CODESIGN_PFX_PASSWORD'
    $null = New-Item -ItemType Directory -Path $bundleInputDirectory
    try {
        $leafPasswordText = [System.Net.NetworkCredential]::new('', $leafPassword).Password
        if ([string]::IsNullOrEmpty($leafPasswordText)) {
            throw 'Code-signing PFX password must not be empty.'
        }
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($bundlePasswordPath, $leafPasswordText, $utf8NoBom)

        & $pythonCommand.Source @pythonArguments $bundleGenerator $outputPath `
            --platform windows `
            --distribution-trust private-trust `
            --identity-file $identityPath `
            --variable "WINDOWS_CODESIGN_CERTIFICATE_SHA256=$($identity.certificateSha256)" `
            --variable "WINDOWS_CODESIGN_CERTIFICATE_THUMBPRINT=$($identity.nativeSha1Thumbprint)" `
            --variable 'WINDOWS_SIGNING_TRUST_MODE=private-trust' `
            --secret-base64 "WINDOWS_CODESIGN_PFX_BASE64=$leafPfx" `
            --secret "WINDOWS_CODESIGN_PFX_PASSWORD=$bundlePasswordPath"
        if ($LASTEXITCODE -ne 0) {
            throw 'Failed to create the standardized GitHub Actions signing bundle.'
        }
    }
    finally {
        $leafPasswordText = $null
        if (Test-Path -LiteralPath $bundleInputDirectory) {
            Remove-Item -LiteralPath $bundleInputDirectory -Recurse -Force
        }
    }

    Write-Host "Created private signing material in: $outputPath"
    Write-Host "Root thumbprint: $($root.Thumbprint)"
    Write-Host "Leaf thumbprint: $($leaf.Thumbprint)"
    Write-Host "Public identity metadata: $identityPath"
    Write-Host "GitHub Actions configuration bundle: $(Join-Path $outputPath 'github-actions')"
    Write-Warning 'Keep both PFX files and their passwords offline. Review the generated variables.env, then use its upload helper without printing secret files. Install only the public root CER on explicitly managed test machines.'
}
finally {
    if ($null -ne $leaf -and -not [string]::IsNullOrWhiteSpace($leaf.Thumbprint)) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($leaf.Thumbprint)" -ErrorAction SilentlyContinue
    }
    if ($null -ne $root -and -not [string]::IsNullOrWhiteSpace($root.Thumbprint)) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($root.Thumbprint)" -ErrorAction SilentlyContinue
    }
}
