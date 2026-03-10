param(
    [string]$SarifFile = "appscan-results.sarif"
)

Write-Host "Starting GitHub Code Scanning upload..."

$appId = $env:GH_APP_ID
$installationId = $env:GH_APP_INSTALLATION_ID
$privateKey = $env:GH_APP_PRIVATE_KEY

if (!$appId -or !$installationId -or !$privateKey) {
    Write-Error "Missing required GitHub App environment variables"
    exit 1
}

Write-Host "GitHub App ID: $appId"
Write-Host "Installation ID: $installationId"

# ------------------------------------------------
# Normalize private key formatting
# ------------------------------------------------

$privateKey = $privateKey -replace "`r",""
$privateKey = $privateKey -replace "\\n","`n"

$keyPath = "github-app-key.pem"
$privateKey | Out-File -FilePath $keyPath -Encoding ascii

Write-Host "Private key length:" $privateKey.Length

# ------------------------------------------------
# Create JWT
# ------------------------------------------------

$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$exp = $now + 540

$header = '{"alg":"RS256","typ":"JWT"}'

$payload = @{
    iat = $now
    exp = $exp
    iss = $appId
} | ConvertTo-Json -Compress

function Base64UrlEncode($text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $base64 = [Convert]::ToBase64String($bytes)
    return $base64.TrimEnd("=") -replace "\+", "-" -replace "/", "_"
}

$headerEncoded = Base64UrlEncode $header
$payloadEncoded = Base64UrlEncode $payload

$unsignedToken = "$headerEncoded.$payloadEncoded"

Write-Host "Signing JWT..."

$unsignedToken | Out-File jwt.txt -NoNewline

openssl dgst -sha256 -sign $keyPath jwt.txt | openssl base64 -A > sig.txt

$signature = Get-Content sig.txt
$signature = $signature.TrimEnd("=") -replace "\+", "-" -replace "/", "_"

$jwt = "$unsignedToken.$signature"

Write-Host "JWT generated"

# ------------------------------------------------
# Verify JWT (debug)
# ------------------------------------------------

Write-Host "Validating JWT with GitHub..."

$jwtTest = Invoke-RestMethod `
    -Uri "https://api.github.com/app" `
    -Headers @{
        Authorization = "Bearer $jwt"
        Accept = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }

Write-Host "JWT valid for App:" $jwtTest.name

# ------------------------------------------------
# Request installation token
# ------------------------------------------------

Write-Host "Requesting installation token..."

$tokenResponse = Invoke-RestMethod `
    -Uri "https://api.github.com/app/installations/$installationId/access_tokens" `
    -Method POST `
    -Headers @{
        Authorization = "Bearer $jwt"
        Accept = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }

$installationToken = $tokenResponse.token

Write-Host "Installation token generated"

# ------------------------------------------------
# Validate SARIF
# ------------------------------------------------

if (!(Test-Path $SarifFile)) {
    Write-Error "SARIF file not found: $SarifFile"
    exit 1
}

# ------------------------------------------------
# Compress SARIF
# ------------------------------------------------

Write-Host "Compressing SARIF..."

$gzipFile = "$SarifFile.gz"

$inStream = [System.IO.File]::OpenRead($SarifFile)
$outStream = [System.IO.File]::Create($gzipFile)
$gzipStream = New-Object System.IO.Compression.GzipStream($outStream,[System.IO.Compression.CompressionMode]::Compress)

$inStream.CopyTo($gzipStream)

$gzipStream.Close()
$outStream.Close()
$inStream.Close()

Write-Host "SARIF compressed"

# ------------------------------------------------
# Base64 encode SARIF
# ------------------------------------------------

Write-Host "Encoding SARIF..."

$bytes = [System.IO.File]::ReadAllBytes($gzipFile)
$sarifEncoded = [Convert]::ToBase64String($bytes)

# ------------------------------------------------
# Upload SARIF
# ------------------------------------------------

Write-Host "Uploading SARIF to GitHub Code Scanning..."

$body = @{
    commit_sha = $env:GITHUB_SHA
    ref = $env:GITHUB_REF
    sarif = $sarifEncoded
    tool_name = "HCL AppScan DAST"
} | ConvertTo-Json -Depth 10

$uploadUrl = "https://api.github.com/repos/$env:GITHUB_REPOSITORY/code-scanning/sarifs"

$response = Invoke-RestMethod `
    -Uri $uploadUrl `
    -Method POST `
    -Headers @{
        Authorization = "Bearer $installationToken"
        Accept = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    } `
    -Body $body `
    -ContentType "application/json"

Write-Host "SARIF uploaded successfully!"
