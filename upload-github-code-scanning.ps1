param(
    [string]$SarifFile = "appscan-results.sarif"
)

Write-Host "Starting GitHub Code Scanning upload..."

$appId = $env:GH_APP_ID
$installationId = $env:GH_APP_INSTALLATION_ID
$privateKey = $env:GH_APP_PRIVATE_KEY

if ($privateKey) {
    $privateKey = $privateKey -replace "\\n","`n"
}

if (!$appId -or !$installationId -or !$privateKey) {
    Write-Error "Missing GitHub App environment variables"
    exit 1
}

Write-Host "GitHub App ID: $appId"
Write-Host "Installation ID: $installationId"

# -----------------------------
# Create JWT
# -----------------------------

$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$exp = $now + 600

$header = @{
    alg = "RS256"
    typ = "JWT"
}

$payload = @{
    iat = $now
    exp = $exp
    iss = $appId
}

function Base64UrlEncode($input) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($input)
    $base64 = [Convert]::ToBase64String($bytes)
    return $base64.TrimEnd("=") -replace "\+", "-" -replace "/", "_"
}

$headerEncoded = Base64UrlEncode ($header | ConvertTo-Json -Compress)
$payloadEncoded = Base64UrlEncode ($payload | ConvertTo-Json -Compress)

$unsignedToken = "$headerEncoded.$payloadEncoded"

# -----------------------------
# Sign JWT
# -----------------------------

$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportFromPem($privateKey)

$signatureBytes = $rsa.SignData(
    [System.Text.Encoding]::UTF8.GetBytes($unsignedToken),
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

$signature = [Convert]::ToBase64String($signatureBytes)
$signature = $signature.TrimEnd("=") -replace "\+", "-" -replace "/", "_"

$jwt = "$unsignedToken.$signature"

Write-Host "JWT generated"

# -----------------------------
# Get installation token
# -----------------------------

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

# -----------------------------
# Validate SARIF file
# -----------------------------

if (!(Test-Path $SarifFile)) {
    Write-Error "SARIF file not found: $SarifFile"
    exit 1
}

# -----------------------------
# Compress SARIF
# -----------------------------

$gzipFile = "$SarifFile.gz"

$inStream = [System.IO.File]::OpenRead($SarifFile)
$outStream = [System.IO.File]::Create($gzipFile)
$gzipStream = New-Object System.IO.Compression.GzipStream($outStream, [System.IO.Compression.CompressionMode]::Compress)

$inStream.CopyTo($gzipStream)

$gzipStream.Close()
$outStream.Close()
$inStream.Close()

Write-Host "SARIF compressed"

# -----------------------------
# Encode SARIF
# -----------------------------

$bytes = [System.IO.File]::ReadAllBytes($gzipFile)
$sarifEncoded = [Convert]::ToBase64String($bytes)

Write-Host "SARIF encoded"

# -----------------------------
# Upload SARIF
# -----------------------------

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

Write-Host "SARIF uploaded successfully"
