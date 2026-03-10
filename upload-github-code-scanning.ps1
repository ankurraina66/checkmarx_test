param(
    [string]$SarifFile = "appscan-results.sarif"
)

Write-Host "Starting GitHub Code Scanning upload..."

$appId = $env:GH_APP_ID
$installationId = $env:GH_APP_INSTALLATION_ID
$privateKey = $env:GH_APP_PRIVATE_KEY

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
$exp = $now + 540

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
# DEBUG: Verify JWT works
# -----------------------------

Write-Host "Validating JWT with GitHub..."

$jwtTest = Invoke-RestMethod `
  -Uri "https://api.github.com/app" `
  -Headers @{
      Authorization = "Bearer $jwt"
      Accept = "application/vnd.github+json"
      "X-GitHub-Api-Version" = "2022-11-28"
  }

Write-Host "JWT is valid for GitHub App:"
Write-Host "App ID:" $jwtTest.id
Write-Host "App Name:" $jwtTest.name

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
