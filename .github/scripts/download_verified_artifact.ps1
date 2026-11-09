param(
    [Parameter(Mandatory = $true)]
    [uri] $Url,
    [Parameter(Mandatory = $true)]
    [string] $Output,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string] $Sha256
)

$ErrorActionPreference = "Stop"
if ($Url.Scheme -ne "https" -and -not ($Url.Scheme -eq "http" -and $Url.IsLoopback)) {
    throw "Artifact URL must use HTTPS."
}

$maximumAttempts = 3
$partialOutput = "$Output.$PID.partial"
$downloaded = $false
for ($attempt = 1; $attempt -le $maximumAttempts; $attempt++) {
    try {
        Invoke-WebRequest -Uri $Url -OutFile $partialOutput -TimeoutSec 120 | Out-Null
        $downloaded = $true
        break
    }
    catch {
        Remove-Item -LiteralPath $partialOutput -Force -ErrorAction SilentlyContinue
        $statusCode = 0
        $response = $_.Exception.Response
        if ($null -ne $response -and $null -ne $response.StatusCode) {
            $statusCode = [int] $response.StatusCode
        }
        $transientStatus = $statusCode -eq 0 -or $statusCode -in @(408, 429) -or ($statusCode -ge 500 -and $statusCode -lt 600)
        if (-not $transientStatus -or $attempt -eq $maximumAttempts) {
            throw
        }
        Start-Sleep -Seconds $attempt
    }
}

if (-not $downloaded) {
    throw "Artifact download failed after $maximumAttempts attempts."
}
$actualSha256 = (Get-FileHash -Algorithm SHA256 -Path $partialOutput).Hash.ToLowerInvariant()
if ($actualSha256 -ne $Sha256.ToLowerInvariant()) {
    Remove-Item -LiteralPath $partialOutput -Force
    throw "Artifact SHA-256 mismatch: expected $Sha256, got $actualSha256"
}
Move-Item -LiteralPath $partialOutput -Destination $Output -Force
