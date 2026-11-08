# ============================================================================
#  luminosity :: fileless edition
#  Paste-to-run loader. Nothing touches disk.
#
#  Flow: console key system (KeyAuth 1.3 REST) -> fetch AES key from an
#  authenticated-only global variable -> download the encrypted payload from
#  GitHub raw (public but AES-encrypted) -> decrypt in memory ->
#  manual-map into this PowerShell process -> watchdog loop re-validates the
#  session every few minutes and kills everything on a server-side revocation
#  verdict.
#
#  Dev params (not available via irm|iex - disk-run only):
#    -LocalBlob <path>  decrypt+map from a local payload.enc (no KeyAuth)
#    -NoPatch           skip the AMSI patch (debugging)
#    -TestMap           skip auth, decrypt with the local tools key, map, idle
# ============================================================================
param(
    [string]$LocalBlob = '',
    [switch]$NoPatch,
    [switch]$TestMap       # dev: skip auth, decrypt with local key, map, idle
)

# -- config ------------------------------------------------------------------
$KaName    = 'Luminosity-fileless'
$KaOwner   = 'HzZmPin0u1'
$KaVersion = '1.0'
$KaUrl     = 'https://keyauth.win/api/1.3/'
$VarName   = 'pl_cfg'          # AES-256 key (64 hex chars), Authenticated variable
$BlobUrl   = 'https://raw.githubusercontent.com/luminositygg/luminosity-fileless/main/payload.enc'
$WatchSecs = 300               # session re-check cadence while the cheat runs

# -- ui helpers --------------------------------------------------------------
$Host.UI.RawUI.WindowTitle = 'luminosity.gg'

function Write-Brand {
    Write-Host ''
    Write-Host '  =====================================' -ForegroundColor DarkMagenta
    Write-Host '   luminosity  ::  fileless edition'     -ForegroundColor Magenta
    Write-Host '  =====================================' -ForegroundColor DarkMagenta
    Write-Host ''
}
function Write-Ok([string]$m)   { Write-Host "  [+] $m" -ForegroundColor Green }
function Write-Err([string]$m)  { Write-Host "  [-] $m" -ForegroundColor Red }
function Write-Info([string]$m) { Write-Host "  [ ] $m" -ForegroundColor Gray }

# -- hwid --------------------------------------------------------------------
# MachineGuid: stable per-Windows-install, no admin needed, 36 chars
# (KeyAuth app requires >= 20).
$script:Hwid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction Stop).MachineGuid

# -- keyauth client (1.3 REST, mirrors lumi_auth_host's SDK) ----------------
$script:SessionId = ''
$script:User      = ''
$script:Expiry    = 0

function Invoke-Ka {
    param([string]$Query)
    return Invoke-RestMethod -Uri ($KaUrl + '?' + $Query) -Method Post `
        -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30
}

function Start-Session {
    $r = Invoke-Ka "type=init&ver=$KaVersion&name=$KaName&ownerid=$KaOwner"
    if (-not $r.success) { throw "app init failed: $($r.message)" }
    $script:SessionId = $r.sessionid
}

# furthest subscription expiry, unix seconds (same rule the broker uses)
function Get-FurthestExpiry($info) {
    $max = [long]0
    if ($info -and $info.subscriptions) {
        foreach ($s in @($info.subscriptions)) {
            $e = 0
            if (-not [long]::TryParse([string]$s.expiry, [ref]$e)) { continue }
            if ($e -gt $max) { $max = $e }
        }
    }
    return $max
}

function Invoke-Login {
    param([string]$U, [string]$P, [string]$Code = '')
    $r = Invoke-Ka "type=login&username=$([uri]::EscapeDataString($U))&pass=$([uri]::EscapeDataString($P))&code=$([uri]::EscapeDataString($Code))&hwid=$([uri]::EscapeDataString($script:Hwid))&sessionid=$script:SessionId&name=$KaName&ownerid=$KaOwner"
    return $r
}

function Invoke-Register {
    param([string]$U, [string]$P, [string]$Key)
    $r = Invoke-Ka "type=register&username=$([uri]::EscapeDataString($U))&pass=$([uri]::EscapeDataString($P))&key=$([uri]::EscapeDataString($Key))&email=&hwid=$([uri]::EscapeDataString($script:Hwid))&sessionid=$script:SessionId&name=$KaName&ownerid=$KaOwner"
    return $r
}

function Invoke-License {
    param([string]$Key)
    $r = Invoke-Ka "type=license&key=$([uri]::EscapeDataString($Key))&code=&hwid=$([uri]::EscapeDataString($script:Hwid))&sessionid=$script:SessionId&name=$KaName&ownerid=$KaOwner"
    return $r
}

function Test-Session {
    try {
        $r = Invoke-Ka "type=check&sessionid=$script:SessionId&name=$KaName&ownerid=$KaOwner"
        return [bool]$r.success
    } catch {
        return $true   # network fault: never a verdict (matches the loader's resilience)
    }
}

function Format-Expiry([long]$unix) {
    if ($unix -le 0) { return 'lifetime' }
    $left = $unix - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($left -le 0) { return 'expired' }
    $d = [Math]::Floor($left / 86400)
    $h = [Math]::Floor(($left % 86400) / 3600)
    if ($d -gt 0) { return "$d d $($h) h" }
    $m = [Math]::Floor(($left % 3600) / 60)
    return "$h h $m m"
}

# -- key system --------------------------------------------------------------
function Show-KeySystem {
    while ($true) {
        Write-Host ''
        Write-Host '   [1] login            (username + password)' -ForegroundColor White
        Write-Host '   [2] register         (username + password + key)' -ForegroundColor White
        Write-Host '   [3] license key' -ForegroundColor White
        Write-Host '   [4] exit' -ForegroundColor White
        $choice = "$(Read-Host '   choice')".Trim()

        if ($choice -eq '4') { return $false }

        if ($choice -eq '1') {
            $u = "$(Read-Host '   username')".Trim()
            $p = "$(Read-Host '   password')".Trim()
            if (-not $u -or -not $p) { Write-Err 'fill in every field.'; continue }
            try { $r = Invoke-Login -U $u -P $p } catch { Write-Err 'connection failed - try again.'; continue }
            if ($r.success) {
                $script:User = $u; $script:Expiry = Get-FurthestExpiry $r.info
                return $true
            }
            if ($r.message -match '2fa') {
                $code = "$(Read-Host '   2FA code')".Trim()
                try { $r = Invoke-Login -U $u -P $p -Code $code } catch { Write-Err 'connection failed - try again.'; continue }
                if ($r.success) {
                    $script:User = $u; $script:Expiry = Get-FurthestExpiry $r.info
                    return $true
                }
            }
            Write-Err $r.message
            continue
        }

        if ($choice -eq '2') {
            $u = "$(Read-Host '   username')".Trim()
            $p = "$(Read-Host '   password')".Trim()
            $k = "$(Read-Host '   key')".Trim()
            if (-not $u -or -not $p -or -not $k) { Write-Err 'fill in every field.'; continue }
            try { $r = Invoke-Register -U $u -P $p -Key $k } catch { Write-Err 'connection failed - try again.'; continue }
            if ($r.success) {
                $script:User = $u; $script:Expiry = Get-FurthestExpiry $r.info
                return $true
            }
            Write-Err $r.message
            continue
        }

        if ($choice -eq '3') {
            $k = "$(Read-Host '   key')".Trim()
            if (-not $k) { Write-Err 'enter a key.'; continue }
            try { $r = Invoke-License -Key $k } catch { Write-Err 'connection failed - try again.'; continue }
            if ($r.success) {
                $script:User = $k; $script:Expiry = Get-FurthestExpiry $r.info
                return $true
            }
            Write-Err $r.message
            continue
        }
    }
}

# ============================================================================
#  native shim (precompiled, loaded from memory)
# ============================================================================
$shimB64 = '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gACRIIsADwACAAAAAACAAJEglAAVAAQAUCAAAAAAkQCcABsABgCUIAAAAACRAJ4AIAAHAMQgAAAAAJYAogAmAAkAlCEAAAAAkQCnACoACQDAIQAAAACRAKsANAANAOAhAAAAAJEAswA8ABAADCIAAAAAlgC7AEMAEgAAAAAAAwCGGMAASQATAAAAAAADAMYBxgBPABUAAAAAAAMAxgHoAFcAGQAAAAAAAwDGAfQAYwAfAAAAAAADAIYYwABJACAAAAAAAAMAxgHGAGkAIgAAAAAAAwDGAegAcgAmAAAAAAADAMYB9AB/ACwAAAAAAAMAhhjAAEkALgAAAAAAAwDGAcYAhwAwAAAAAAADAMYB6ACOADMAAAAAAAMAxgH0AJkAOAAAAAAAAwCGGMAASQA5AAAAAAADAMYBxgCfADsAAAAAAAMAxgHoAKYAPgAAAAAAAwDGAfQAsQBDAAAAAAADAIYYwABJAEQAAAAAAAMAxgHGALcARgAAAAAAAwDGAegApgBJAAAAAAADAMYB9AC+AE4AAAABAP4AAAABAAMBAAACAP4AAAABAAMBAAACAAcBAAABAA8BAAABABMBAAACAP4AAAABABcBAAACABoBAAADACEBAgAEACcBAAABAFgBAAACAF4BAAADAGIBAAABAFgBAAACAF4BAAABABcBAAABAGgBAAACAG8BAAABAHYBAAACACcBAAADAHsBAAAEAIEBAAABAHYBAAACACcBAAADAHsBAAAEAIEBAAAFAIkBAAAGAGgBAAABAJIBAAABAGgBAAACAG8BAAABAHYBAAACACcBAAADAIEBAgAEAJkBAAABAHYBAAACACcBAAADAIEBAgAEAJkBAAAFAIkBAAAGAGgBAgABAJkBAAACAJIBAAABAGgBAAACAG8BAAABAJ0BAAACAKMBAAADAKkBAAABAJ0BAAACAKMBAAADAKkBAAAEAIkBAAAFAGgBAAABAJIBAAABAGgBAAACAG8BAAABALMBAAACALwBAAADAMMBAAABALMBAAACALwBAAADAMMBAAAEAIkBAAAFAGgBAAABAJIBAAABAGgBAAACAG8BAAABALMBAAACALwBAAADAMMBAAABALMBAAACALwBAAADAMMBAAAEAIkBAAAFAGgBAAABAJIBKQDAAMQAMQDAAMgAOQDAAMQAQQDAAM0ASQBiAtIAWQCNAtgAWQCXAt0AYQCoAukAYQCtAuwAaQDQAvYAeQDzAv0AiQAZAwUBeQAlAwoBkQA3AyABkQA/AysBmQBVAzEBWQCXAkEBkQBfA0kBqQDAAM0AkQByA1ABkQB7A1cBiQAZA14BYQAZA2MBsQCJA2gBuQCUA24BYQAZA3QBYQCbA3kBYQDAAH0BeQCjA2MBLgATAMMBLgAbAMwB4wDyABMBJwE8AYIBQgJCAQMAfgABAEIBBQBLAgEAQAEHAEsCAQAEgAAAAAAAAAAAAAAAAAAAAAAqAgAABAAAAAAAAAAAAAAAAQBVAAAAAAADAAIABAACAAUAAgAGAAIABwACAAAAAAAAPE1vZHVsZT4Ac2hpbS5kbGwAQ29yZQBMdW0ARGVsQWxsb2MARGVsUHJvdGVjdABEZWxUYWJsZQBEbGxNYWluRGVsZWdhdGUAVGxzQ2FsbGJhY2sAbXNjb3JsaWIAU3lzdGVtAE9iamVjdABNdWx0aWNhc3REZWxlZ2F0ZQBMb2FkTGlicmFyeUEAUHJvY05hbWUAUHJvY09yZABEAFJlcwBQcmVwAERpcgBXcml0ZTY0AFpTdHJpbmcATG9hZAAuY3RvcgBJbnZva2UASUFzeW5jUmVzdWx0AEFzeW5jQ2FsbGJhY2sAQmVnaW5JbnZva2UARW5kSW52b2tlAG5hbWUAbW9kAG9yZGluYWwAYjY0AGRsbABwZQBkaXJPZmYAaW5kZXgAc2l6ZQBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAT3V0QXR0cmlidXRlAGltYWdlAHJ2YQB2YWx1ZQBvYmplY3QAbWV0aG9kAGFkZHIAYWxsb2MAcHJvdGVjdABjYWxsYmFjawByZXN1bHQAb2xkAHRhYmxlAGNvdW50AGltYWdlQmFzZQBpbnN0YW5jZQByZWFzb24AcmVzZXJ2ZWQAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAHNoaW0ARGxsSW1wb3J0QXR0cmlidXRlAGtlcm5lbDMyAEdldFByb2NBZGRyZXNzAENvbnZlcnQARnJvbUJhc2U2NFN0cmluZwBCeXRlAFN5c3RlbS5U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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

function Install-NativeShim {
    # precompiled shim, loaded from memory - nothing touches disk
    [void][Reflection.Assembly]::Load([Convert]::FromBase64String($shimB64))
}

# -- payload -----------------------------------------------------------------
function Get-PayloadBlob {
    if ($LocalBlob) {
        Write-Info "dev: local blob $LocalBlob"
        return [IO.File]::ReadAllBytes($LocalBlob)
    }
    if (-not $BlobUrl) { throw "no blob url configured and no -LocalBlob given" }
    Write-Info 'downloading payload...'
    $r = Invoke-WebRequest -Uri $BlobUrl -UseBasicParsing -TimeoutSec 120
    return $r.Content
}

function ConvertFrom-Hex([string]$hex) {
    if ($hex -notmatch '^[0-9a-fA-F]{64}$') { throw 'payload key is not 64 hex chars' }
    $b = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    return $b
}

function Decrypt-Payload {
    param([byte[]]$Blob, [string]$KeyHex)
    $key = ConvertFrom-Hex $KeyHex
    $iv = New-Object byte[] 16
    [Array]::Copy($Blob, 0, $iv, 0, 16)
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.KeySize = 256
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $dec = $aes.CreateDecryptor()
    return $dec.TransformFinalBlock($Blob, 16, $Blob.Length - 16)
}

# -- watchdog: server-side enforcement while the cheat runs -----------------
# A definitive success:false (revoked / expired / banned) kills the process.
# Network faults never count as a verdict - the loader build tolerates those
# too, and killing someone mid-game over lost wifi is worse than the risk.
function Start-Watchdog {
    while ($true) {
        Start-Sleep -Seconds $WatchSecs
        $ok = Test-Session
        if (-not $ok) {
            Write-Host ''
            Write-Err 'session revoked or expired - closing.'
            Start-Sleep -Seconds 3
            Stop-Process -Id $PID -Force
        }
    }
}

# ============================================================================
#  main
# ============================================================================
Write-Brand

if ($TestMap) {
    # dev-only path: local key, no auth, no watchdog. Validates decrypt +
    # map + DLL startup mechanics. The mapped cheat waits for Roblox.
    $keyHex = (Get-Content (Join-Path $PSScriptRoot '..\tools\payload_key.txt') -Raw).Trim()
    $blobPath = if ($LocalBlob) { $LocalBlob } else { Join-Path $PSScriptRoot '..\payload\payload.enc' }
    try {
        Install-NativeShim
        $blob = [IO.File]::ReadAllBytes($blobPath)
        Write-Ok ("blob loaded ({0} KB)" -f [Math]::Round($blob.Length / 1KB))
        $pe = Decrypt-Payload -Blob $blob -KeyHex $keyHex
        Write-Ok ("payload decrypted ({0} KB)" -f [Math]::Round($pe.Length / 1KB))
        $base = [Lum.Core]::Load($pe)
        Write-Ok ("mapped at 0x{0:X} - cheat thread started" -f $base)
        Write-Info 'test mode: idling (no watchdog). kill this process when done.'
        while ($true) { Start-Sleep -Seconds 60 }
    } catch {
        Write-Err $_.Exception.Message
        return
    }
}

try {
    Write-Info 'connecting...'
    Start-Session
    Write-Ok 'connected'
} catch {
    Write-Err $_.Exception.Message
    Write-Host ''
    return
}

if (-not (Show-KeySystem)) { return }

Write-Ok ("welcome, {0} - subscription: {1}" -f $script:User, (Format-Expiry $script:Expiry))

# identity for the overlay watermark (read via env by the mapped image)
$env:LUM_USER   = $script:User
$env:LUM_EXPIRY = [string]$script:Expiry

# fetch the payload key: authenticated sessions only (dashboard "Authenticated" flag).
# type=var = GLOBAL variables (the dashboard's Global Variables tab); the value
# arrives in the message field. (type=getvar is the per-USER variable store.)
try {
    Write-Info 'fetching payload key...'
    $keyResp = Invoke-Ka "type=var&varid=$VarName&sessionid=$script:SessionId&name=$KaName&ownerid=$KaOwner"
    if (-not $keyResp.success) { throw "key fetch failed: $($keyResp.message)" }
    $payloadKey = [string]$keyResp.message
    if (-not $payloadKey) { throw 'key fetch returned empty' }
    Write-Ok 'payload key ready'
} catch {
    Write-Err $_.Exception.Message
    return
}

# native shim
try {
    Install-NativeShim
} catch {
    Write-Err "native shim failed: $($_.Exception.Message)"
    return
}

# download + decrypt + map
try {
    $blob = Get-PayloadBlob
    Write-Ok ("payload received ({0} KB)" -f [Math]::Round($blob.Length / 1KB))
    $pe = Decrypt-Payload -Blob $blob -KeyHex $payloadKey
    Write-Ok ("payload decrypted ({0} KB)" -f [Math]::Round($pe.Length / 1KB))
    $base = [Lum.Core]::Load($pe)
    Write-Ok ('loaded - waiting for Roblox. Close this window to stop everything.')
} catch {
    Write-Err $_.Exception.Message
    return
}

# the mapped image runs on its own thread; this thread enforces the license
Start-Watchdog