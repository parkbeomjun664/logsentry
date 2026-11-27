# InfoGuard self-test: prove a REAL incident alert email reaches the inbox, end to end.
#
# WHAT IT DOES / DOES NOT TOUCH
#   - Starts a SEPARATE, throwaway InfoGuard on a spare port, reading a SYNTHETIC attack
#     log file in a temp folder. It reuses the real config ONLY so the real email account
#     sends the mail. It then sends 3 real incident emails to the address in the config.
#   - It does NOT touch the production InfoGuard (port 8790), the real Caddy access log,
#     or the real logsentry.db. No requests are sent to the app, Caddy, or any outside host
#     (except the normal RDAP/email that InfoGuard already does). No login is attempted.
#   - Everything it creates (temp log, temp db, temp instance) is deleted at the end.
#
# Exit: 0 = instance ran and 3 incidents detected (emails sent) | 1 = aborted | 2 = unexpected
# ASCII only (Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI).

param(
    [string]$LogSentry = 'C:\logsentry\logsentry.py',
    [string]$Config    = 'C:\logsentry\logsentry.json',
    [int]   $Port      = 8795,
    [switch]$CheckBlocking    # also send ONE Next-Action request to localhost:3000 and expect 403
)
$ErrorActionPreference = 'Stop'

function Say([string]$m) { Write-Host ('{0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), $m) }

# Resolve python
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { Say 'python not found in PATH'; exit 1 }
$lsDir = Split-Path $LogSentry -Parent
foreach ($f in $LogSentry, $Config) { if (-not (Test-Path $f)) { Say "missing: $f"; exit 1 } }

# Port free?
try { $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port); $l.Start(); $l.Stop() }
catch { Say "port $Port is busy - pass -Port <other>"; exit 1 }

# Confirm the config has an email channel; read the mail-to AND the real login path from the config.
# (load_config() prints a line to stdout, so tag our line with IGPROBE and read only that one.)
$probeCode = "import sys; sys.path.insert(0, r'$lsDir'); import logsentry as L; L.load_config(r'$Config'); em=(L._NOTIFY or {}).get('email') or {}; to=em.get('to'); ap=(L._AUTH_PATHS or ['/api/auth/login'])[0]; print('IGPROBE|' + ('yes' if L.notify_channels() else 'no') + '|' + (', '.join(to) if isinstance(to,(list,tuple)) else str(to or '')) + '|' + ap)"
$probeLine = (& $py -c $probeCode | Where-Object { $_ -like 'IGPROBE|*' } | Select-Object -Last 1)
$parts = ($probeLine -split '\|')
if ($parts[1] -ne 'yes') { Say 'no notification channel in config (notify) - set it up first'; exit 1 }
$mailTo = $parts[2]; $authPath = $parts[3]
Say "email will be sent to: $mailTo"
Say "login path (from config auth_paths): $authPath"

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$work  = Join-Path $env:TEMP "infoguard-selftest-$stamp"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$log = Join-Path $work 'synthetic.log'
$db  = Join-Path $work 'selftest.db'
$pidProc = $null

try {
    # --- synthetic attack log (all from 27.100.38.10, the IP that really attacked us) ---
    # 3 incidents: (a) secret file 200  (b) Next-Action request 200  (c) 6x login fail then success.
    # Plus a couple of blocked 404 probes to show those do NOT raise incidents.
    # true unix seconds (PS 5.1 'Get-Date -UFormat %s' treats local time as UTC -> 9h off in the email)
    $now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $ip  = '27.100.38.10'
    function L([int]$ago, [string]$m, [string]$uri, [int]$st, [bool]$na=$false) {
        $h = @{ 'User-Agent' = @('InfoGuard-selftest/1.0') }
        if ($na) { $h['Next-Action'] = @('x') }
        (@{ ts = $now - $ago
            request = @{ client_ip = $ip; method = $m; uri = $uri; headers = $h }
            status = $st } | ConvertTo-Json -Compress -Depth 6)
    }
    $lines = @(
        (L 40 'GET'  '/wp-login.php' 404),
        (L 39 'GET'  '/.git/config'  404),
        (L 30 'GET'  '/.env'         200),          # (a) exposure
        (L 25 'POST' '/'             200 $true),    # (b) attack_ok (Next-Action)
        (L 20 'POST' $authPath 401),
        (L 19 'POST' $authPath 401),
        (L 18 'POST' $authPath 401),
        (L 17 'POST' $authPath 401),
        (L 16 'POST' $authPath 401),
        (L 15 'POST' $authPath 401),
        (L 13 'POST' $authPath 200)                 # (c) login success after fails (real login path)
    )
    [IO.File]::WriteAllText($log, ($lines -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))

    # Fresh temp DB, and mark today's daily summary as already sent so the test does NOT
    # also email a daily report (we only want the 3 incident emails).
    & $py -c "import sys,datetime; sys.path.insert(0, r'$lsDir'); import logsentry as L; c=L.open_db(r'$db'); L.set_meta(c,'last_daily',datetime.date.today().isoformat()); c.close()" | Out-Null

    Say "starting throwaway InfoGuard on port $Port (separate from production 8790)"
    $out = Join-Path $work 'instance.out.txt'
    $pidProc = Start-Process -FilePath $py -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError (Join-Path $work 'instance.err.txt') `
        -ArgumentList @($LogSentry, $log, '--format', 'json', '--dashboard', "$Port", '--host', '127.0.0.1',
                        '--scan-interval', '2', '--db', $db, '--config', $Config)

    # wait for it to answer
    $ok = $false
    for ($i = 0; $i -lt 40; $i++) {
        try { Invoke-WebRequest "http://127.0.0.1:$Port/" -UseBasicParsing -TimeoutSec 2 | Out-Null; $ok = $true; break }
        catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ok) { Say 'temp instance did not come up'; Get-Content $out, (Join-Path $work 'instance.err.txt') -ErrorAction SilentlyContinue | Select-Object -Last 15; exit 2 }

    Say 'waiting ~25s for detection + email send ...'
    Start-Sleep -Seconds 25

    $alerts = Invoke-RestMethod "http://127.0.0.1:$Port/api/alerts" -TimeoutSec 5
    $incs = @($alerts.incidents)
    Say ("incidents detected: {0}" -f $incs.Count)
    foreach ($x in $incs) { Say ("  - [{0}] {1} ({2} {3} -> {4})" -f $x.type, $x.title, $x.method, $x.path, $x.status) }

    if ($CheckBlocking) {
        Say 'blocking check (one request each):'
        $b1 = (& curl.exe -s -o NUL -w '%{http_code}' --max-time 5 -A 'InfoGuard-selftest/1.0' -X POST -H 'Next-Action: x' http://localhost:3000/)
        $b2 = (& curl.exe -s -o NUL -w '%{http_code}' --max-time 5 -A 'InfoGuard-selftest/1.0' http://localhost:3000/)
        Say ("  POST / with Next-Action -> {0} (expect 403)" -f $b1)
        Say ("  normal GET /            -> {0} (expect 200/307/308)" -f $b2)
    }

    if ($incs.Count -ge 3) {
        Say ("SELFTEST PASS - 3 incident emails were sent to {0}. Check that inbox (and phone)." -f $mailTo)
        $code = 0
    } else {
        Say 'SELFTEST INCOMPLETE - fewer than 3 incidents (see output above)'
        $code = 2
    }
}
catch {
    Say ("ERROR: {0}" -f $_.Exception.Message)
    $code = 2
}
finally {
    if ($pidProc) { try { Stop-Process -Id $pidProc.Id -Force -ErrorAction SilentlyContinue } catch {} }
    Start-Sleep -Milliseconds 500
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
    Say 'cleaned up temp instance / log / db (production untouched)'
}
exit $code
