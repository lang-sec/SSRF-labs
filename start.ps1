$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSCommandPath
$runtime = Join-Path $root '.runtime'
$public = Join-Path $root 'public'
$pidFile = Join-Path $runtime 'pids.json'

if (-not (Test-Path -LiteralPath $runtime)) {
    New-Item -ItemType Directory -Path $runtime | Out-Null
}

$phpCommand = Get-Command php -ErrorAction SilentlyContinue
if ($null -eq $phpCommand) {
    throw 'PHP is not available in PATH. Install PHP 8.1+ and run this script again.'
}

function Test-LabPort {
    param([int]$Port)

    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) {
            $listener.Stop()
        }
    }
}

$servers = @(
    @{ Name = 'app'; Port = 8080; Router = 'router-app.php' },
    @{ Name = 'internal'; Port = 8081; Router = 'router-internal.php' },
    @{ Name = 'metadata'; Port = 8082; Router = 'router-metadata.php' },
    @{ Name = 'redirect'; Port = 8083; Router = 'router-redirect.php' },
    @{ Name = 'callback'; Port = 8084; Router = 'router-callback.php' }
)

foreach ($server in $servers) {
    if (-not (Test-LabPort -Port $server.Port)) {
        throw "Port $($server.Port) is already in use. Stop the conflicting process and retry."
    }
}

if (-not (Test-LabPort -Port 6380)) {
    throw 'Port 6380 is already in use. Stop the conflicting process and retry.'
}

if (Test-Path -LiteralPath $pidFile) {
    Remove-Item -LiteralPath $pidFile -Force
}

$started = @()
try {
    foreach ($server in $servers) {
        $router = Join-Path $root $server.Router
        $stdout = Join-Path $runtime "$($server.Name).out.log"
        $stderr = Join-Path $runtime "$($server.Name).err.log"
        $arguments = @(
            '-S',
            "127.0.0.1:$($server.Port)",
            '-t',
            $public,
            $router
        )

        $process = Start-Process `
            -FilePath $phpCommand.Source `
            -ArgumentList $arguments `
            -WorkingDirectory $root `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -PassThru

        $started += [pscustomobject]@{
            name = $server.Name
            port = $server.Port
            pid = $process.Id
            startedAt = $process.StartTime.ToString('o')
        }
    }

    $gopherScript = Join-Path $root 'bin\mock-tcp.php'
    $gopherProcess = Start-Process `
        -FilePath $phpCommand.Source `
        -ArgumentList @($gopherScript) `
        -WorkingDirectory $root `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $runtime 'gopher.out.log') `
        -RedirectStandardError (Join-Path $runtime 'gopher.err.log') `
        -PassThru

    $started += [pscustomobject]@{
        name = 'gopher'
        port = 6380
        pid = $gopherProcess.Id
        startedAt = $gopherProcess.StartTime.ToString('o')
    }

    $started | ConvertTo-Json | Set-Content -LiteralPath $pidFile -Encoding UTF8

    $ready = $false
    for ($attempt = 0; $attempt -lt 24; $attempt++) {
        Start-Sleep -Milliseconds 250
        try {
            $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/health' -TimeoutSec 1
            $internal = Invoke-RestMethod -Uri 'http://127.0.0.1:8081/api/health' -TimeoutSec 1
            $metadata = Invoke-RestMethod -Uri 'http://127.0.0.1:8082/api/health' -TimeoutSec 1
            $redirect = Invoke-RestMethod -Uri 'http://127.0.0.1:8083/api/health' -TimeoutSec 1
            $callback = Invoke-RestMethod -Uri 'http://127.0.0.1:8084/api/health' -TimeoutSec 1

            $tcpClient = [System.Net.Sockets.TcpClient]::new()
            try {
                $tcpClient.Connect('127.0.0.1', 6380)
                $gopherReady = $tcpClient.Connected
            } catch {
                $gopherReady = $false
            } finally {
                $tcpClient.Dispose()
            }

            if ($health.ok -and $internal.ok -and $metadata.ok -and $redirect.ok -and $callback.ok -and $gopherReady) {
                $ready = $true
                break
            }
        } catch {
            # PHP may still be starting.
        }
    }

    if (-not $ready) {
        throw 'The lab processes started, but health checks did not pass. Inspect .runtime/*.err.log.'
    }
} catch {
    foreach ($entry in $started) {
        $process = Get-Process -Id $entry.pid -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            Stop-Process -Id $entry.pid -Force
        }
    }
    throw
}

Write-Host ''
Write-Host 'SSRF Field Lab is running.' -ForegroundColor Green
Write-Host '  Main UI            http://127.0.0.1:8080'
Write-Host '  Internal service   http://127.0.0.1:8081'
Write-Host '  Mock metadata      http://127.0.0.1:8082'
Write-Host '  Public redirect    http://127.0.0.1:8083'
Write-Host '  Callback listener  http://127.0.0.1:8084'
Write-Host '  Mock TCP pivot     127.0.0.1:6380'
Write-Host ''
Write-Host 'Only loopback addresses and lab ports are reachable. Run .\stop.ps1 to stop all services.'

