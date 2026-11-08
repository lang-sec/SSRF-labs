$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSCommandPath
$pidFile = Join-Path (Join-Path $root '.runtime') 'pids.json'

if (-not (Test-Path -LiteralPath $pidFile)) {
    Write-Host 'No lab PID file was found. Nothing to stop.'
    exit 0
}

$entries = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
foreach ($entry in @($entries)) {
    $processId = [int] $entry.pid
    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue

    if ($null -eq $processInfo) {
        continue
    }

    $commandLine = [string] $processInfo.CommandLine
    if ($commandLine -notlike "*$root*" -or ($commandLine -notlike '*router-*.php*' -and $commandLine -notlike '*mock-tcp.php*')) {
        Write-Warning "Skipped PID $processId because its command line does not belong to this lab."
        continue
    }

    Stop-Process -Id $processId -Force
    Write-Host "Stopped $($entry.name) on port $($entry.port)."
}

Remove-Item -LiteralPath $pidFile -Force
Write-Host 'SSRF Field Lab stopped.'

