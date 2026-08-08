param(
    [string]$Target = "C:\shared\target",
    [string]$OutFile = "C:\shared\result.json",
    [int]$Seconds = 75
)

$ErrorActionPreference = "SilentlyContinue"
$result = [ordered]@{
    started = (Get-Date).ToString("s")
    target = $Target
    launched = $false
    pool_hits = @()
    external_connections = @()
    child_processes = @()
    max_cpu_seconds = 0
    notes = @()
}

function Get-Conns {
    Get-NetTCPConnection | Where-Object {
        $_.State -in @('Established', 'SynSent') -and
        $_.RemoteAddress -notin @('127.0.0.1', '::1', '0.0.0.0', '::') -and
        $_.RemoteAddress -notlike '169.254.*'
    } | Select-Object RemoteAddress, RemotePort, OwningProcess
}

$exe = $null
if (Test-Path $Target -PathType Container) {
    $exe = Get-ChildItem $Target -Recurse -Filter *.exe |
        Where-Object { $_.Name -notmatch 'unins|crashhandler|vc_redist|dxsetup|setup' } |
        Sort-Object Length -Descending | Select-Object -First 1 -ExpandProperty FullName
} elseif ($Target -match '\.exe$') {
    $exe = $Target
}

if (-not $exe) {
    $result.notes += "No game executable found to launch."
    $result | ConvertTo-Json -Depth 5 | Out-File $OutFile -Encoding utf8
    return
}

$base = @(Get-Conns | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)/$($_.OwningProcess)" })
$poolPorts = @(3333, 3334, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444, 45560, 45700, 3032, 5730)

$p = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) `
    -ArgumentList '-screen-fullscreen', '0', '-screen-width', '800', '-screen-height', '600' -PassThru
$result.launched = $true
$gamePid = $p.Id

$deadline = (Get-Date).AddSeconds($Seconds)
$ext = @{}; $tree = @{}; $maxcpu = 0
while ((Get-Date) -lt $deadline -and -not $p.HasExited) {
    $all = Get-CimInstance Win32_Process
    $rel = @($gamePid) + ($all | Where-Object { $_.ParentProcessId -eq $gamePid }).ProcessId
    foreach ($c in ($all | Where-Object { $_.ParentProcessId -eq $gamePid })) {
        $tree["$($c.ProcessId)"] = "$($c.Name)"
    }
    foreach ($c in (Get-Conns)) {
        $k = "$($c.RemoteAddress):$($c.RemotePort)/$($c.OwningProcess)"
        if ($k -notin $base) {
            $isRel = [int]$c.OwningProcess -in $rel
            $ext[$k] = @{ addr = $c.RemoteAddress; port = $c.RemotePort; game = $isRel }
            if ([int]$c.RemotePort -in $poolPorts -and $isRel) { $result.pool_hits += $k }
        }
    }
    foreach ($rp in $rel) {
        $pr = Get-Process -Id $rp -ErrorAction SilentlyContinue
        if ($pr -and $pr.CPU -gt $maxcpu) { $maxcpu = [math]::Round($pr.CPU, 1) }
    }
    Start-Sleep -Seconds 3
}

$all = Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $gamePid }
foreach ($c in $all) { Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue }
Stop-Process -Id $gamePid -Force -ErrorAction SilentlyContinue

$result.external_connections = @($ext.Values)
$result.child_processes = @($tree.Values)
$result.max_cpu_seconds = $maxcpu
$result.finished = (Get-Date).ToString("s")
$result | ConvertTo-Json -Depth 5 | Out-File $OutFile -Encoding utf8
