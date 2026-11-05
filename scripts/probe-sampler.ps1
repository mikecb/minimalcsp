param([string]$Out)
$counters = '\Processor(_Total)\% Processor Time', '\System\Processor Queue Length',
    '\Memory\Available MBytes', '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer',
    '\PhysicalDisk(_Total)\Current Disk Queue Length', '\PhysicalDisk(_Total)\Disk Bytes/sec'
$previous = @{}
$services = @{}
$tick = 0
while ($true) {
    if ($tick % 30 -eq 0) {
        $services = @{}
        Get-CimInstance Win32_Service -Filter "State='Running'" | ForEach-Object {
            $services[[int]$_.ProcessId] = [string]$services[[int]$_.ProcessId] + $_.Name + ','
        }
    }
    $tick++
    $line = (Get-Date).ToUniversalTime().ToString('HH:mm:ss.f')
    try {
        $samples = (Get-Counter -Counter $counters -ErrorAction SilentlyContinue).CounterSamples
        $line += ' ' + (($samples | ForEach-Object {
            (($_.Path.Split([char]92))[-1] -replace ' ', '_') + '=' + [math]::Round($_.CookedValue, 3)
        }) -join ' ')
    } catch { $line += ' counter-error' }
    $now = @{}
    $chromes = 0
    Get-Process | ForEach-Object {
        if ($_.Name -eq 'chrome') { $chromes++ }
        $key = $_.Name
        if ($key -eq 'svchost') { $key = 'svchost:' + [string]$services[[int]$_.Id] }
        $now[$key] = [double]$now[$key] + [double]$_.CPU
    }
    $deltas = $now.Keys | ForEach-Object {
        [pscustomobject]@{ Name = $_; D = $now[$_] - [double]$previous[$_] }
    } | Sort-Object D -Descending | Select-Object -First 6
    $line += " chromes=$chromes top: " + (($deltas | ForEach-Object { "$($_.Name)=$([math]::Round($_.D, 1))" }) -join ' ')
    $previous = $now
    Add-Content -Path $Out -Value $line
    Start-Sleep -Seconds 1
}
