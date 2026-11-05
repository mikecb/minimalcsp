param([string]$Out)
$counters = '\Processor(_Total)\% Processor Time', '\System\Processor Queue Length',
    '\Memory\Available MBytes', '\PhysicalDisk(*)\Avg. Disk sec/Transfer',
    '\PhysicalDisk(*)\Current Disk Queue Length', '\PhysicalDisk(*)\Disk Transfers/sec'
$previous = @{}
while ($true) {
    $line = (Get-Date).ToUniversalTime().ToString('HH:mm:ss.f')
    try {
        $samples = (Get-Counter -Counter $counters -ErrorAction SilentlyContinue).CounterSamples
        $line += ' ' + (($samples | ForEach-Object {
            ($_.Path -replace '^\\[^\]+\', '' -replace ' ', '_') + '=' + [math]::Round($_.CookedValue, 3)
        }) -join ' ')
    } catch { $line += " counter-error=$_" }
    $now = @{}
    Get-Process | ForEach-Object { $now[$_.Name] = [double]$now[$_.Name] + [double]$_.CPU }
    $deltas = $now.Keys | ForEach-Object {
        [pscustomobject]@{ Name = $_; D = $now[$_] - [double]$previous[$_] }
    } | Sort-Object D -Descending | Select-Object -First 6
    $line += ' top: ' + (($deltas | ForEach-Object { "$($_.Name)=$([math]::Round($_.D, 1))" }) -join ' ')
    $previous = $now
    Add-Content -Path $Out -Value $line
    Start-Sleep -Seconds 1
}
