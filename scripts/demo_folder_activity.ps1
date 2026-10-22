[CmdletBinding()]
param(
    [string]$TargetPath,
    [ValidateSet('random', 'create-modify', 'delete-burst', 'mixed-burst')]
    [string]$Scenario = 'random',
    [switch]$NoPrompts
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

function Read-Setting([string]$Name, [string]$Fallback) {
    $envFile = Join-Path $projectRoot '.env'
    if (Test-Path -LiteralPath $envFile) {
        $match = Select-String -LiteralPath $envFile -Pattern "^\s*$Name\s*=\s*(.*?)\s*$" | Select-Object -First 1
        if ($match) {
            $value = $match.Matches[0].Groups[1].Value.Trim().Trim('"').Trim("'")
            if ($value) { return $value }
        }
    }
    return $Fallback
}

$defaultTarget = Read-Setting 'MONITOR_TARGET_PATH' 'instance/monitor_target'
if (-not [IO.Path]::IsPathRooted($defaultTarget)) {
    $defaultTarget = Join-Path $projectRoot $defaultTarget
}
if (-not $TargetPath -and -not $NoPrompts) {
    $enteredPath = Read-Host "Enter the server folder watched by RansomShield, or press ENTER for $defaultTarget"
    if ($enteredPath) { $TargetPath = $enteredPath }
}
if (-not $TargetPath) { $TargetPath = $defaultTarget }
$TargetPath = [IO.Path]::GetFullPath($TargetPath)

$policy = @{
    window_seconds = 30
    delete_threshold = 10
    modify_threshold = 20
    mixed_threshold = 30
    mixed_destructive_minimum = 10
    auto_quarantine = ((Read-Setting 'AUTO_QUARANTINE' 'false') -eq 'true')
}
$policyFile = Join-Path $projectRoot 'instance/monitor_policy.json'
if (Test-Path -LiteralPath $policyFile) {
    try {
        $saved = Get-Content -LiteralPath $policyFile -Raw | ConvertFrom-Json
        foreach ($key in $policy.Keys) {
            if ($null -ne $saved.$key) {
                if ($key -eq 'auto_quarantine') { $policy[$key] = [bool]$saved.$key }
                else { $policy[$key] = [int]$saved.$key }
            }
        }
    } catch {
        Write-Warning "Could not read saved monitor settings. Using the default limits for this demo."
    }
}

if (-not (Test-Path -LiteralPath $TargetPath -PathType Container)) {
    throw "The watched server folder does not exist: $TargetPath"
}

$availableScenarios = @('create-modify', 'delete-burst', 'mixed-burst')
if ($Scenario -eq 'random') { $Scenario = Get-Random -InputObject $availableScenarios }
switch ($Scenario) {
    'create-modify' {
        $operationCount = [Math]::Min(5000, $policy.modify_threshold + (Get-Random -Minimum 1 -Maximum 4))
        $destructiveCount = $operationCount
    }
    'delete-burst' {
        $operationCount = [Math]::Min(5000, $policy.delete_threshold + (Get-Random -Minimum 1 -Maximum 4))
        $destructiveCount = $operationCount
    }
    'mixed-burst' {
        $operationCount = [Math]::Min(5000, [Math]::Max($policy.mixed_threshold, $policy.mixed_destructive_minimum) + (Get-Random -Minimum 1 -Maximum 4))
        $destructiveCount = [Math]::Min($operationCount, [Math]::Max($policy.mixed_destructive_minimum, 1))
    }
}

$demoFolderName = 'RansomShield-Random-Demo-' + [guid]::NewGuid().ToString('N')
$demoFolder = Join-Path $TargetPath $demoFolderName
New-Item -ItemType Directory -Path $demoFolder | Out-Null
$files = for ($i = 1; $i -le $operationCount; $i++) {
    Join-Path $demoFolder ("sample-{0:D5}.txt" -f $i)
}

Write-Host ''
Write-Host 'Random activity test is ready.' -ForegroundColor Cyan
Write-Host "Watched folder: $TargetPath"
Write-Host "Safe test folder: $demoFolder"
Write-Host "Random case: $Scenario"
Write-Host "Files/operations: $operationCount"
Write-Host "Alert window: $($policy.window_seconds) seconds"
Write-Host "Current limits: delete $($policy.delete_threshold), modify $($policy.modify_threshold), mixed $($policy.mixed_threshold) with $($policy.mixed_destructive_minimum) edits/deletions"
if (-not $NoPrompts) {
    Read-Host 'Start the server-folder monitor in the app, then press ENTER here to run the random changes' | Out-Null
}

$order = $files | Sort-Object { Get-Random }
foreach ($file in $order) {
    $randomContent = 'RansomShield safe test content ' + [guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($file, $randomContent)
    if ($operationCount -le 100) { Start-Sleep -Milliseconds (Get-Random -Minimum 5 -Maximum 60) }
}

if ($Scenario -eq 'delete-burst') {
    Start-Sleep -Milliseconds 2200
    $order = $files | Sort-Object { Get-Random }
    foreach ($file in $order) {
        Remove-Item -LiteralPath $file -Force
        if ($operationCount -le 100) { Start-Sleep -Milliseconds (Get-Random -Minimum 5 -Maximum 60) }
    }
} else {
    # Let the monitor record the initial files before the randomized edits.
    Start-Sleep -Milliseconds 2200
    $editOrder = $files | Sort-Object { Get-Random } | Select-Object -First $destructiveCount
    foreach ($file in $editOrder) {
        $randomContent = "`r`nRandom edit: $([guid]::NewGuid().ToString('N'))"
        [IO.File]::AppendAllText($file, $randomContent)
        if ($operationCount -le 100) { Start-Sleep -Milliseconds (Get-Random -Minimum 5 -Maximum 60) }
    }
}

Write-Host ''
Write-Host 'Random activity is complete.' -ForegroundColor Green
Write-Host 'Review the alert and file paths in the app.'
if ($policy.auto_quarantine -and $Scenario -ne 'delete-burst') {
    Write-Host 'Automatic quarantine is enabled: changed files may have moved to quarantine. Restore them from Email & history if needed.' -ForegroundColor Yellow
} elseif ($Scenario -eq 'delete-burst') {
    Write-Host 'This case deletes its own test files; deleted files no longer exist to be quarantined.' -ForegroundColor Yellow
} else {
    Write-Host 'Automatic quarantine is off. You can manually quarantine a listed file from the alert.'
}
Write-Host "The unique test folder is left at: $demoFolder"
Write-Host 'Remove that folder yourself after reviewing the results.'
