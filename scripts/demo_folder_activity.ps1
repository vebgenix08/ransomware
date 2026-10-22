[CmdletBinding()]
param(
    [string]$TargetPath,
    [ValidateSet('guided', 'random', 'create-modify', 'delete-burst', 'mixed-burst')]
    [string]$Scenario = 'guided',
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

if ($Scenario -eq 'guided') {
    $maximumDemoFiles = 5000
    $demoFolderName = 'RansomShield-Guided-Demo-' + [guid]::NewGuid().ToString('N')
    $demoFolder = Join-Path $TargetPath $demoFolderName
    New-Item -ItemType Directory -Path $demoFolder | Out-Null

    $initialCount = [Math]::Min($maximumDemoFiles, [Math]::Max(5, $policy.modify_threshold))
    $createAgainCount = [Math]::Min($maximumDemoFiles, [Math]::Max(5, $policy.delete_threshold))
    $mixedCount = [Math]::Min($maximumDemoFiles, [Math]::Max(2, [Math]::Max($policy.mixed_threshold, $policy.mixed_destructive_minimum)))
    $mixedDestructiveCount = [Math]::Min($mixedCount, [Math]::Max(2, $policy.mixed_destructive_minimum))
    $fewModifyCount = [Math]::Min($initialCount, [Math]::Max(1, [Math]::Min(3, $policy.modify_threshold - 1)))
    $moreModifyCount = [Math]::Min($initialCount, $policy.modify_threshold)
    $deleteCount = [Math]::Min($createAgainCount, $policy.delete_threshold)

    function Get-RandomSubset($Items, [int]$Count) {
        return @($Items | Sort-Object { Get-Random } | Select-Object -First $Count)
    }

    function New-DemoFiles([string]$Prefix, [int]$Count) {
        $created = @()
        for ($index = 1; $index -le $Count; $index++) {
            $file = Join-Path $demoFolder ("{0}-{1:D5}.txt" -f $Prefix, $index)
            [IO.File]::WriteAllText($file, "RansomShield safe demo content $([guid]::NewGuid())")
            $created += $file
        }
        return $created
    }

    function Invoke-GuidedStage([int]$Number, [string]$Title, [scriptblock]$Action) {
        Write-Host "`nSTEP $Number/6: $Title" -ForegroundColor Cyan
        & $Action
        if (-not $NoPrompts -and $Number -lt 6) {
            Start-Sleep -Seconds 2
            Read-Host 'Review Recent activity in the app, then press ENTER to continue' | Out-Null
            $cooldown = [Math]::Max(1, $policy.window_seconds + 1)
            Write-Host "Waiting $cooldown seconds so the next step starts outside the current alert window..."
            Start-Sleep -Seconds $cooldown
        }
    }

    Write-Host ''
    Write-Host 'RansomShield six-step activity walkthrough' -ForegroundColor Cyan
    Write-Host "Watched folder: $TargetPath"
    Write-Host "Safe demo folder: $demoFolder"
    Write-Host "Alert window: $($policy.window_seconds) seconds"
    Write-Host "Limits: delete $($policy.delete_threshold), modify $($policy.modify_threshold), mixed $($policy.mixed_threshold), minimum modified/deleted $($policy.mixed_destructive_minimum)"
    Write-Host 'All changes stay inside the new demo folder. Automatic quarantine may move changed demo files.'
    Write-Host 'Create-only and below-limit stages still appear in Recent activity but may not create alerts. Threshold stages should alert if monitoring is active and the alert cooldown has expired.'
    Write-Host "Planned steps: create $initialCount; modify $fewModifyCount; modify $moreModifyCount; create $createAgainCount; delete $deleteCount; mixed $mixedCount."
    if (-not $NoPrompts) {
        Read-Host 'Start the server-folder monitor in the app, then press ENTER to begin' | Out-Null
    }

    $initialFiles = @()
    Invoke-GuidedStage 1 "Create only ($initialCount files)" {
        $script:initialFiles = @(New-DemoFiles 'initial' $initialCount)
    }
    Invoke-GuidedStage 2 "Modify a few ($fewModifyCount files)" {
        foreach ($file in (Get-RandomSubset $initialFiles $fewModifyCount)) {
            [IO.File]::AppendAllText($file, "`r`nSmall edit $([guid]::NewGuid())")
        }
    }
    Invoke-GuidedStage 3 "Modify more ($moreModifyCount files)" {
        foreach ($file in (Get-RandomSubset $initialFiles $moreModifyCount)) {
            [IO.File]::AppendAllText($file, "`r`nLarger edit $([guid]::NewGuid())")
        }
    }
    $secondFiles = @()
    Invoke-GuidedStage 4 "Create again ($createAgainCount new files)" {
        $script:secondFiles = @(New-DemoFiles 'created-again' $createAgainCount)
    }
    Invoke-GuidedStage 5 "Delete some ($deleteCount files)" {
        foreach ($file in (Get-RandomSubset $secondFiles $deleteCount)) {
            Remove-Item -LiteralPath $file -Force
        }
    }
    Invoke-GuidedStage 6 "Mix create, modify, and delete ($mixedCount paths)" {
        $mixedFiles = @(New-DemoFiles 'mixed' $mixedCount)
        if (-not $NoPrompts) { Start-Sleep -Seconds 2 }
        $changedFiles = Get-RandomSubset $mixedFiles $mixedDestructiveCount
        $modifyMixedCount = [Math]::Ceiling($changedFiles.Count / 2)
        $deleteMixedCount = $changedFiles.Count - $modifyMixedCount
        foreach ($file in (Get-RandomSubset $changedFiles $modifyMixedCount)) {
            [IO.File]::AppendAllText($file, "`r`nMixed edit $([guid]::NewGuid())")
        }
        $remainingMixedFiles = @($changedFiles | Where-Object { Test-Path -LiteralPath $_ })
        foreach ($file in (Get-RandomSubset -Items $remainingMixedFiles -Count $deleteMixedCount)) {
            Remove-Item -LiteralPath $file -Force
        }
        if (-not $NoPrompts) { Start-Sleep -Seconds 2 }
    }

    Write-Host ''
    Write-Host 'Six-step walkthrough complete. Review the activity log and alerts in the app.' -ForegroundColor Green
    if ($policy.auto_quarantine) {
        Write-Host 'Automatic quarantine is enabled. Changed files may have moved to quarantine; restore demo files from Email & history if needed.' -ForegroundColor Yellow
    } else {
        Write-Host 'Automatic quarantine is off. You can manually quarantine an existing demo file from an alert.'
    }
    Write-Host "The demo folder is left at: $demoFolder"
    Write-Host 'Delete that demo folder yourself after reviewing. Do not delete or restore files from any other folder.'
    return
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
