# Removes what the Vigie installer added for this Windows user: its Python environment
# and the Desktop icon. The reports made in the app stay, unless the user deletes them.
# "Uninstall Vigie (Windows).bat" runs it with -ExecutionPolicy Bypass, for this run only.

$ErrorActionPreference = 'Continue'
$Data = if ($env:VIGIE_DATA_DIR) { $env:VIGIE_DATA_DIR } else { Join-Path $env:LOCALAPPDATA 'Vigie' }
$Venv = Join-Path $Data 'venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'

Write-Host 'Removing Vigie.'
$removed = $false
if (Test-Path $VenvPython) {
    & $VenvPython -m vigie shortcut --remove 2>$null | Out-Null
    $removed = ($LASTEXITCODE -eq 0)
}
if (-not $removed) {
    # Without a working environment, remove the icons Vigie makes, from the real Desktop
    # folder (it can be redirected to OneDrive).
    $desktop = [Environment]::GetFolderPath('Desktop')
    foreach ($name in @('Vigie.lnk', 'Vigie.cmd')) {
        $path = Join-Path $desktop $name
        if (Test-Path $path) { Remove-Item -Force $path; Write-Host "  Removed $path" }
    }
} else {
    Write-Host '  The Vigie icon is removed.'
}
if (Test-Path $Venv) {
    Remove-Item -Recurse -Force $Venv
    Write-Host "  Vigie's Python environment is removed."
} else {
    Write-Host "  Vigie's Python environment was not there."
}
Write-Host ''
Write-Host "  Done. Your reports are still in: $Data"
Write-Host '  Delete that folder too if you do not need them any more.'
if (-not $env:VIGIE_INSTALL_NO_PAUSE) {
    Write-Host ''
    Read-Host 'Press Enter to close this window' | Out-Null
}
