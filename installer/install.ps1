# Installs Vigie for this Windows user, from the folder this script sits in:
# its own Python environment in %LOCALAPPDATA%\Vigie, a Vigie icon on the Desktop, then the app.
# Running it again upgrades Vigie in place. Everything it does is written to install.log.
# "Install Vigie (Windows).bat" runs it with -ExecutionPolicy Bypass, for this run only.

$ErrorActionPreference = 'Stop'
$Project = Split-Path -Parent $PSScriptRoot
$Data = if ($env:VIGIE_DATA_DIR) { $env:VIGIE_DATA_DIR } else { Join-Path $env:LOCALAPPDATA 'Vigie' }
$Venv = Join-Path $Data 'venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'
$VenvPythonw = Join-Path $Venv 'Scripts\pythonw.exe'
$Log = Join-Path $Data 'install.log'
$PythonPage = 'https://www.python.org/downloads/'

function Say([string]$Text) { Write-Host $Text }
function Step([string]$Text) { Write-Host ''; Write-Host "  $Text" -ForegroundColor Cyan }
function Write-Log([string]$Text) { Add-Content -Path $Log -Value $Text -Encoding UTF8 }

function Close-Window([int]$Code) {
    if (-not $env:VIGIE_INSTALL_NO_PAUSE) {
        Write-Host ''
        Read-Host 'Press Enter to close this window' | Out-Null
    }
    exit $Code
}

function Fail([string]$Text) {
    Say ''
    Say "  $Text"
    Say "  The details are in this file: $Log"
    Say '  If you ask for help, share that file.'
    Close-Window 1
}

# Run a program with its output in the log only; return its exit code.
function Invoke-Logged([string]$Program, [string[]]$Arguments) {
    Write-Log ('$ ' + $Program + ' ' + ($Arguments -join ' '))
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Program @Arguments 2>&1 | ForEach-Object { "$_" } | Add-Content -Path $Log -Encoding UTF8
        return $LASTEXITCODE
    } catch {
        Write-Log "$_"
        return 1
    } finally {
        $ErrorActionPreference = $previous
    }
}

# The first Python 3.10 or later found: the py launcher, then python, then python3.
# The Microsoft Store placeholder for python.exe fails the check and is skipped.
# The system Python always runs with -I (isolated): a broken package in the user's
# site-packages or a PYTHON* variable cannot get in the way of the install.
function Find-Python {
    $candidates = @(
        @{ Program = 'py'; Extra = @('-3') },
        @{ Program = 'python'; Extra = @() },
        @{ Program = 'python3'; Extra = @() }
    )
    # No double quotes in arguments: Windows PowerShell 5.1 drops them on the way to python.
    $check = 'import sys, venv; assert sys.version_info >= (3, 10); print(sys.executable)'
    foreach ($candidate in $candidates) {
        if (-not (Get-Command $candidate.Program -ErrorAction SilentlyContinue)) { continue }
        $extra = @($candidate.Extra)
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $found = & $candidate.Program @extra -I -c $check 2>$null
            if ($LASTEXITCODE -eq 0 -and $found) {
                $path = ("$found" -split "`n")[-1].Trim()
                if ($path -and (Test-Path $path)) { return $path }
            }
        } catch {
        } finally {
            $ErrorActionPreference = $previous
        }
    }
    return $null
}

function Main {
    New-Item -ItemType Directory -Force -Path $Data | Out-Null
    Write-Log ''
    Write-Log ("=== " + (Get-Date -Format 's') + " install from $Project")

    Say 'Installing Vigie, the log analyzer.'
    Step '1/4  Looking for Python 3.10 or later...'
    $python = Find-Python
    if (-not $python) {
        Write-Log 'no suitable Python found'
        Say ''
        Say '  Vigie needs Python 3.10 or later, and this computer does not have it yet.'
        Say '  1. The Python download page opens in your browser: download Python and run its installer.'
        Say '  2. On the first screen of that installer, tick "Add python.exe to PATH".'
        Say '  3. Then double-click "Install Vigie (Windows)" again.'
        Start-Process $PythonPage
        Close-Window 1
    }
    $version = & $python -I -c 'import platform; print(platform.python_version())'
    Say "  Found Python ${version}: $python"
    Write-Log "python: $python"

    Step "2/4  Preparing Vigie's own Python environment..."
    if ((Test-Path $VenvPython) -and ((Invoke-Logged $VenvPython @('-c', 'import sys')) -eq 0)) {
        Say "  Updating the one already in $Venv"
    } else {
        if (Test-Path $Venv) { Remove-Item -Recurse -Force $Venv }
        if ((Invoke-Logged $python @('-I', '-m', 'venv', $Venv)) -ne 0) {
            Fail 'Vigie could not create its Python environment.'
        }
        Say "  Created in $Venv"
    }

    Step '3/4  Installing Vigie (this can take a minute)...'
    $pip = @('-m', 'pip', 'install', '--disable-pip-version-check')
    if ((Invoke-Logged $VenvPython ($pip + @('--upgrade', $Project))) -ne 0) {
        Fail 'Vigie could not be installed. Check the internet connection, then try again.'
    }
    # The same version number from a newer download: install its files anyway.
    if ((Invoke-Logged $VenvPython ($pip + @('--force-reinstall', '--no-deps', $Project))) -ne 0) {
        Fail 'Vigie could not be installed.'
    }
    $installed = & $VenvPython -c 'import vigie; print(vigie.__version__)'
    Say "  Vigie $installed is installed."

    Step '4/4  Adding the Vigie icon to the Desktop...'
    if ((Invoke-Logged $VenvPython @('-m', 'vigie', 'shortcut')) -eq 0) {
        Say '  The Vigie icon is on your Desktop.'
    } else {
        Say "  The icon could not be added (see $Log); Vigie still works."
    }

    if (-not $env:VIGIE_INSTALL_NO_LAUNCH) {
        Say ''
        Say '  Opening Vigie in your browser...'
        $program = if (Test-Path $VenvPythonw) { $VenvPythonw } else { $VenvPython }
        Start-Process -FilePath $program -ArgumentList @('-m', 'vigie', 'ui') -WindowStyle Hidden
    }
    Say ''
    Say '  Done. Next time, double-click the Vigie icon on your Desktop.'
    Say '  To remove Vigie, double-click "Uninstall Vigie (Windows)" next to the installer.'
    Close-Window 0
}

try {
    Main
} catch {
    Write-Log ($_ | Out-String)
    Fail ('Something went wrong: ' + $_.Exception.Message)
}
