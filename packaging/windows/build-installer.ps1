[CmdletBinding()]
param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$BuildRoot = Join-Path $RepositoryRoot "build\windows"
$AssetDirectory = Join-Path $BuildRoot "assets"
$InstallerDirectory = Join-Path $BuildRoot "installer"

function Invoke-CodeSigning {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    if ([string]::IsNullOrWhiteSpace($env:WINDOWS_SIGNING_CERTIFICATE)) {
        return
    }
    $SignTool = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue
    if (-not $SignTool) {
        $WindowsKits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
        $SignTool = Get-ChildItem -Path "$WindowsKits\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $SignTool) {
        throw "signtool.exe was not found, but WINDOWS_SIGNING_CERTIFICATE is configured."
    }

    $SigningArguments = @(
        "sign", "/fd", "SHA256", "/td", "SHA256",
        "/tr", "http://timestamp.digicert.com",
        "/f", $env:WINDOWS_SIGNING_CERTIFICATE
    )
    if (-not [string]::IsNullOrWhiteSpace($env:WINDOWS_SIGNING_PASSWORD)) {
        $SigningArguments += @("/p", $env:WINDOWS_SIGNING_PASSWORD)
    }
    $SigningArguments += $FilePath
    & $SignTool @SigningArguments
    if ($LASTEXITCODE -ne 0) { throw "Code signing failed for $FilePath." }
}

Push-Location $RepositoryRoot
try {
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $Version = (& python -c "import wifi_agent; print(wifi_agent.APP_VERSION)").Trim()
    }

    if (Test-Path $BuildRoot) {
        Remove-Item -Recurse -Force $BuildRoot
    }
    New-Item -ItemType Directory -Force -Path $AssetDirectory, $InstallerDirectory | Out-Null

    & python "packaging\generate_assets.py" --version $Version --output-dir $AssetDirectory
    if ($LASTEXITCODE -ne 0) { throw "Could not generate installer assets." }

    $PyInstallerArguments = @(
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onedir",
        "--name", "WiFiAgent",
        "--icon", (Join-Path $AssetDirectory "wifi-agent.ico"),
        "--version-file", (Join-Path $AssetDirectory "windows-version-info.txt"),
        "--paths", $AssetDirectory,
        "--collect-submodules", "keyring.backends",
        "--hidden-import", "pystray._win32",
        "--distpath", (Join-Path $BuildRoot "dist"),
        "--workpath", (Join-Path $BuildRoot "work"),
        "--specpath", (Join-Path $BuildRoot "spec"),
        "wifi_agent.py"
    )
    & python -m PyInstaller @PyInstallerArguments
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
    $ApplicationExecutable = Join-Path $BuildRoot "dist\WiFiAgent\WiFiAgent.exe"
    # A windowed executable returns to PowerShell immediately unless waited for.
    $SelfTestResult = Join-Path $BuildRoot "self-test.txt"
    $SelfTest = Start-Process -FilePath $ApplicationExecutable -ArgumentList @("self-test", "--result-file", "`"$SelfTestResult`"") -Wait -PassThru
    if ($SelfTest.ExitCode -ne 0 -or -not (Test-Path $SelfTestResult) -or (Get-Content $SelfTestResult -TotalCount 1) -ne "ok") {
        if (Test-Path $SelfTestResult) { Get-Content $SelfTestResult | Write-Host }
        throw "The packaged Windows application failed its startup self-test."
    }
    Invoke-CodeSigning $ApplicationExecutable

    $CompilerCandidates = @(
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 7\ISCC.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }
    $Compiler = $CompilerCandidates | Select-Object -First 1
    if (-not $Compiler) {
        throw "Inno Setup 6 or 7 was not found. Install it and rerun this script."
    }

    & $Compiler "/DAppVersion=$Version" "/DBuildRoot=$BuildRoot" "/DOutputDir=$InstallerDirectory" "packaging\windows\WiFiAgent.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }
    $Installers = @(Get-ChildItem -Path $InstallerDirectory -Filter "*.exe")
    if ($Installers.Count -ne 1) { throw "Expected exactly one Windows installer, found $($Installers.Count)." }
    Invoke-CodeSigning $Installers[0].FullName

    Write-Host "Windows installer created in $InstallerDirectory"
}
finally {
    Pop-Location
}
