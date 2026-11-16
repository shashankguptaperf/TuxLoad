<#
.SYNOPSIS
    Read-only TuxLoad discovery for a Windows application machine or Windows Tuxedo host.

.DESCRIPTION
    Collects the facts needed before building a 64-bit Tuxedo recorder and replay engine:
      1. Operating system and Tuxedo version
      2. Workstation vs native client, and application language
      3. Buffer types, conversations, and transactions
      4. Whether 64-bit client libraries and field tables are present

    The script does not change the machine, does not log on to Tuxedo, and does not
    initialize git. It may open a short TCP connection to a Workstation listener
    address found in the application startup configuration, to see if that port accepts
    a connection.

.PARAMETER AppPath
    Full path to the application executable, or to the folder that contains it.

.PARAMETER TuxDir
    Full path to a Tuxedo installation (the folder that contains bin). Use this when
    TUXDIR is not set in the environment.

.PARAMETER StartupScript
    Path to the .bat or .cmd that starts the application and sets TUXDIR, WSNADDR,
    and the field-table variables. The script also scans .bat and .cmd files next
    to the application.

.PARAMETER SearchRoot
    Extra folder to search for a Tuxedo installation.

.PARAMETER OutDir
    Folder where tuxload-discovery.txt and tuxload-discovery.json are written.
    Defaults to .\tuxload-discovery-output in the current directory.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\discovery\Discover-Tuxedo.ps1 -AppPath "D:\Apps\Billing\billing.exe"

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\discovery\Discover-Tuxedo.ps1 -AppPath "D:\Apps\Billing" -StartupScript "D:\Apps\Billing\start-billing.cmd" -TuxDir "D:\oracle\tuxedo12.2.2.0.0"
#>
[CmdletBinding()]
param(
    [string]$AppPath,
    [string]$TuxDir,
    [string]$StartupScript,
    [string]$SearchRoot,
    [string]$OutDir,
    [switch]$SelfTest,
    [switch]$NoMachineScan,
    [switch]$SkipNetwork
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$ScriptVersion = '0.1.0'
$InterestingEnvNames = @(
    'TUXDIR', 'WSNADDR', 'TUXCONFIG', 'TOBJADDR',
    'FLDTBLDIR', 'FLDTBLDIR32', 'FIELDTBLS', 'FIELDTBLS32',
    'VIEWDIR', 'VIEWDIR32', 'VIEWFILES', 'VIEWFILES32',
    'CLASSPATH'
)
$BinaryTokens = @(
    'libwsc.dll', 'libtux.dll', 'libfml32.dll', 'libfml.dll', 'libengine.dll',
    'libbuft.dll', 'wtuxws32.dll', 'libtxml.dll', 'joltwsc.dll', 'jolt.dll',
    'tpcall', 'tpacall', 'tpgetrply', 'tpconnect', 'tpsend', 'tprecv',
    'tpbegin', 'tpcommit', 'tpabort', 'tpenqueue', 'tpdequeue', 'tpinit',
    'Fadd32', 'Fget32', 'Fchg32', 'Finit32', 'FML32', 'VIEW32', 'CARRAY',
    'WSNADDR', 'TUXCONFIG', 'TOBJADDR'
)
$SecretNamePattern = '(?i)PASS|SECRET|PWD|CREDENTIAL|APP_PW|TOKEN'

function Write-ProgressLine {
    param([string]$Message)
    Write-Host $Message
}

function Resolve-FullPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        if (Test-Path -LiteralPath $Path) {
            return (Resolve-Path -LiteralPath $Path).Path
        }
    } catch {
        return $null
    }
    return $null
}

function Get-PeInfo {
    param([Parameter(Mandatory = $true)][string]$Path)
    $result = New-Object psobject -Property @{
        Path         = $Path
        Machine      = $null
        IsPe         = $false
        IsDotNet     = $false
        Prefer32Bit  = $false
        AnyCpu       = $false
        Error        = $null
    }
    $fs = $null
    $br = $null
    try {
        $fs = New-Object System.IO.FileStream(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)
        $br = New-Object System.IO.BinaryReader($fs)
        if ($fs.Length -lt 0x40) {
            $result.Error = 'file is too small to be a PE'
            return $result
        }
        $mz = $br.ReadUInt16()
        if ($mz -ne 0x5A4D) {
            $result.Error = 'not an MZ executable'
            return $result
        }
        $fs.Position = 0x3C
        $peOffset = $br.ReadInt32()
        if ($peOffset -le 0 -or ($peOffset + 26) -ge $fs.Length) {
            $result.Error = 'PE header offset is invalid'
            return $result
        }
        $fs.Position = $peOffset
        $sig = $br.ReadUInt32()
        if ($sig -ne 0x00004550) {
            $result.Error = 'PE signature is missing'
            return $result
        }
        $machine = $br.ReadUInt16()
        $sectionCount = $br.ReadUInt16()
        $null = $br.ReadUInt32()
        $null = $br.ReadUInt32()
        $null = $br.ReadUInt32()
        $sizeOpt = $br.ReadUInt16()
        $null = $br.ReadUInt16()
        $result.IsPe = $true
        switch ($machine) {
            0x14C { $result.Machine = 'x86' }
            0x8664 { $result.Machine = 'x64' }
            0xAA64 { $result.Machine = 'ARM64' }
            default { $result.Machine = ('0x{0:X}' -f $machine) }
        }
        if ($sizeOpt -lt 96) { return $result }
        $optStart = $fs.Position
        $magic = $br.ReadUInt16()
        $numDir = 0
        $dataDir = 0
        if ($magic -eq 0x10B -and $sizeOpt -ge 96) {
            $fs.Position = $optStart + 92
            $numDir = $br.ReadInt32()
            $dataDir = $optStart + 96
        } elseif ($magic -eq 0x20B -and $sizeOpt -ge 112) {
            $fs.Position = $optStart + 108
            $numDir = $br.ReadInt32()
            $dataDir = $optStart + 112
        } else {
            return $result
        }
        if ($numDir -le 14) { return $result }
        $fs.Position = $dataDir + (14 * 8)
        if ($fs.Position + 8 -gt $fs.Length) { return $result }
        $comRva = $br.ReadUInt32()
        $comSize = $br.ReadUInt32()
        if ($comRva -eq 0 -or $comSize -eq 0) { return $result }
        $result.IsDotNet = $true
        $sectionTable = $optStart + $sizeOpt
        $fileOff = -1
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $entry = $sectionTable + ($i * 40)
            if ($entry + 24 -gt $fs.Length) { break }
            $fs.Position = $entry + 8
            $virtualSize = $br.ReadUInt32()
            $va = $br.ReadUInt32()
            $rawSize = $br.ReadUInt32()
            $rawPtr = $br.ReadUInt32()
            $span = $virtualSize
            if ($rawSize -gt $span) { $span = $rawSize }
            if ($span -eq 0) { continue }
            $end = [uint64]$va + [uint64]$span
            if ([uint64]$comRva -ge [uint64]$va -and [uint64]$comRva -lt $end) {
                $fileOff = [int]($rawPtr + ($comRva - $va))
                break
            }
        }
        if ($fileOff -ge 0 -and ($fileOff + 20) -lt $fs.Length) {
            $fs.Position = $fileOff + 16
            $flags = $br.ReadUInt32()
            if (($flags -band 2) -ne 0) { $result.Prefer32Bit = $true }
            if ($result.Machine -eq 'x86' -and -not $result.Prefer32Bit) { $result.AnyCpu = $true }
        }
        return $result
    } catch {
        $result.Error = $_.Exception.Message
        return $result
    } finally {
        if ($null -ne $br) { $br.Dispose() }
        elseif ($null -ne $fs) { $fs.Dispose() }
    }
}

function Get-AsciiTokenHits {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string[]]$Tokens
    )
    $hits = New-Object System.Collections.Generic.List[string]
    try {
        $length = (Get-Item -LiteralPath $Path).Length
        if ($length -gt 80MB) {
            return $hits
        }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($token in $Tokens) {
            if ($text.IndexOf($token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $hits.Add($token)
            }
        }
    } catch {
        return $hits
    }
    return $hits
}

function Protect-EnvValue {
    param([string]$Name, [string]$Value)
    if ($Name -match $SecretNamePattern) { return '***redacted***' }
    return $Value
}

function Parse-AssignmentFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $found = New-Object System.Collections.Generic.List[psobject]
    if (-not (Test-Path -LiteralPath $Path)) { return $found }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -gt 2MB) { return $found }
    $raw = $null
    try {
        $raw = [System.IO.File]::ReadAllText($Path)
    } catch {
        return $found
    }
    $regex = [regex]'(?im)^\s*set\s+"?([A-Za-z_][A-Za-z0-9_]*)"?\s*=\s*"?([^"\r\n]*)"?\s*$'
    foreach ($m in $regex.Matches($raw)) {
        $name = $m.Groups[1].Value
        if ($InterestingEnvNames -notcontains $name.ToUpperInvariant()) { continue }
        $value = $m.Groups[2].Value.Trim()
        $found.Add((New-Object psobject -Property @{
            Name   = $name.ToUpperInvariant()
            Value  = (Protect-EnvValue -Name $name -Value $value)
            Source = $Path
        }))
    }
    $xmlRegex = [regex]'(?i)(WSNADDR|TUXCONFIG|TUXDIR|FLDTBLDIR32|FIELDTBLS32|VIEWDIR32|VIEWFILES32|TOBJADDR)["\s=:]+([^"<>\s]+)'
    foreach ($m in $xmlRegex.Matches($raw)) {
        $name = $m.Groups[1].Value.ToUpperInvariant()
        $value = $m.Groups[2].Value.Trim().Trim('"')
        $already = $false
        foreach ($existing in $found) {
            if ($existing.Name -eq $name -and $existing.Value -eq (Protect-EnvValue -Name $name -Value $value)) {
                $already = $true
            }
        }
        if ($already) { continue }
        if ($InterestingEnvNames -notcontains $name) { continue }
        $found.Add((New-Object psobject -Property @{
            Name   = $name
            Value  = (Protect-EnvValue -Name $name -Value $value)
            Source = $Path
        }))
    }
    return $found
}

function Get-MachineEnvAssignments {
    $found = New-Object System.Collections.Generic.List[psobject]
    foreach ($name in $InterestingEnvNames) {
        $value = [Environment]::GetEnvironmentVariable($name, 'Process')
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = [Environment]::GetEnvironmentVariable($name, 'User')
        }
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = [Environment]::GetEnvironmentVariable($name, 'Machine')
        }
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $found.Add((New-Object psobject -Property @{
            Name   = $name
            Value  = (Protect-EnvValue -Name $name -Value $value)
            Source = 'environment'
        }))
    }
    return $found
}

function Merge-Assignments {
    param($Items)
    $map = @{}
    $sources = @{}
    foreach ($item in $Items) {
        $map[$item.Name] = $item.Value
        if (-not $sources.ContainsKey($item.Name)) {
            $sources[$item.Name] = New-Object System.Collections.Generic.List[string]
        }
        if (-not $sources[$item.Name].Contains($item.Source)) {
            $sources[$item.Name].Add($item.Source)
        }
    }
    return New-Object psobject -Property @{
        Values  = $map
        Sources = $sources
    }
}

function Get-MapValue {
    param($Map, [string]$Name)
    if ($null -eq $Map) { return $null }
    if ($Map.ContainsKey($Name)) { return [string]$Map[$Name] }
    return $null
}

function Add-UniquePath {
    param($List, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $full = $Path.Trim().Trim('"')
    if ($full.EndsWith('\bin') -or $full.EndsWith('/bin')) {
        $parent = Split-Path -Path $full -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent)) { $full = $parent }
    }
    foreach ($existing in $List) {
        if ($existing -eq $full) { return }
    }
    try {
        if (Test-Path -LiteralPath $full) {
            $resolved = (Resolve-Path -LiteralPath $full).Path
            foreach ($existing in @($List)) {
                if ($existing -eq $resolved) { return }
            }
            $List.Add($resolved)
            return
        }
    } catch {
        return
    }
}

function Test-TuxedoHome {
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
    $markers = @(
        'bin\libwsc.dll', 'bin\libtux.dll', 'bin\tmboot.exe', 'bin\tmadmin.exe', 'bin\wtuxws32.dll',
        'lib\libwsc.dll', 'lib\libtux.dll'
    )
    foreach ($rel in $markers) {
        if (Test-Path -LiteralPath (Join-Path $Dir $rel)) { return $true }
    }
    return $false
}

function Get-RegistryInstalls {
    $rows = New-Object System.Collections.Generic.List[psobject]
    $views = @(
        [Microsoft.Win32.RegistryView]::Registry64,
        [Microsoft.Win32.RegistryView]::Registry32
    )
    foreach ($view in $views) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $uninstall) { continue }
            foreach ($subName in $uninstall.GetSubKeyNames()) {
                $sub = $null
                try {
                    $sub = $uninstall.OpenSubKey($subName)
                    if ($null -eq $sub) { continue }
                    $display = [string]$sub.GetValue('DisplayName')
                    if ([string]::IsNullOrWhiteSpace($display)) { continue }
                    if ($display -notmatch 'Tuxedo|Jolt') { continue }
                    $rows.Add((New-Object psobject -Property @{
                        DisplayName     = $display
                        DisplayVersion  = [string]$sub.GetValue('DisplayVersion')
                        InstallLocation = [string]$sub.GetValue('InstallLocation')
                        Publisher       = [string]$sub.GetValue('Publisher')
                        RegistryView    = $view.ToString()
                    }))
                } catch {
                    continue
                } finally {
                    if ($null -ne $sub) { $sub.Dispose() }
                }
            }
        } catch {
            continue
        } finally {
            if ($null -ne $base) { $base.Dispose() }
        }
    }
    return $rows
}

function Find-TuxedoHomes {
    param(
        [string]$ExplicitTuxDir,
        [string]$ExtraRoot,
        [switch]$SkipMachine,
        $EnvMap
    )
    $homes = New-Object System.Collections.Generic.List[string]
    $checked = New-Object System.Collections.Generic.List[string]
    $registry = New-Object System.Collections.Generic.List[psobject]

    $explicit = Resolve-FullPath $ExplicitTuxDir
    if ($explicit) { Add-UniquePath -List $homes -Path $explicit }
    $fromEnv = Get-MapValue -Map $EnvMap -Name 'TUXDIR'
    if ($fromEnv) { Add-UniquePath -List $homes -Path $fromEnv }

    if (-not $SkipMachine) {
        $checked.Add('Environment variable TUXDIR')
        $checked.Add('Registry uninstall keys in the 32-bit and 64-bit views')
        $checked.Add('PATH entries that contain tmboot.exe or tmadmin.exe')
        $registry = Get-RegistryInstalls
        foreach ($row in $registry) {
            Add-UniquePath -List $homes -Path $row.InstallLocation
        }
        $pathEntries = @()
        if ($env:PATH) { $pathEntries = $env:PATH -split ';' }
        foreach ($entry in $pathEntries) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            foreach ($exe in @('tmboot.exe', 'tmadmin.exe', 'libwsc.dll')) {
                $candidate = Join-Path $entry.Trim() $exe
                if (Test-Path -LiteralPath $candidate) {
                    Add-UniquePath -List $homes -Path $entry.Trim()
                }
            }
        }
        $roots = @(
            'C:\bea', 'C:\bea64', 'C:\oracle', 'C:\Oracle', 'C:\tuxedo', 'C:\Tuxedo',
            'C:\Program Files\Oracle', 'C:\Program Files\BEA',
            'C:\Program Files (x86)\Oracle', 'C:\Program Files (x86)\BEA'
        )
        if (-not [string]::IsNullOrWhiteSpace($ExtraRoot)) { $roots += $ExtraRoot }
        foreach ($root in $roots) {
            $rootFull = Resolve-FullPath $root
            if (-not $rootFull) { continue }
            $checked.Add($rootFull)
            Add-UniquePath -List $homes -Path $rootFull
            try {
                $dirs = @(Get-ChildItem -LiteralPath $rootFull -Directory -Recurse -Depth 3 -ErrorAction SilentlyContinue)
                foreach ($dir in $dirs) {
                    if ($dir.Name -match 'tuxedo|jolt|^bea$') {
                        Add-UniquePath -List $homes -Path $dir.FullName
                    }
                }
            } catch {
                continue
            }
        }
    } else {
        $checked.Add('Machine-wide search skipped')
        if (-not [string]::IsNullOrWhiteSpace($ExplicitTuxDir)) {
            $checked.Add("Explicit -TuxDir $ExplicitTuxDir")
        }
    }

    $confirmed = New-Object System.Collections.Generic.List[string]
    foreach ($tuxHome in @($homes)) {
        if (Test-TuxedoHome $tuxHome) { $confirmed.Add($tuxHome) }
    }
    return New-Object psobject -Property @{
        Homes    = $confirmed
        Checked  = $checked
        Registry = $registry
    }
}

function Get-VersionFromPath {
    param([string]$Path)
    $match = [regex]::Match($Path, '(\d+\.\d+\.\d+(?:\.\d+)*)')
    if ($match.Success) { return $match.Groups[1].Value }
    return $null
}

function Get-LibraryRecord {
    param([string]$Path)
    $pe = Get-PeInfo -Path $Path
    $product = ''
    $fileVersion = ''
    $productVersion = ''
    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if ($info.ProductName) { $product = $info.ProductName }
        if ($info.FileVersion) { $fileVersion = $info.FileVersion }
        if ($info.ProductVersion) { $productVersion = $info.ProductVersion }
    } catch {
        $product = ''
    }
    return New-Object psobject -Property @{
        Path           = $Path
        Name           = [System.IO.Path]::GetFileName($Path)
        Machine        = $pe.Machine
        IsPe           = $pe.IsPe
        IsDotNet       = $pe.IsDotNet
        ProductName    = $product
        FileVersion    = $fileVersion
        ProductVersion = $productVersion
        PeError        = $pe.Error
    }
}

function Get-HomeLibraries {
    param([string]$InstallHome)
    $names = @(
        'libwsc.dll', 'libtux.dll', 'libfml.dll', 'libfml32.dll', 'libengine.dll',
        'libbuft.dll', 'libtxml.dll', 'wtuxws32.dll', 'joltwsc.dll', 'jolt.dll',
        'tmboot.exe', 'tmadmin.exe'
    )
    $records = New-Object System.Collections.Generic.List[psobject]
    foreach ($sub in @('bin', 'lib')) {
        foreach ($name in $names) {
            $path = Join-Path (Join-Path $InstallHome $sub) $name
            if (Test-Path -LiteralPath $path) {
                $records.Add((Get-LibraryRecord -Path $path))
            }
        }
    }
    try {
        $jars = @(Get-ChildItem -LiteralPath $InstallHome -Filter 'jolt.jar' -Recurse -Depth 4 -File -ErrorAction SilentlyContinue)
        foreach ($jar in $jars) {
            $records.Add((New-Object psobject -Property @{
                Path           = $jar.FullName
                Name           = $jar.Name
                Machine        = 'jar'
                IsPe           = $false
                IsDotNet       = $false
                ProductName    = 'Jolt'
                FileVersion    = ''
                ProductVersion = ''
                PeError        = $null
            }))
        }
    } catch {
        # A locked directory should not hide the libraries we already found.
    }
    return $records
}

function Get-AppBinaries {
    param([string]$ResolvedApp)
    $files = New-Object System.Collections.Generic.List[string]
    if (-not $ResolvedApp) { return $files }
    $item = Get-Item -LiteralPath $ResolvedApp
    $roots = New-Object System.Collections.Generic.List[string]
    if (-not $item.PSIsContainer) {
        $files.Add($item.FullName)
        $roots.Add($item.DirectoryName)
    } else {
        $roots.Add($item.FullName)
    }
    foreach ($root in @($roots)) {
        try {
            $candidates = @(Get-ChildItem -LiteralPath $root -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(exe|dll)$' })
            foreach ($candidate in $candidates) {
                if ($candidate.Name -match '^(api-ms-win|msvcr|msvcp|vcruntime|ucrtbase|concrt)') { continue }
                $already = $false
                foreach ($existing in $files) {
                    if ($existing -eq $candidate.FullName) { $already = $true }
                }
                if (-not $already) { $files.Add($candidate.FullName) }
                if ($files.Count -ge 80) { break }
            }
        } catch {
            continue
        }
    }
    return $files
}

function Get-ConfigFiles {
    param([string]$Folder)
    $files = New-Object System.Collections.Generic.List[string]
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return $files }
    try {
        $candidates = @(Get-ChildItem -LiteralPath $Folder -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '^\.(bat|cmd|config|xml|ini|properties|json|cfg)$' })
        foreach ($candidate in $candidates) {
            if ($candidate.Length -gt 2MB) { continue }
            $files.Add($candidate.FullName)
            if ($files.Count -ge 200) { break }
        }
    } catch {
        return $files
    }
    return $files
}

function Resolve-TableFiles {
    param($EnvMap, [string]$DirName, [string]$ListName, [string]$Extension)
    $dirsRaw = Get-MapValue -Map $EnvMap -Name $DirName
    $listRaw = Get-MapValue -Map $EnvMap -Name $ListName
    $dirs = New-Object System.Collections.Generic.List[string]
    if ($dirsRaw) {
        foreach ($part in ($dirsRaw -split ';')) {
            $part = $part.Trim()
            if ($part -and (Test-Path -LiteralPath $part)) { $dirs.Add((Resolve-Path -LiteralPath $part).Path) }
        }
    }
    $files = New-Object System.Collections.Generic.List[string]
    if ($listRaw) {
        foreach ($name in ($listRaw -split ',')) {
            $name = $name.Trim()
            if (-not $name) { continue }
            foreach ($dir in $dirs) {
                $candidate = Join-Path $dir $name
                if (Test-Path -LiteralPath $candidate) {
                    $files.Add((Resolve-Path -LiteralPath $candidate).Path)
                }
            }
        }
    }
    if ($files.Count -eq 0) {
        foreach ($dir in $dirs) {
            try {
                $found = @(Get-ChildItem -LiteralPath $dir -Filter $Extension -File -ErrorAction SilentlyContinue)
                foreach ($file in $found) {
                    $files.Add($file.FullName)
                    if ($files.Count -ge 50) { break }
                }
            } catch {
                continue
            }
        }
    }
    return New-Object psobject -Property @{
        Directories = $dirs
        Files       = $files
    }
}

function Test-FieldTableContent {
    param([string]$Path)
    try {
        $fs = New-Object System.IO.FileStream($Path, 'Open', 'Read', 'ReadWrite')
        $sr = New-Object System.IO.StreamReader($fs)
        $sample = $sr.ReadToEnd()
        $sr.Dispose()
        if ($sample.Length -gt 4000) { $sample = $sample.Substring(0, 4000) }
        return ($sample -match '(?m)^\s*\*base\b')
    } catch {
        return $false
    }
}

function Get-WsEndpoints {
    param([string]$Wsnaddr)
    $list = New-Object System.Collections.Generic.List[psobject]
    if ([string]::IsNullOrWhiteSpace($Wsnaddr)) { return $list }
    $regex = [regex]'//([A-Za-z0-9._-]+):(\d+)'
    foreach ($m in $regex.Matches($Wsnaddr)) {
        if ($list.Count -ge 5) { break }
        $list.Add((New-Object psobject -Property @{
            Host = $m.Groups[1].Value
            Port = [int]$m.Groups[2].Value
        }))
    }
    return $list
}

function Test-TcpPort {
    param([string]$TargetHost, [int]$Port, [int]$TimeoutMs = 2000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) {
            $client.Close()
            return 'timed out'
        }
        $client.EndConnect($iar)
        $client.Close()
        return 'reachable'
    } catch {
        try { $client.Close() } catch { }
        return 'closed'
    }
}

function Get-RunningAppModules {
    param([string]$AppFolder, [string]$AppExe)
    $rows = New-Object System.Collections.Generic.List[psobject]
    $running = $false
    if (-not $AppFolder) { return (New-Object psobject -Property @{ Running = $false; Modules = $rows }) }
    $procs = @(Get-Process -ErrorAction SilentlyContinue)
    foreach ($proc in $procs) {
        $procPath = $null
        try { $procPath = $proc.Path } catch { $procPath = $null }
        if (-not $procPath) { continue }
        $inFolder = $procPath.StartsWith($AppFolder, [System.StringComparison]::OrdinalIgnoreCase)
        $isExe = $AppExe -and ($procPath -eq $AppExe)
        if (-not $inFolder -and -not $isExe) { continue }
        $running = $true
        try {
            $modules = @($proc.Modules)
        } catch {
            continue
        }
        foreach ($mod in $modules) {
            if ($mod.ModuleName -notmatch '^(libwsc|libtux|libfml|libengine|libbuft|libtxml|wtuxws|jolt)') { continue }
            $rows.Add((New-Object psobject -Property @{
                Process = $proc.ProcessName
                Module  = $mod.ModuleName
                Path    = $mod.FileName
            }))
        }
    }
    return New-Object psobject -Property @{
        Running = $running
        Modules = $rows
    }
}

function New-MinimalPe {
    param(
        [Parameter(Mandatory = $true)][string]$MachineName,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$AsciiPayload
    )
    $pe = New-Object byte[] 1024
    $pe[0] = 0x4D
    $pe[1] = 0x5A
    $pe[0x3C] = 0x80
    $pe[0x80] = 0x50
    $pe[0x81] = 0x45
    if ($MachineName -eq 'x64') {
        $pe[0x84] = 0x64
        $pe[0x85] = 0x86
        $pe[0x98] = 0x0B
        $pe[0x99] = 0x02
        $pe[0x104] = 16
    } else {
        $pe[0x84] = 0x4C
        $pe[0x85] = 0x01
        $pe[0x98] = 0x0B
        $pe[0x99] = 0x01
        $pe[0xF4] = 16
    }
    $pe[0x86] = 1
    $pe[0x94] = 0xF0
    $nameBytes = [System.Text.Encoding]::ASCII.GetBytes('.text')
    [System.Array]::Copy($nameBytes, 0, $pe, 0x188, $nameBytes.Length)
    $payload = [System.Text.Encoding]::ASCII.GetBytes($AsciiPayload)
    $len = $payload.Length
    $pe[0x190] = [byte]($len -band 0xFF)
    $pe[0x191] = [byte](($len -shr 8) -band 0xFF)
    $pe[0x194] = 0x00
    $pe[0x195] = 0x10
    $pe[0x198] = [byte]($len -band 0xFF)
    $pe[0x199] = [byte](($len -shr 8) -band 0xFF)
    $pe[0x19C] = 0x00
    $pe[0x19D] = 0x02
    if ((0x200 + $len) -gt $pe.Length) {
        $bigger = New-Object byte[] (0x200 + $len + 16)
        [System.Array]::Copy($pe, $bigger, $pe.Length)
        $pe = $bigger
    }
    [System.Array]::Copy($payload, 0, $pe, 0x200, $len)
    [System.IO.File]::WriteAllBytes($Path, $pe)
}

function Get-Kernel32Path {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        return (Join-Path $env:SystemRoot 'Sysnative\kernel32.dll')
    }
    return (Join-Path $env:SystemRoot 'System32\kernel32.dll')
}

function Invoke-Discovery {
    param(
        [string]$AppPath,
        [string]$TuxDir,
        [string]$StartupScript,
        [string]$SearchRoot,
        [string]$OutDir,
        [switch]$NoMachineScan,
        [switch]$SkipNetwork
    )

    Write-ProgressLine 'TuxLoad discovery is read-only. Collecting operating system, Tuxedo installs, application client mode, buffers, and libraries.'

    $osCaption = 'Windows'
    $osVersion = [Environment]::OSVersion.Version.ToString()
    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.ProductName) { $osCaption = [string]$cv.ProductName }
        if ($cv.CurrentBuild) { $osVersion = "$osVersion build $($cv.CurrentBuild)" }
        if ($cv.DisplayVersion) { $osVersion = "$osVersion $($cv.DisplayVersion)" }
        if ($cv.CurrentBuild -and [int]$cv.CurrentBuild -ge 22000 -and $osCaption -like 'Windows 10*') {
            $osCaption = $osCaption -replace '^Windows 10', 'Windows 11'
        }
    } catch {
        $osCaption = 'Windows'
    }
    $osArch = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }

    $assignmentItems = New-Object System.Collections.Generic.List[psobject]
    if (-not $NoMachineScan) {
        foreach ($row in @(Get-MachineEnvAssignments)) { $assignmentItems.Add($row) }
    }
    $startupExplicit = Resolve-FullPath $StartupScript
    if ($StartupScript -and -not $startupExplicit) {
        Write-ProgressLine "Startup script was not found: $StartupScript"
    }
    if ($startupExplicit) {
        foreach ($row in @(Parse-AssignmentFile -Path $startupExplicit)) { $assignmentItems.Add($row) }
    }

    $appResolved = Resolve-FullPath $AppPath
    $appFolder = $null
    $appExe = $null
    $appMissing = $false
    if ($AppPath -and -not $appResolved) { $appMissing = $true }
    if ($appResolved) {
        $appItem = Get-Item -LiteralPath $appResolved
        if ($appItem.PSIsContainer) {
            $appFolder = $appItem.FullName
        } else {
            $appExe = $appItem.FullName
            $appFolder = $appItem.DirectoryName
        }
        foreach ($cfg in @(Get-ConfigFiles -Folder $appFolder)) {
            foreach ($row in @(Parse-AssignmentFile -Path $cfg)) { $assignmentItems.Add($row) }
        }
    }

    $merged = Merge-Assignments -Items $assignmentItems
    $envMap = $merged.Values

    Write-ProgressLine 'Looking for Tuxedo installations.'
    $homeSearch = Find-TuxedoHomes -ExplicitTuxDir $TuxDir -ExtraRoot $SearchRoot -SkipMachine:$NoMachineScan -EnvMap $envMap

    $installs = New-Object System.Collections.Generic.List[psobject]
    foreach ($tuxHome in @($homeSearch.Homes)) {
        Write-ProgressLine "Reading libraries in $tuxHome"
        $libs = @(Get-HomeLibraries -InstallHome $tuxHome)
        $version = $null
        $versionSource = $null
        foreach ($lib in $libs) {
            $named = $lib.ProductName -match 'Tuxedo|Oracle|BEA|Jolt'
            if ($named -and $lib.ProductVersion) {
                $version = $lib.ProductVersion
                $versionSource = 'file version resource'
                break
            }
        }
        if (-not $version) {
            $version = Get-VersionFromPath -Path $tuxHome
            if ($version) { $versionSource = 'install directory name' }
        }
        $installs.Add((New-Object psobject -Property @{
            Home          = $tuxHome
            Version       = $version
            VersionSource = $versionSource
            Libraries     = $libs
        }))
    }

    $binaryHits = New-Object System.Collections.Generic.List[string]
    $appPe = $null
    $binaries = @()
    if ($appFolder) {
        Write-ProgressLine 'Reading the application executable and nearby libraries.'
        $binaries = @(Get-AppBinaries -ResolvedApp $(if ($appExe) { $appExe } else { $appFolder }))
        foreach ($binary in $binaries) {
            if (-not $appPe -and $binary -match '\.exe$') {
                $appPe = Get-PeInfo -Path $binary
                if ($appPe.IsPe -and -not $appExe) { $appExe = $binary }
            }
            if ($appExe -and $binary -eq $appExe) { $appPe = Get-PeInfo -Path $binary }
            foreach ($hit in @(Get-AsciiTokenHits -Path $binary -Tokens $BinaryTokens)) {
                if (-not $binaryHits.Contains($hit)) { $binaryHits.Add($hit) }
            }
        }
    }

    if ($NoMachineScan) {
        $loaded = New-Object psobject -Property @{
            Running = $false
            Modules = (New-Object System.Collections.Generic.List[psobject])
        }
    } else {
        $loaded = Get-RunningAppModules -AppFolder $appFolder -AppExe $appExe
    }
    foreach ($mod in @($loaded.Modules)) {
        if ($mod.Path -and (Test-Path -LiteralPath $mod.Path)) {
            $record = Get-LibraryRecord -Path $mod.Path
            $alreadyHome = $false
            foreach ($inst in $installs) {
                foreach ($lib in @($inst.Libraries)) {
                    if ($lib.Path -eq $record.Path) { $alreadyHome = $true }
                }
            }
            if (-not $alreadyHome) {
                $installs.Add((New-Object psobject -Property @{
                    Home          = 'loaded by the running application'
                    Version       = $(if ($record.ProductName -match 'Tuxedo|Oracle|BEA|Jolt') { $record.ProductVersion } else { $null })
                    VersionSource = 'loaded module version resource'
                    Libraries     = @($record)
                }))
            }
        }
    }

    $fml32 = Resolve-TableFiles -EnvMap $envMap -DirName 'FLDTBLDIR32' -ListName 'FIELDTBLS32' -Extension '*.fml32'
    $fml16 = Resolve-TableFiles -EnvMap $envMap -DirName 'FLDTBLDIR' -ListName 'FIELDTBLS' -Extension '*.fml'
    $confirmedFml = 0
    foreach ($file in @($fml32.Files)) {
        if (Test-FieldTableContent -Path $file) { $confirmedFml++ }
    }

    $endpoints = @(Get-WsEndpoints -Wsnaddr (Get-MapValue -Map $envMap -Name 'WSNADDR'))
    $tcpRows = New-Object System.Collections.Generic.List[psobject]
    if (-not $SkipNetwork) {
        foreach ($ep in $endpoints) {
            Write-ProgressLine ("Checking TCP {0}:{1}" -f $ep.Host, $ep.Port)
            $state = Test-TcpPort -TargetHost $ep.Host -Port $ep.Port
            $tcpRows.Add((New-Object psobject -Property @{
                Host  = $ep.Host
                Port  = $ep.Port
                State = $state
            }))
        }
    }

    $allLibs = New-Object System.Collections.Generic.List[psobject]
    foreach ($inst in $installs) {
        foreach ($lib in @($inst.Libraries)) { $allLibs.Add($lib) }
    }

    $has = {
        param($name)
        foreach ($hit in $binaryHits) {
            if ($hit -eq $name) { return $true }
        }
        foreach ($mod in @($loaded.Modules)) {
            if ($mod.Module -match [regex]::Escape($name)) { return $true }
        }
        return $false
    }

    $wsn = Get-MapValue -Map $envMap -Name 'WSNADDR'
    $tuxConfig = Get-MapValue -Map $envMap -Name 'TUXCONFIG'
    $tobj = Get-MapValue -Map $envMap -Name 'TOBJADDR'
    $classpath = Get-MapValue -Map $envMap -Name 'CLASSPATH'

    $workstation = (& $has 'libwsc.dll') -or (& $has 'wtuxws32.dll') -or (-not [string]::IsNullOrWhiteSpace($wsn))
    $native = (& $has 'libtux.dll') -or (-not [string]::IsNullOrWhiteSpace($tuxConfig) -and [string]::IsNullOrWhiteSpace($wsn))
    $jolt = (& $has 'jolt.dll') -or (& $has 'joltwsc.dll') -or ($classpath -match '(?i)jolt')
    foreach ($lib in $allLibs) {
        if ($lib.Name -eq 'jolt.jar') { $jolt = $true }
        if ($lib.Name -eq 'libwsc.dll' -or $lib.Name -eq 'wtuxws32.dll') { $workstation = $true }
        if ($lib.Name -eq 'libtux.dll') { $native = $true }
    }
    $corba = -not [string]::IsNullOrWhiteSpace($tobj)

    $modes = New-Object System.Collections.Generic.List[string]
    if ($workstation) { $modes.Add('Workstation') }
    if ($native -and -not $workstation) { $modes.Add('Native') }
    elseif ($native -and $tuxConfig -and $wsn) { $modes.Add('Native variables are also set') }
    if ($jolt) { $modes.Add('Jolt') }
    if ($corba) { $modes.Add('CORBA') }
    if ($modes.Count -eq 0) { $modes.Add('not determined') }
    $clientMode = ($modes -join '; ')

    $language = 'not determined'
    if ($appPe -and $appPe.IsDotNet) {
        $language = '.NET'
        if ($appPe.AnyCpu) { $language = '.NET AnyCPU' }
    } elseif ($jolt) {
        $language = 'Java (Jolt)'
    } elseif ($appPe -and $appPe.IsPe -and (($workstation -and (& $has 'libwsc.dll')) -or (& $has 'libtux.dll'))) {
        $language = 'C/C++'
    } elseif ($appPe -and $appPe.IsPe) {
        $language = 'native executable, Tuxedo import not confirmed'
    }

    $buffers = New-Object System.Collections.Generic.List[string]
    if ((& $has 'FML32') -or (& $has 'Fadd32') -or (& $has 'libfml32.dll') -or (Get-MapValue -Map $envMap -Name 'FIELDTBLS32') -or @($fml32.Files).Count -gt 0) {
        $buffers.Add('FML32')
    }
    if ((Get-MapValue -Map $envMap -Name 'FIELDTBLS') -or @($fml16.Files).Count -gt 0 -or (& $has 'libfml.dll')) {
        $buffers.Add('FML16')
    }
    if ((Get-MapValue -Map $envMap -Name 'VIEWFILES32') -or (Get-MapValue -Map $envMap -Name 'VIEWDIR32') -or (& $has 'VIEW32')) {
        $buffers.Add('VIEW32')
    }
    if (& $has 'CARRAY') { $buffers.Add('CARRAY') }
    if (& $has 'libtxml.dll') { $buffers.Add('XML') }
    if ($buffers.Count -eq 0) { $buffers.Add('not determined') }

    $conversations = ((& $has 'tpconnect') -or (& $has 'tpsend') -or (& $has 'tprecv'))
    $transactions = ((& $has 'tpbegin') -or (& $has 'tpcommit') -or (& $has 'tpabort'))
    $async = ((& $has 'tpacall') -or (& $has 'tpgetrply'))
    $queues = ((& $has 'tpenqueue') -or (& $has 'tpdequeue'))

    $lib64wsc = @($allLibs | Where-Object { $_.Name -eq 'libwsc.dll' -and $_.Machine -eq 'x64' })
    $lib32wsc = @($allLibs | Where-Object { ($_.Name -eq 'libwsc.dll' -or $_.Name -eq 'wtuxws32.dll') -and $_.Machine -eq 'x86' })
    $lib64tux = @($allLibs | Where-Object { $_.Name -eq 'libtux.dll' -and $_.Machine -eq 'x64' })
    $fieldCount = @($fml32.Files).Count

    $q2Why = New-Object System.Collections.Generic.List[string]
    if ($wsn) { $q2Why.Add('WSNADDR is set') }
    if ($tuxConfig) { $q2Why.Add('TUXCONFIG is set') }
    if (& $has 'libwsc.dll') { $q2Why.Add('the application references libwsc.dll') }
    if (& $has 'libtux.dll') { $q2Why.Add('the application references libtux.dll') }
    if (@($loaded.Modules).Count -gt 0) { $q2Why.Add('a running process has a Tuxedo library loaded') }
    if ($jolt) { $q2Why.Add('Jolt is present') }
    if ($q2Why.Count -eq 0) { $q2Why.Add('no startup variables or Tuxedo references were found') }

    $q2Confidence = 'low'
    $strongBinary = (& $has 'libwsc.dll') -or (& $has 'libtux.dll') -or (@($loaded.Modules).Count -gt 0) -or $jolt
    $strongConfig = $wsn -or $tuxConfig -or $tobj
    if ($strongBinary -and $strongConfig) { $q2Confidence = 'high' }
    elseif ($strongBinary -or $strongConfig) { $q2Confidence = 'medium' }
    if (-not $appFolder) { $q2Confidence = 'low' }

    $q3Confidence = 'low'
    if ($fieldCount -gt 0 -or (& $has 'Fadd32') -or (& $has 'FML32')) { $q3Confidence = 'high' }
    elseif ((Get-MapValue -Map $envMap -Name 'FLDTBLDIR32') -or (Get-MapValue -Map $envMap -Name 'VIEWDIR32')) { $q3Confidence = 'medium' }

    $q1Confidence = 'low'
    if ($installs.Count -gt 0 -and $installs[0].Version) { $q1Confidence = 'high' }
    elseif ($installs.Count -gt 0) { $q1Confidence = 'medium' }

    $replay = 'not ready - no Tuxedo client libraries were found'
    $wsc64 = 'not found'
    if ($lib64wsc.Count -gt 0) {
        $wsc64 = 'found'
        if ($fieldCount -gt 0) {
            $replay = 'ready for a 64-bit Workstation replay engine'
        } else {
            $replay = 'partial - a 64-bit Workstation library is present, and field tables were not found'
        }
    } elseif ($lib64tux.Count -gt 0) {
        $replay = 'partial - 64-bit native libraries are present, and libwsc.dll was not found'
    } elseif ($lib32wsc.Count -gt 0) {
        $replay = 'partial - only 32-bit Workstation libraries were found'
    }

    $recording = 'application bitness was not determined; re-run with -AppPath pointing at the executable'
    if ($appPe -and $appPe.Machine -eq 'x64') {
        $recording = 'the application is 64-bit, so the capture agent must be 64-bit and must hook this process'
    } elseif ($appPe -and $appPe.Machine -eq 'x86') {
        $recording = 'the application executable is 32-bit'
    } elseif ($appPe -and $appPe.AnyCpu) {
        $recording = 'the application is .NET AnyCPU and runs as 64-bit on this operating system'
    }

    $gaps = New-Object System.Collections.Generic.List[string]
    if (-not $appFolder) { $gaps.Add('Pass -AppPath so the script can inspect the application executable.') }
    if ($appMissing) { $gaps.Add("AppPath was not found: $AppPath") }
    if ($installs.Count -eq 0) { $gaps.Add('No Tuxedo installation was found. Re-run with -TuxDir set to the folder that contains bin.') }
    if ($appFolder -and -not $NoMachineScan -and -not $loaded.Running) { $gaps.Add('The application was not running, so the loaded Tuxedo DLL could not be confirmed. Start the application and run the script again.') }
    if ((Get-MapValue -Map $envMap -Name 'FLDTBLDIR32') -and $fieldCount -eq 0) { $gaps.Add('FLDTBLDIR32 is set, but no .fml32 files were found in that folder.') }
    if ($lib64wsc.Count -eq 0) { $gaps.Add('A 64-bit libwsc.dll was not found. Replay needs the 64-bit Tuxedo Workstation client on the load generator.') }
    $gaps.Add('Server operating system and server Tuxedo version are not collected here. Run discovery/discover-tuxedo.sh on the Tuxedo server.')

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('TuxLoad discovery')
    $lines.Add("Script: Discover-Tuxedo.ps1 $ScriptVersion")
    $lines.Add('Collected: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $lines.Add('Computer: ' + $env:COMPUTERNAME)
    $lines.Add('Read-only: yes')
    $lines.Add('')
    $lines.Add('Answer 1 - Tuxedo version and operating system')
    $lines.Add("  Operating system: $osCaption $osVersion ($osArch)")
    $lines.Add('  PowerShell process bitness: ' + $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }))
    $lines.Add('  Tuxedo installs found: ' + @($installs).Count)
    if ($installs.Count -eq 0) {
        $lines.Add('  No Tuxedo installation was confirmed on this machine.')
    }
    foreach ($inst in $installs) {
        $verText = 'unknown'
        if ($inst.Version) { $verText = $inst.Version }
        $src = ''
        if ($inst.VersionSource) { $src = ' (from ' + $inst.VersionSource + ')' }
        $lines.Add('  - ' + $inst.Home)
        $lines.Add('    Version: ' + $verText + $src)
    }
    if ($homeSearch.Registry.Count -gt 0) {
        $lines.Add('  Registry products:')
        foreach ($row in @($homeSearch.Registry)) {
            $lines.Add('  - ' + $row.DisplayName + ' ' + $row.DisplayVersion + ' [' + $row.RegistryView + ']')
        }
    }
    $lines.Add('  Server operating system: not collected. Run discover-tuxedo.sh on the Tuxedo server.')
    $lines.Add('  Confidence: ' + $q1Confidence)
    $lines.Add('')
    $lines.Add('Answer 2 - Client mode and language')
    if ($appExe) { $lines.Add('  Application: ' + $appExe) }
    elseif ($appFolder) { $lines.Add('  Application folder: ' + $appFolder) }
    else { $lines.Add('  Application: not supplied') }
    if ($appPe -and $appPe.Machine) { $lines.Add('  Application bitness: ' + $appPe.Machine) }
    if ($appPe -and $appPe.IsDotNet) { $lines.Add('  CLR: yes') }
    $lines.Add('  Client mode: ' + $clientMode)
    $lines.Add('  Language: ' + $language)
    $lines.Add('  WSNADDR: ' + $(if ($wsn) { $wsn } else { 'not set' }))
    $lines.Add('  TUXCONFIG: ' + $(if ($tuxConfig) { $tuxConfig } else { 'not set' }))
    $lines.Add('  TOBJADDR: ' + $(if ($tobj) { $tobj } else { 'not set' }))
    if ($SkipNetwork) {
        $lines.Add('  Listener TCP: skipped')
    } elseif ($tcpRows.Count -eq 0) {
        $lines.Add('  Listener TCP: no //host:port address was found')
    } else {
        foreach ($row in $tcpRows) {
            $lines.Add(('  Listener TCP: {0}:{1} {2}' -f $row.Host, $row.Port, $row.State))
        }
    }
    $lines.Add('  Application process running: ' + $(if ($loaded.Running) { 'yes' } else { 'no' }))
    $lines.Add('  Confidence: ' + $q2Confidence)
    $lines.Add('  Why: ' + ($q2Why -join '; '))
    $lines.Add('')
    $lines.Add('Answer 3 - Buffer types, conversations, and transactions')
    $lines.Add('  Buffers: ' + ($buffers -join ', '))
    $lines.Add('  FML32 field tables: ' + $fieldCount)
    $lines.Add('  FML32 files that contain *base: ' + $confirmedFml)
    $fmlDirs = @($fml32.Directories) -join '; '
    if (-not $fmlDirs) { $fmlDirs = 'not set' }
    $lines.Add('  FLDTBLDIR32: ' + $fmlDirs)
    $lines.Add('  Conversations: ' + $(if ($conversations) { 'found' } else { 'not found' }))
    $lines.Add('  Transactions: ' + $(if ($transactions) { 'found' } else { 'not found' }))
    $lines.Add('  Async calls: ' + $(if ($async) { 'found' } else { 'not found' }))
    $lines.Add('  Queues: ' + $(if ($queues) { 'found' } else { 'not found' }))
    $lines.Add('  Confidence: ' + $q3Confidence)
    $lines.Add('')
    $lines.Add('Answer 4 - 64-bit libraries and field tables for replay')
    $lines.Add('  64-bit workstation library: ' + $wsc64)
    foreach ($lib in $lib64wsc) { $lines.Add('    ' + $lib.Path + ' (' + $lib.Machine + ')') }
    $lines.Add('  32-bit workstation library count: ' + $lib32wsc.Count)
    $lines.Add('  64-bit native library count: ' + $lib64tux.Count)
    $lines.Add('  Field tables: ' + $fieldCount)
    $lines.Add('  Replay readiness: ' + $replay)
    $lines.Add('  Recording readiness: ' + $recording)
    $lines.Add('  Gaps:')
    foreach ($gap in $gaps) { $lines.Add('  - ' + $gap) }
    $lines.Add('')
    $lines.Add('What was checked')
    foreach ($item in @($homeSearch.Checked)) { $lines.Add('  - ' + $item) }
    $lines.Add('')
    $lines.Add('Evidence - libraries')
    if ($allLibs.Count -eq 0) { $lines.Add('  none') }
    foreach ($lib in $allLibs) {
        $ver = $lib.FileVersion
        if (-not $ver) { $ver = 'no file version' }
        $machine = $lib.Machine
        if (-not $machine) { $machine = 'unknown bitness' }
        $lines.Add('  - ' + $lib.Name + ' ' + $machine + ' ' + $ver)
        $lines.Add('    ' + $lib.Path)
    }
    $lines.Add('')
    $lines.Add('Evidence - tokens found in application files')
    if ($binaryHits.Count -eq 0) { $lines.Add('  none') }
    else { $lines.Add('  ' + ($binaryHits -join ', ')) }
    $lines.Add('')
    $lines.Add('Evidence - loaded modules')
    if (@($loaded.Modules).Count -eq 0) { $lines.Add('  none') }
    foreach ($mod in @($loaded.Modules)) {
        $lines.Add('  - ' + $mod.Process + ' -> ' + $mod.Path)
    }
    $lines.Add('')
    $lines.Add('Evidence - field tables')
    $shown = 0
    foreach ($file in @($fml32.Files)) {
        $flag = 'unconfirmed'
        if (Test-FieldTableContent -Path $file) { $flag = 'has *base' }
        $lines.Add('  - ' + $file + ' (' + $flag + ')')
        $shown++
        if ($shown -ge 30) { break }
    }
    if ($fieldCount -eq 0) { $lines.Add('  none') }
    $lines.Add('')
    $lines.Add('Next step')
    $lines.Add('  Copy tuxload-discovery.txt back. Review it before sharing: it contains host names and file paths.')
    $lines.Add('  If this was not the application machine, copy Discover-Tuxedo.ps1 there and run it with -AppPath.')

    $reportText = $lines -join "`r`n"

    if (-not $OutDir) { $OutDir = Join-Path (Get-Location) 'tuxload-discovery-output' }
    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }
    $txtPath = Join-Path $OutDir 'tuxload-discovery.txt'
    $jsonPath = Join-Path $OutDir 'tuxload-discovery.json'
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($txtPath, $reportText + "`r`n", $utf8)

    $jsonObject = New-Object psobject -Property @{
        ScriptVersion = $ScriptVersion
        Computer      = $env:COMPUTERNAME
        OperatingSystem = "$osCaption $osVersion ($osArch)"
        Answer1 = "installs=$($installs.Count); confidence=$q1Confidence"
        Answer2 = "mode=$clientMode; language=$language; confidence=$q2Confidence"
        Answer3 = "buffers=$($buffers -join ', '); conversations=$(if ($conversations) {'found'} else {'not found'}); transactions=$(if ($transactions) {'found'} else {'not found'})"
        Answer4 = $replay
        Installs = @($installs | ForEach-Object { $_.Home })
        Libraries = @($allLibs | ForEach-Object { $_.Path })
        Tokens = @($binaryHits)
        FieldTableCount = $fieldCount
    }
    ($jsonObject | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    Write-Host ''
    Write-Host $reportText
    Write-Host ''
    Write-Host "Wrote $txtPath"
    Write-Host "Wrote $jsonPath"

    return New-Object psobject -Property @{
        Text                 = $reportText
        TextPath             = $txtPath
        ClientMode           = $clientMode
        Language             = $language
        Replay               = $replay
        Recording            = $recording
        Transactions         = $transactions
        Conversations        = $conversations
        FieldTableCount      = $fieldCount
        WorkstationLibrary64 = $wsc64
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Self-test failed: $Message" }
}

function Invoke-SelfTest {
    $failures = New-Object System.Collections.Generic.List[string]
    try {
        $kernel = Get-Kernel32Path
        $kinfo = Get-PeInfo -Path $kernel
        if ($kinfo.Machine -ne 'x64' -and $kinfo.Machine -ne 'ARM64') {
            throw "kernel32 machine was $($kinfo.Machine), error=$($kinfo.Error)"
        }
        if ($kinfo.IsDotNet) { throw 'kernel32 was classified as .NET' }
        $wow = Join-Path $env:SystemRoot 'SysWOW64\kernel32.dll'
        if (Test-Path -LiteralPath $wow) {
            $winfo = Get-PeInfo -Path $wow
            if ($winfo.Machine -ne 'x86') { throw "SysWOW64 kernel32 machine was $($winfo.Machine)" }
        }

        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('tuxload-selftest-' + [guid]::NewGuid().ToString('N'))
        $tux = Join-Path $root 'tuxedo12.2.2.0.0'
        $bin = Join-Path $tux 'bin'
        $app = Join-Path $root 'app'
        $fields = Join-Path $root 'fields'
        New-Item -ItemType Directory -Path $bin -Force | Out-Null
        New-Item -ItemType Directory -Path $app -Force | Out-Null
        New-Item -ItemType Directory -Path $fields -Force | Out-Null
        New-MinimalPe -MachineName 'x64' -Path (Join-Path $bin 'libwsc.dll') -AsciiPayload 'libwsc'
        $payload = 'tpcall tpbegin tpcommit libwsc.dll Fadd32 FML32'
        New-MinimalPe -MachineName 'x64' -Path (Join-Path $app 'billing.exe') -AsciiPayload $payload
        $fieldFile = Join-Path $fields 'cust.fml32'
        [System.IO.File]::WriteAllText($fieldFile, "*base 100`r`nCUST_ID 1 string`r`n")
        $startup = Join-Path $app 'start-billing.cmd'
        $startupText = @"
@echo off
set TUXDIR=$tux
set WSNADDR=//127.0.0.1:1
set FLDTBLDIR32=$fields
set FIELDTBLS32=cust.fml32
"@
        [System.IO.File]::WriteAllText($startup, $startupText)
        $out = Join-Path $root 'out'
        $result = Invoke-Discovery -AppPath (Join-Path $app 'billing.exe') -TuxDir $tux -OutDir $out -NoMachineScan -SkipNetwork
        Assert-True ($result.Text.Contains('Client mode: Workstation')) 'client mode'
        Assert-True ($result.Language -eq 'C/C++') "language was $($result.Language)"
        Assert-True ($result.Text.Contains('Buffers: FML32')) 'buffers'
        Assert-True ($result.Transactions -eq $true) 'transactions'
        Assert-True ($result.Conversations -eq $false) 'conversations'
        Assert-True ($result.FieldTableCount -ge 1) 'field table count'
        Assert-True ($result.WorkstationLibrary64 -eq 'found') '64-bit libwsc'
        Assert-True ($result.Text.Contains('Version: 12.2.2.0.0 (from install directory name)')) 'version from path'
        Assert-True ($result.Replay -eq 'ready for a 64-bit Workstation replay engine') "replay was $($result.Replay)"
        Assert-True ($result.Text.Contains('Application bitness: x64')) 'app bitness'
        Assert-True (Test-Path -LiteralPath $result.TextPath) 'report file'

        $emptyOut = Join-Path $root 'empty'
        $empty = Invoke-Discovery -OutDir $emptyOut -NoMachineScan -SkipNetwork -TuxDir (Join-Path $root 'missing-tuxedo')
        Assert-True ($empty.Text.Contains('Tuxedo installs found: 0')) 'empty install count'
        Assert-True ($empty.Text.Contains('Client mode: not determined')) 'empty client mode'

        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host 'Self-test passed.'
        return 0
    } catch {
        Write-Host ("Self-test failed: " + $_.Exception.Message)
        Write-Host $_.ScriptStackTrace
        return 1
    }
}

if ($SelfTest) {
    exit (Invoke-SelfTest)
}

if (-not $OutDir) {
    $OutDir = Join-Path (Get-Location) 'tuxload-discovery-output'
}

$null = Invoke-Discovery -AppPath $AppPath -TuxDir $TuxDir -StartupScript $StartupScript -SearchRoot $SearchRoot -OutDir $OutDir -NoMachineScan:$NoMachineScan -SkipNetwork:$SkipNetwork
