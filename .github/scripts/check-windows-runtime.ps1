# Verifies that a Windows build directory runs on a clean machine without the
# Visual C++ Redistributable installed.
#
# For every .exe/.dll under -Dir it reads the import table with dumpbin and
# fails when:
#   - a VC++ runtime DLL (msvcp*/vcruntime*/concrt*/vccorlib*) is imported but
#     not shipped next to that binary (app-local deployment), or
#   - a debug CRT (*d.dll, ucrtbased.dll) is imported, or
#   - any other imported DLL is neither shipped in the binary's directory nor
#     present in System32.
# Requires dumpbin on PATH (ilammy/msvc-dev-cmd).
param(
  [Parameter(Mandatory = $true)][string]$Dir
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command dumpbin -ErrorAction SilentlyContinue)) {
  throw "dumpbin not found on PATH; run ilammy/msvc-dev-cmd first"
}
$root = (Resolve-Path $Dir).Path
$system32 = Join-Path $env:SystemRoot "System32"
$vcRuntime = '^(msvcp\d+.*|vcruntime\d+.*|concrt\d+|vccorlib\d+)\.dll$'
$debugCrt = '^(msvcp\d+d.*|vcruntime\d+.*d|concrt\d+d|vccorlib\d+d|ucrtbased)\.dll$'

$binaries = Get-ChildItem -Path $root -Recurse -File -Include *.exe, *.dll
if (-not $binaries) { throw "no .exe/.dll found under $root" }

$errors = @()
foreach ($bin in $binaries) {
  # dumpbin lists normal imports, then (optionally) delay-load imports.
  # Delay-loaded DLLs are optional at startup (e.g. jni's jvm.dll), so only
  # the VC++ runtime rules apply to them.
  $deps = @()
  $section = ""
  foreach ($line in (& dumpbin /NOLOGO /DEPENDENTS $bin.FullName)) {
    $t = $line.ToString().Trim()
    if ($t -match '^Image has the following delay load dependencies') { $section = "delay"; continue }
    if ($t -match '^Image has the following dependencies') { $section = "normal"; continue }
    if ($t -eq "Summary") { break }
    if ($section -and $t -match '^[^\s]+\.dll$') {
      $deps += [pscustomobject]@{ Name = $t; Delay = ($section -eq "delay") }
    }
  }
  $rel = $bin.FullName.Substring($root.Length).TrimStart('\', '/')
  foreach ($d in $deps) {
    $dep = $d.Name
    $local = Test-Path (Join-Path $bin.DirectoryName $dep)
    if ($dep -match $debugCrt) {
      $errors += "${rel}: imports debug CRT $dep"
    } elseif ($dep -match $vcRuntime) {
      if (-not $local) { $errors += "${rel}: imports $dep but it is not shipped next to it" }
    } elseif ($d.Delay -or $dep -match '^(api|ext)-ms-' -or $dep -ieq 'jvm.dll') {
      # Delay-loaded imports are optional; API sets are resolved by the loader;
      # jvm.dll (package:jni) is only loaded when a JVM is spawned.
    } elseif (-not $local -and -not (Test-Path (Join-Path $system32 $dep))) {
      $errors += "${rel}: imports $dep which is neither shipped nor in System32"
    }
  }
}

Write-Host "VC++ runtime DLLs shipped:"
Get-ChildItem -Path $root -Recurse -File |
  Where-Object { $_.Name -match $vcRuntime } |
  ForEach-Object { Write-Host "  $($_.FullName.Substring($root.Length).TrimStart('\', '/'))" }

if ($errors) {
  $errors | ForEach-Object { Write-Host "::error::$_" }
  throw "$($errors.Count) runtime dependency problem(s) in $root"
}
Write-Host "✓ $($binaries.Count) binaries checked, all runtime dependencies satisfied"
