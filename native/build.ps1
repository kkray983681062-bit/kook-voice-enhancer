param(
    [string]$Toolchain = $env:LLVM_MINGW_BIN
)
$ErrorActionPreference = 'Stop'
if (!$Toolchain) {
    $installedClang = Get-Command 'x86_64-w64-mingw32-clang.exe' -ErrorAction SilentlyContinue
    if ($installedClang) { $Toolchain = Split-Path -Parent $installedClang.Source }
    else { throw 'Pass -Toolchain with the LLVM-MinGW bin directory, or set LLVM_MINGW_BIN.' }
}
$clang = Join-Path $Toolchain 'x86_64-w64-mingw32-clang.exe'
$windres = Join-Path $Toolchain 'x86_64-w64-mingw32-windres.exe'
if (!(Test-Path -LiteralPath $clang)) { throw 'Pass -Toolchain with the LLVM-MinGW bin directory.' }
Push-Location $PSScriptRoot
try {
    New-Item -ItemType Directory -Path build -Force | Out-Null
    $flags = @('-std=c11','-Wall','-Wextra','-Werror','-Os','-s')
    $hook = @('vendor/minhook/src/hook.c','vendor/minhook/src/buffer.c','vendor/minhook/src/trampoline.c','vendor/minhook/src/hde/hde64.c')
    & $clang @flags -shared -D_WIN32_WINNT=0x0601 agent.c features.c @hook -o build/kook-native-agent.dll
    if ($LASTEXITCODE) { throw 'Agent compilation failed.' }
    & $windres app.rc -O coff -o build/app-resource.o
    if ($LASTEXITCODE) { throw 'Resource compilation failed.' }
    & $clang @flags -municode -mwindows ui.c host.c locator.c chart.c build/app-resource.o -lgdi32 -luser32 -lcomdlg32 -ladvapi32 -lshell32 -lole32 -luuid -o build/KOOK-Voice-Enhancer.exe
    if ($LASTEXITCODE) { throw 'GUI compilation failed.' }
    & $clang @flags live_test.c host.c build/app-resource.o -o build/native-live-test.exe
    if ($LASTEXITCODE) { throw 'Live probe compilation failed.' }
    & $clang @flags -municode probe.c features.c vendor/minhook/src/hde/hde64.c -o build/feature-probe.exe
    if ($LASTEXITCODE) { throw 'Feature probe compilation failed.' }
    & $clang @flags -municode component_test.c chart.c locator.c -ladvapi32 -lshell32 -lole32 -luuid -o build/component-test.exe
    if ($LASTEXITCODE) { throw 'Component probe compilation failed.' }
    Get-Item build/KOOK-Voice-Enhancer.exe | Select-Object Name,Length
} finally { Pop-Location }
