$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$desktopPath = [Environment]::GetFolderPath('DesktopDirectory')
if (!$desktopPath -or !(Test-Path -LiteralPath $desktopPath -PathType Container)) { throw 'Windows desktop folder is unavailable.' }
$probeLogPath = Join-Path $desktopPath ('KOOK-Probe-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6) + '.log')
$writer = New-Object IO.StreamWriter($probeLogPath, $false, (New-Object Text.UTF8Encoding($true)))
function SafeText([object]$value) {
    $text = [string]$value
    if ($env:USERPROFILE) { $text = $text.Replace($env:USERPROFILE, '%USERPROFILE%') }
    return $text
}
function Log([object]$value) { $writer.WriteLine((SafeText $value)); $writer.Flush() }
$nativeCode = @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class KProbe {
  [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool IsWow64Process(IntPtr p,out bool wow);
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr p,IntPtr address,byte[] data,UIntPtr size,out UIntPtr done);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool QueryFullProcessImageName(IntPtr p,uint flags,StringBuilder text,ref uint size);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,out int value,int length,out int required);
  public static string Elevated(IntPtr p) {
    IntPtr token; if(!OpenProcessToken(p,8,out token))return "unknown:"+Marshal.GetLastWin32Error();
    try {int value,required;return GetTokenInformation(token,20,out value,4,out required)?(value!=0?"true":"false"):"unknown:"+Marshal.GetLastWin32Error();}finally{CloseHandle(token);}
  }
  public class PEInfo {public string Machine;public int ExportCount;public bool StartAudio,SetBitrate;public string[] AudioExports;public string Error;}
  static uint U32(byte[] b,int p){if(p<0||p>b.Length-4)throw new Exception("PE field outside file");return BitConverter.ToUInt32(b,p);}
  static ushort U16(byte[] b,int p){if(p<0||p>b.Length-2)throw new Exception("PE field outside file");return BitConverter.ToUInt16(b,p);}
  public static PEInfo Inspect(string file) {
    PEInfo result=new PEInfo();result.AudioExports=new string[0];
    try {
      FileInfo fi=new FileInfo(file);if(fi.Length>134217728){result.Error="File exceeds 128MB read limit";return result;}
      byte[] b=File.ReadAllBytes(file);int pe=(int)U32(b,60);if(U16(b,0)!=0x5a4d||U32(b,pe)!=0x4550)throw new Exception("Not a PE file");
      ushort machine=U16(b,pe+4);result.Machine=machine==0x8664?"x64":machine==0x14c?"x86":machine==0xaa64?"ARM64":"0x"+machine.ToString("x");
      int sections=U16(b,pe+6),optional=pe+24,table=optional+U16(b,pe+20),magic=U16(b,optional);
      if(magic!=0x20b&&magic!=0x10b)throw new Exception("Unknown optional header");
      Func<uint,int> offset=delegate(uint rva){
        if(rva<U32(b,optional+60))return (int)rva;
        for(int i=0;i<sections;i++){int s=table+i*40;uint va=U32(b,s+12),raw=U32(b,s+16);if(rva>=va&&rva-va<raw)return checked((int)(U32(b,s+20)+rva-va));}
        throw new Exception("RVA outside backed sections");
      };
      int directory=optional+(magic==0x20b?112:96);uint exportRva=U32(b,directory);if(exportRva==0)return result;
      int ex=offset(exportRva),count=checked((int)U32(b,ex+24));if(count>100000)throw new Exception("Export count too large");result.ExportCount=count;
      int names=offset(U32(b,ex+32));List<string> interesting=new List<string>();
      for(int i=0;i<count;i++) {
        int start=offset(U32(b,names+i*4)),end=start;while(end<b.Length&&end-start<512&&b[end]!=0)end++;
        if(end>=b.Length||end-start>=512)continue;string name=Encoding.ASCII.GetString(b,start,end-start);
        if(name=="KL_StartPushAudioStream")result.StartAudio=true;if(name=="KL_SetPushAudioBitratebps")result.SetBitrate=true;
        string lower=name.ToLowerInvariant();
        if((name.StartsWith("KL_")&&(lower.Contains("audio")||lower.Contains("version")||lower.Contains("init")))||lower.StartsWith("opus_"))if(interesting.Count<80)interesting.Add(name);
      }
      result.AudioExports=interesting.ToArray();
    }catch(Exception e){result.Error=e.GetType().Name+": "+e.Message;}
    return result;
  }
}
'@
try {
    Write-Host 'KOOK read-only diagnostic. Keep KOOK open and join a voice channel.'
    Write-Host 'Collecting process, module and version information. No audio or chat is collected.'
    Log 'KOOK READ-ONLY DIAGNOSTIC v1'
    Log ('UTC: ' + [DateTime]::UtcNow.ToString('o'))
    Log ('OS: ' + [Environment]::OSVersion.VersionString)
    Log ('OS64: ' + [Environment]::Is64BitOperatingSystem + '; Probe64: ' + [Environment]::Is64BitProcess)
    Log ('PowerShell: ' + $PSVersionTable.PSVersion.ToString())
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Log ('ProbeElevated: ' + $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    try { Get-CimInstance Win32_Processor -OperationTimeoutSec 5 | ForEach-Object { Log ('CPU: ' + $_.Name + '; AddressWidth: ' + $_.AddressWidth) } } catch { Log ('CPUQuery: ' + $_.Exception.Message) }
    Add-Type -TypeDefinition $nativeCode -Language CSharp
    $installRoots = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $filesSeen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $candidatePattern = '(?i)kaihei|capture|audio|voice|rtc|opus|agora|zego|volc|byted|media|engine|ffmpeg'
    function AddRoot([string]$path) {
        if (!$path) { return }
        $dir = Split-Path -Parent $path
        if ($dir -and $dir.Length -gt 4 -and (Test-Path -LiteralPath $dir -PathType Container)) {
            [void]$installRoots.Add($dir)
            if ((Split-Path -Leaf $dir) -like 'app-*') { [void]$installRoots.Add((Split-Path -Parent $dir)) }
        }
    }
    function InspectFile([string]$path,[string]$reason) {
        if (!$filesSeen.Add($path)) { return }
        Log ('FILE [' + $reason + ']: ' + $path)
        try {
            $item = Get-Item -LiteralPath $path
            Log ('  Bytes=' + $item.Length + ' Version=' + $item.VersionInfo.FileVersion + ' Product=' + $item.VersionInfo.ProductName)
            $info = [KProbe]::Inspect($path)
            Log ('  PE=' + $info.Machine + ' Exports=' + $info.ExportCount + ' KL_StartPushAudioStream=' + $info.StartAudio + ' KL_SetPushAudioBitratebps=' + $info.SetBitrate)
            if ($info.Error) { Log ('  PEError=' + $info.Error) }
            if ($info.AudioExports.Count) { Log ('  AudioExports=' + ($info.AudioExports -join ', ')) }
            Log ('  SHA256=' + (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)
        } catch { Log ('  FileError=' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
    }
    try {
        $selected = (Get-ItemProperty -LiteralPath 'HKCU:\Software\Kekemi\KookVoiceEnhancer' -Name ExecutablePath -ErrorAction Stop).ExecutablePath
        Log ('EnhancerSelectedPath: ' + $selected); AddRoot $selected
        if (Test-Path -LiteralPath $selected -PathType Leaf) { InspectFile $selected 'selected-launcher' }
    } catch { Log 'EnhancerSelectedPath: not saved or unavailable' }
    $observedProcesses = New-Object 'Collections.Generic.HashSet[int]'
    $matchCount = 0
    foreach ($sample in 1..3) {
        if ($sample -gt 1) { Start-Sleep -Seconds 3 }
        Log ('--- PROCESS SAMPLE ' + $sample + ' UTC=' + [DateTime]::UtcNow.ToString('o') + ' ---')
        $processes = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -ieq 'KOOK' -or $_.ProcessName -ieq 'KaiHeiLa' })
        Log ('KOOKProcessCount=' + $processes.Count)
        foreach ($proc in $processes) {
            $processId = [uint32]$proc.Id
            Log ('PROCESS PID=' + $processId + ' Name=' + $proc.ProcessName)
            $query = [KProbe]::OpenProcess(0x1000,$false,$processId)
            if ($query -eq [IntPtr]::Zero) { Log ('  QueryAccessError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); continue }
            try {
                $sb = New-Object Text.StringBuilder 2048; [uint32]$pathSize=2048
                if ([KProbe]::QueryFullProcessImageName($query,0,$sb,[ref]$pathSize)) {
                    $exePath=$sb.ToString(); Log ('  Executable=' + $exePath); AddRoot $exePath
                    if ($observedProcesses.Add([int]$processId)) { InspectFile $exePath 'running-executable' }
                } else { Log ('  PathError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
                [bool]$wow=$false
                if ([KProbe]::IsWow64Process($query,[ref]$wow)) { Log ('  ProcessArchitecture=' + $(if (![Environment]::Is64BitOperatingSystem -or $wow) {'x86'} else {'x64'})) }
                Log ('  ProcessElevated=' + [KProbe]::Elevated($query))
            } finally { [void][KProbe]::CloseHandle($query) }
            $readHandle=[KProbe]::OpenProcess(0x1010,$false,$processId)
            if ($readHandle -eq [IntPtr]::Zero) { Log ('  MemoryReadAccessError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
            else { Log '  MemoryReadAccess=OK'; [void][KProbe]::CloseHandle($readHandle) }
            try {
                $proc.Refresh(); $modules=@($proc.Modules)
                Log ('  ModuleCount=' + $modules.Count)
                Log ('  ModuleNames=' + (($modules | ForEach-Object { $_.ModuleName }) -join ', '))
                foreach ($module in $modules) {
                    $path=$module.FileName
                    if ($module.ModuleName -match $candidatePattern -or $module.ModuleName -like '*.node') {
                        Log ('  AUDIO_CANDIDATE_LOADED=' + $path)
                        InspectFile $path 'loaded-audio-candidate'
                    }
                    if ($path -and $exePath -and $path.StartsWith((Split-Path -Parent $exePath),[StringComparison]::OrdinalIgnoreCase)) {
                        $pe=[KProbe]::Inspect($path)
                        if ($pe.StartAudio -or $pe.SetBitrate) {
                            Log ('  ENGINE_EXPORT_MATCH=' + $path + ' Start=' + $pe.StartAudio + ' Set=' + $pe.SetBitrate)
                            if ($pe.StartAudio -and $pe.SetBitrate) { $matchCount++ }
                            InspectFile $path 'engine-export-match'
                        }
                    }
                }
            } catch { Log ('  ModuleReadError=' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message); if ($_.Exception.InnerException) { Log ('  InnerError=' + $_.Exception.InnerException.Message) } }
        }
    }
    Log '--- AUDIO MODULES ON DISK (bounded install-folder search) ---'
    $queue=New-Object 'Collections.Generic.Queue[object]'
    foreach ($root in $installRoots) { Log ('InstallRoot=' + $root); $queue.Enqueue(@($root,0)) }
    $dirsSeen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $watch=[Diagnostics.Stopwatch]::StartNew();$fileCount=0;$visited=0
    while ($queue.Count -and $watch.Elapsed.TotalSeconds -lt 12 -and $visited -lt 2500 -and $fileCount -lt 80) {
        $entry=$queue.Dequeue();$dir=[string]$entry[0];$depth=[int]$entry[1]
        if (!$dirsSeen.Add($dir)) { continue };$visited++
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -ErrorAction SilentlyContinue)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($item.PSIsContainer) { if ($depth -lt 8) { $queue.Enqueue(@($item.FullName,$depth+1)) } }
            elseif ($item.Extension -match '^\.(dll|node)$' -and $item.Name -match $candidatePattern) { InspectFile $item.FullName 'on-disk-audio-candidate';$fileCount++ }
            if ($fileCount -ge 80 -or $watch.Elapsed.TotalSeconds -ge 12) { break }
        }
    }
    Log ('DiskSearchDirectories=' + $visited + ' CandidateFiles=' + $fileCount + ' RemainingQueue=' + $queue.Count)
    Log ('EngineExportMatchesAcrossSamples=' + $matchCount)
    Log 'Read-only probe: no injection, no memory writes, no audio capture, no client log or chat content, no network upload.'
    Log 'END'
    Write-Host ('Completed. Desktop log: ' + $probeLogPath)
} catch {
    Log ('FATAL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message)
    Log ('LOCATION: line ' + $_.InvocationInfo.ScriptLineNumber)
    Write-Host ('Probe error recorded in: ' + $probeLogPath)
} finally { $writer.Dispose() }
