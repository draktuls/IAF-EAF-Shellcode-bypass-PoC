param(
    [Parameter(Mandatory=$True, ValueFromPipeline=$false)]
    [System.String]
    $Build,
	[Parameter(Mandatory=$False, ValueFromPipeline=$false)]
	[System.String]
    $Name,
	[Parameter(Mandatory=$False, ValueFromPipeline=$false)]
	[System.String]
    $Src
)

if($Name -eq $null){
	$Name = "shellcode"
}

if($Src -eq $null){
	$Src = ""
}

$Src
$Cur = pwd

if($build -contains "Debug"){
	Write-Host "Chosen Debug x64 build" -ForegroundColor cyan
	$largs = "/DEBUG /MACHINE:X64"
	$assembler = "ml64.exe"
	$args = "/DDEBUG_D"
	$out = $Name + ".exe"
}elseif($build -contains "Debug32"){
	Write-Host "Chosen Debug x86 build" -ForegroundColor cyan
	$largs = "/DEBUG /MACHINE:X86"
	$assembler = "ml.exe"
	$args = "/DDEBUG_D"
	$out = $Name + "32.exe"
}elseif($build -contains "Shellcode"){
    Write-Host "Chosen Shellcode x64 build" -ForegroundColor cyan
	$largs = "/entry:AlignRSP /MACHINE:X64"
	$assembler = "ml64.exe"
	$args = ""
	$out = $Name + ".exe"
}elseif($build -contains "Shellcode32"){
	Write-Host "Chosen Shellcode x86 build" -ForegroundColor cyan
	$largs = "/entry:main /MACHINE:X86"
	$assembler = "ml.exe"
	$args = ""
	$out = $Name + "32.exe"
}else{
	Write-Host "Choose one of the following: Debug,Debug32,Shellcode,Shellcode32" -ForegroundColor red
	exit
}

. ./Dump-Bin.ps1

cd $Src

function Remove-CompilationArtifacts{
	Write-Host "Removing compilation artifacts" -ForegroundColor cyan
	rm *.obj
	rm *.o
}

# Build main obj file without optimizations - it causes the strings to be allocated outside of .text
Invoke-Expression -Command "cl.exe $args /Zp8 /c /nologo /Od /GR- /EHa /GS- /W0 /MT /Tc shellcode.c"
if($LastExitCode -ne 0){
	Write-Host "Compiling shellcode went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd $Cur
	Exit($LastExitCode)
}

# Build helper obj file
Invoke-Expression -Command "cl.exe $args /Zp8 /c /nologo /O1 /GR- /EHa /GS- /W0 /MT /Tc helper.c"
if($LastExitCode -ne 0){
	Write-Host "Compiling helper went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd $Cur
	Exit($LastExitCode)
}

# Build gadget obj file
Invoke-Expression -Command "cl.exe $args /Zp8 /c /nologo /O1 /GR- /EHa /GS- /W0 /MT /Tc gadget.c"
if($LastExitCode -ne 0){
	Write-Host "Compiling helper went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd $Cur
	Exit($LastExitCode)
}

# Build finder obj file
Invoke-Expression -Command "cl.exe $args /Zp8 /c /nologo /O1 /GR- /EHa /GS- /W0 /MT /Tc finder.c"
if($LastExitCode -ne 0){
	Write-Host "Compiling finder went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd $Cur
	Exit($LastExitCode)
}

# Build hunter obj file
Invoke-Expression -Command "cl.exe $args /Zp8 /c /nologo /O1 /GR- /EHa /GS- /W0 /MT /Tc hunter.c"
if($LastExitCode -ne 0){
	Write-Host "Compiling hunter went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd $Cur
	Exit($LastExitCode)
}

# Assemble align and rop
Invoke-Expression -Command "$assembler /c .\rop.asm .\align.asm"
if($LastExitCode -ne 0){
	Write-Host "Assembling went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd $Cur
	Exit($LastExitCode)
}
# Link them
Invoke-Expression -Command "link.exe /OUT:$out /OPT:NOREF /OPT:NOICF /nologo align.obj shellcode.obj rop.obj gadget.obj helper.obj finder.obj hunter.obj $largs"
if($LastExitCode -ne 0){
	Write-Host "Linking went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd $Cur
	Exit($LastExitCode)
}

if($build -match "Debug"){
    Write-Host "Shellcode has been compiled in Debug!" -ForegroundColor cyan 
}else{
    Write-Host "Shellcode has been compiled, printing..." -ForegroundColor cyan 
    Invoke-Expression -Command "Dump-Text -Binary ""$out"""
}

Remove-CompilationArtifacts
cd $Cur