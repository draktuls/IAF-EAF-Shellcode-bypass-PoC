param(
    [Parameter(Mandatory=$True, ValueFromPipeline=$false)]
    [System.String]
    $Build
)

function Remove-CompilationArtifacts{
	Write-Host "Removing compilation artifacts" -ForegroundColor cyan
	rm *.obj
	rm *.o
	if( Test-Path -Path "./main_defines_shellcode.h"){
		rm ./main_defines_shellcode.h
	}
}

. ./Dump-Bin.ps1

$out_name = "runner"
$shellcode_out_name = "shellcode"

if($build -contains "x64"){

	Write-Host "Chosen x64 build" -ForegroundColor cyan
	$largs = "/DEBUG /MACHINE:X64"
	Invoke-Expression -Command "./build_shell.ps1 -Build Shellcode -Name $shellcode_out_name -Src src"
	if($LastExitCode -ne 0){
		Write-Host "Compiling the shellcode went wrong, exiting!" -ForegroundColor red 
		Remove-CompilationArtifacts
		Exit($LastExitCode)
	}

	$name = "$shellcode_out_name" + ".exe"
	$shellcode_dump = Dump-Text -Binary src/$name
	$defines_content = Get-Content "main_defines.h"
	$define_args = "{""" + $shellcode_dump + """}"

	$new_define = $defines_content -replace "replaceme", "$define_args"
	$new_define > ./main_defines_shellcode.h
	$out = $out_name + ".exe"

}elseif($build -contains "x86"){

	Write-Host "Chosen x86 build" -ForegroundColor cyan
	$largs = "/DEBUG /MACHINE:X86"
	Invoke-Expression -Command "./build_shell.ps1 -Build Shellcode32 -Name $shellcode_out_name -Src src"
	if($LastExitCode -ne 0){
		Write-Host "Compiling the shellcode went wrong, exiting!" -ForegroundColor red 
		Remove-CompilationArtifacts
		Exit($LastExitCode)
	}
	$name = "$shellcode_out_name" + "32.exe"
	$shellcode_dump = Dump-Text -Binary src/$name
	$defines_content = Get-Content "main_defines.h"
	$define_args = "{""" + $shellcode_dump + """}"

	$new_define = $defines_content -replace "replaceme", "$define_args"
	$new_define > ./main_defines_shellcode.h
	$out = $out_name + "32.exe"

}else{
	Write-Host "Choose one of the following: x86, x64" -ForegroundColor red
	exit
}

Write-Host "Compiling main code" -ForegroundColor cyan

# Build main with shellcode define
Invoke-Expression -Command "cl.exe $args /Zp8 /c /nologo /O1 /GR- /EHa /GS- /W0 /MT /FI main_defines_shellcode.h /Tc main.c"
if($LastExitCode -ne 0){
	Write-Host "Compiling main went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	Exit($LastExitCode)
}

if( Test-Path -Path "./bin"){
	cd bin
}else{
	mkdir ./bin
	cd bin
}
# Link them
Invoke-Expression -Command "link.exe /OUT:$out /OPT:NOREF /OPT:NOICF /nologo $largs ../main.obj"
if($LastExitCode -ne 0){
	Write-Host "Linking went wrong, exiting!" -ForegroundColor red 
	Remove-CompilationArtifacts
	cd ..
	Exit($LastExitCode)
}
cd ..

Remove-CompilationArtifacts
if( Test-Path -Path "./src/$name"){
	rm ./src/$name
}