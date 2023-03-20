function Dump-Text {

    # This function takes binary path as parameter
    # Afterwards we will check for some invalid inputs
    # Finally dump the binary's disassembly with objdump
    # Parse hex values from the output into \x format for easy copy paste

	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $Binary
	)
    if(!$Binary){
        Write-Error("Provide path to the binary!")
        return
    }

    if((Test-Path $Binary -PathType Leaf ) -eq $false){
        Write-Error("Desired binary path doesn't exist!")
        return
    } 

    $check_file = (objdump -x $Binary 2>&1)
    if($check_file -match "file format not recognized"){
        Write-Error("Desired path is in invalid format!")
        return
    }

    $separator = [string[]]@("`n")
    $objdump = ((objdump -d $Binary).Split($separator,[System.StringSplitOptions]::RemoveEmptyEntries))
    $objdump_array = $objdump[3..$objdump.length]

    $output = ""
    foreach($i in $objdump_array){
        $opcodes = $i.Split("`t")[1].Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
        foreach($opcode in $opcodes){
            $output += "\x{0:X2}" -f $opcode
        }
    }
    $output
}