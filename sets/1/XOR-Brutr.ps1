<#
.SYNOPSIS
XOR-Brutr.ps1 brute force decrypts XOR encrypted data. The data may be
read from the command line via the -String argument or from a file via
the -File argument.
.EXAMPLE
XOR-Brutr.ps1 -String 36190f580f1b090107014e42140c1e5509550752
Key             : fun!
EncryptedText   : 36190f580f1b090107014e42140c1e5509550752
DecryptedText   : Playing at crypto is
Entropy         : 3.68418371977919
LetterFreqScore : 305
BiGramScore     : 362
TriGramScore    : 144
TotalScore      : 838.143054637349
.EXAMPLE
XOR-Brutr.ps1 -File 6.txt
Key             :
EntryptedText   :
DecryptedText   :
Entropy         :
LetterFreqScore :
BiGramScore     :
TriGramScore    :
TotalScore      :
#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False,Position=2)]
        [int]$MaxKeySize=20,
    [Parameter(ParameterSetName="String",Mandatory=$False,Position=0)]
        [String]$String,
    [Parameter(ParameterSetName="File",Mandatory=$False,Position=1)]
        [String]$File
)

function GetBytes {
Param(
    [Parameter(Mandatory=$True,Position=0,ValueFromPipeLine=$True)]
        [String]$string
)
    [System.Text.Encoding]::Default.GetBytes($string)
}

function GetBits {
Param(
    [Parameter(Mandatory=$True,Position=0,ValueFromPipeLine=$True)]
        [byte]$byte
)
    [System.Convert]::ToString($byte,2).PadLeft(8,'0') 
}

function GetHammingDistance {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [byte[]]$ByteArray1,
    [Parameter(Mandatory=$True,Position=1)]
        [byte[]]$ByteArray2
)
    if ($ByteArray1.Count -ne $ByteArray2.Count) {
        Write-Error ("Hamming Distance can't be calculated because byte arrays are different lengths. Quitting.")
        Exit
    } else {
        $count = 0
        for ($i = 0; $i -lt $ByteArray1.Count; $i++) {
            $bits = (GetBits ($ByteArray1[$i] -bxor $ByteArray2[$i]))

            for ($j = 0; $j -lt $bits.Length; $j++) {
                if ($bits[$j] -eq '1') {
                    $count++
                }
            }
        }
        $count        
    }
}

function GetCountBytes {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [byte[]]$ByteArray,
    [Parameter(Mandatory=$True,Position=1)]
        [int]$numBytes,
    [Parameter(Mandatory=$True,Position=2)]
        [int]$startPos
)
    [byte[]]$RetByteArray = @()

    if ($startPos + $numBytes -gt $ByteArray.Length) {
        Write-Error ("Reading {0} bytes starting at {1} exceeds the length of `$ByteArray." -f $numBytes, $startPos)
        Exit
    }

    for ($i = $startPos; $i -lt ($startPos + $numBytes); $i++) {
        $RetByteArray += $ByteArray[$i]
    }
    $RetByteArray
}


[byte[]]$CipherByteArray,[byte[]]$FirstKeySz,[byte[]]$SecondKeySz = @()

switch ($PSCmdlet.ParameterSetName) {
    "String" {
        $CipherByteArray = GetBytes $String
    }
    "File" {
        if ($Path = Resolve-Path $File) {
            $File = ls $Path
            $CipherByteArray = [System.IO.File]::ReadAllBytes($File)
        }
    }
    Default {
        Write-Host ("Missing argument.")
    }
}



$obj = "" | Select-Object KeySize,FirstBytes,SecondBytes,HammingDistance,Normalized

[int]$start = 0

for ($i = 1; $i -le $MaxKeySize; $i++) {

    $count = $i

    $obj.KeySize = $i

    $FirstKeySz  = GetCountBytes $CipherByteArray $count $start
    $obj.FirstBytes = $FirstKeySz -join ":"
    
    $start = [int]($count + $start)

    $SecondKeySz = GetCountBytes $CipherByteArray $count $start
    $obj.SecondBytes = $SecondKeySz -join ":"

    $HD = GetHammingDistance $FirstKeySz $SecondKeySz
    $obj.HammingDistance = $HD

    $Normalized = $HD / $i
    $obj.Normalized = $Normalized

    $obj | Select-Object KeySize,FirstBytes,SecondBytes,HammingDistance,Normalized
    $start = 0
}