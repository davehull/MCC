<#
.SYNOPSIS
GetHammingDistance.ps1 returns the Hamming Distance in bits between two
strings supplied by the user.
.EXAMPLE
GetHammingDistance.ps1 -String1 punk -String2 junk
3
.EXAMPLE
GetHammingDistance.ps1 13190b1a37 0b091a102f
15
#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$String1,
    [Parameter(Mandatory=$True,Position=1)]
        [String]$String2
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
    [Parameter(Mandatory=$True,Position=0,ValueFromPipeLine=$True)]
        [String]$HDString1,
    [Parameter(Mandatory=$True,Position=1,ValueFromPipeLine=$True)]
        [String]$HDString2
)
    if ($HDString1.Length -ne $HDString2.Length) {
        Write-Error ("Input strings to GetHammingDistance function must be the same length. Quitting.")
        Exit
    }

    $Difference = 0
    for ($i = 0; $i -lt $HDString1.Length; $i++) {
        if ($HDString1[$i] -ne $HDString2[$i]) {
            $Difference++
        }
    }
    $Difference
}

if ($String1.Length -ne $String2.Length) {
    Write-Error ("Hamming Distance can't be calculated because strings are different lengths. Quitting.")
    Exit
}

$byteArray1 = GetBytes $String1
$byteArray2 = GetBytes $String2

$HammingDistance = 0
for ($i = 0; $i -lt $byteArray1.Count; $i++) {
    $bits1 = GetBits $byteArray1[$i]
    $bits2 = GetBits $byteArray2[$i]

    $HammingDistance += GetHammingDistance -HDString1 $bits1 -HDString2 $bits2
}
$HammingDistance