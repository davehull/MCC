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
    [Parameter(Mandatory=$True,Position=0)]
        [byte[]]$ByteArray1,
    [Parameter(Mandatory=$True,Position=1)]
        [byte[]]$ByteArray2,
    [Parameter(Mandatory=$True,Position=2)]
        [hashtable]$BytePairDist
)
    if ($ByteArray1.Count -ne $ByteArray2.Count) {
        Write-Error ("Hamming Distance can't be calculated because byte arrays are different lengths, {0} and {1}." -f $ByteArray1.Count, $ByteArray2.Count)
        return $False
    } else {
        $Total = 0
        for ($i = 0; $i -lt $ByteArray1.Count; $i++) {
            $bitCount = 0
            # $pair and $rpair are equivalent (10:15 -eq 15:10)
            $pair  = $(($ByteArray1[$i],$ByteArray2[$i]) -join ":")
            $rpair = $(($ByteArray2[$i],$ByteArray1[$i]) -join ":")
            if ($pair -eq $rpair) { 
                # Write-Verbose ("pair is {0}, Hamming Distance is 0" -f $pair)
                # Hamming Distance between identical bytes is 0
                continue
            } elseif ($BytePairDist.Contains($pair) -or $BytePairDist.Contains($rpair)) {
                $bitCount += $BytePairDist[$pair]
                # Write-Verbose ("pair is {0}, Hamming Distance is {1}" -f $pair, $bitCount)
            } else {
                $bits = (GetBits ($ByteArray1[$i] -bxor $ByteArray2[$i]))

                for ($j = 0; $j -lt $bits.Length; $j++) {
                    if ($bits[$j] -eq '1') {
                        $bitCount++
                    }
                }
                # Write-Verbose ("pair is {0}, Hamming Distance is {1}" -f $pair, $bitCount)
                $BytePairDist.Add($pair,$bitCount)
                $BytePairDist.Add($rpair,$bitCount)
            }
            $Total += $bitCount
        }
        $Total
    }
}


<#
function GetHammingDistance {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [byte[]]$ByteArray1,
    [Parameter(Mandatory=$True,Position=1)]
        [byte[]]$ByteAttay2
)
    if ($ByteArray1.Count -ne $ByteAttay2.Count) {
        Write-Error ("Hamming Distance can't be calculated because byte arrays are different lengths. Quitting.")
        Exit
    } else {
        $count = 0
        for ($i = 0; $i -lt $ByteArray1.Count; $i++) {
            $bits = (GetBits ($ByteArray1[$i] -bxor $ByteAttay2[$i]))

            for ($j = 0; $j -lt $bits.Length; $j++) {
                if ($bits[$j] -eq '1') {
                    $count++
                }
            }
        }
        $count        
    }
}
#>

$byteArray1 = GetBytes $String1
$byteArray2 = GetBytes $String2
$BytePairDist = @{}

GetHammingDistance $byteArray1 $byteArray2 $BytePairDist