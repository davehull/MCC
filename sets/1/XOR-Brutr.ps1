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
    [Parameter(Mandatory=$False,Position=3)]
        [int]$MaxSamples=$False,
    [Parameter(ParameterSetName="String",Mandatory=$False,Position=0)]
        [String]$String,
    [Parameter(ParameterSetName="File",Mandatory=$False,Position=1)]
        [String]$File,
    [Parameter(Mandatory=$False,Position=4)]
        [ValidateSet("base16","base64")]
        [String]$Encoding="base16"
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
        Write-Error ("Hamming Distance can't be calculated because byte arrays are different lengths, {0} and {1}." -f $ByteArray1.Count, $ByteArray2.Count)
        return $False
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
# Takes a byte array, a number of bytes and a starting index in the
# array, returns the number of bytes requested as an array of bytes
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

function ConvertBase16-ToByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$base16String
)

    $byteString = $(if ($base16String.Length -eq 1) {
        ([System.Convert]::ToByte( $base16String, 16))
    } elseif ($base16String.Length % 2 -eq 0) {
        $base16String -split "([a-fA-F0-9]{2})" | ForEach-Object {
            if ($_) {
                $ByteInbase16 = [String]::Format("{0:D}", $_)
                $Paddedbase16 = $ByteInbase16.PadLeft(2,"0")
                [System.Convert]::ToByte( $Paddedbase16, 16 )
            }
        }
    })

    $byteString
}

function ConvertBase64-ToByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$base64String
)
    # Takes a Base64 encoded string and returns a byte array
    [System.Convert]::FromBase64String($base64String)
}

function GetGreatestCommonDenominator {
Param (
    [Parameter(Mandatory=$True,Position=0)]
        [int]$val1,
    [Parameter(Mandatory=$True,Position=1)]
        [int]$val2
)
    # We shouldn't have any negative values for Hamming
    # Distances, but this is a generalized algorithm
    $val1,$val2 = ($val1,$val2 | ForEach-Object {
        [math]::Abs($_)
    })

    if ($val2 -eq 0) {
        $val1
    } else {
        GetGreatestCommonDenominator -val1 $val2 -val2 ($val1 % $val2)
    }        
}

[byte[]]$CipherByteArray,[byte[]]$sample = @()

switch ($PSCmdlet.ParameterSetName) {
    "String" {

        switch ($Encoding) {
            "base16" {
                $CipherByteArray = ConvertBase16-ToByte -base16String $String
            }
            "base64" {
               $CipherByteArray = ConvertBase64-ToByte -base64String $String
            }
        }
    }
    "File" {
        if ($Path = Resolve-Path $File) {
            $File = ls $Path
            $FileByteString = ([System.IO.File]::ReadAllText($File)) -join ""

            switch ($Encoding) {
                "base16" {
                    $CipherByteArray = ConvertBase16-ToByte -base16String $FileByteString
                }
                "base64" {
                    $CipherByteArray = ConvertBase64-ToByte -base64String $FileByteString
                }
            }
        }
    }
    Default {
        Write-Host ("Missing argument.")
    }
}

if (-not($MaxSamples)) {
    $NoUserMaxSamples = $True
}

$CipherByteCount = $CipherByteArray.Count
$MaxAllowableSamples = [int]($CipherByteCount / 2) - 1
$MaxAllowableKeySize = [int]($CipherByteCount)

if ($MaxSamples -gt $MaxAllowableSamples) {
    Write-Verbose ("-MaxSamples of {0} was too large. Setting to {1}, ((CipherByteArray.Count / min(keysize)) - 1." -f $MaxSamples, $MaxAllowableSamples)
    $MaxSamples = $MaxAllowableSamples
}

if ($MaxKeySize -gt $MaxAllowableKeySize) {
    Write-Verbose ("-MaxKeySize of {0} exceeds the length of the ciphertext. Setting to {1}, [int](CipherByteArray.Count)." -f $MaxKeySize, $CipherByteArray.Count)
    $MaxKeySize = $MaxAllowableKeySize
}

$objs = @()

for ($KeySize = 2; $KeySize -le $MaxKeySize; $KeySize++) {
    $HDs = @()

    # Write-Verbose ("Keysize is {0}." -f $KeySize)

    if ($NoUserMaxSamples) {
        $MaxSamples = (($CipherByteArray.Count / $KeySize) - 1)
    }

    for ($i = 0; $i -lt $MaxSamples; $i++) {
        $Start = $KeySize * $i
        $End   = $KeySize * ($i + 1)
        # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
        if ($End -gt $CipherByteCount) {
            # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
            continue
        }
        $ByteArray1 = $CipherByteArray[$Start..$End]
        $Start = $End
        $End   = $KeySize * ($i + 2)
        # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
        if ($End -gt $CipherByteCount) {
            # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
            continue
        }
        $ByteArray2 = $CipherByteArray[$Start..$End]
        if ($ByteArray1.Count -eq $ByteArray2.Count) {
            $HDs += ((GetHammingDistance $ByteArray1 $ByteArray2) / $KeySize)
        }
    }
    if ($HDs) {
        $AvgDist = $HDs | Measure-Object -Average | Select-Object -ExpandProperty Average
        $obj = "" | Select-Object KeySize,AvgDist
        $obj.KeySize = $KeySize
        $obj.AvgDist = $AvgDist
        $objs += $obj
        $NoUserMaxSamples = $True
    }
}
$i = 1
$objs | sort AvgDist | ForEach-Object {
    $obj = "" | Select-Object Rank,RankKeySizeRatio,KeySize,KeySizeAvgDistRatio,AvgDist,Total
    $obj.Rank = $i
    $obj.RankKeySizeRatio = $_.KeySize / $i
    $obj.KeySize = $_.KeySize
    $obj.KeySizeAvgDistRatio = $_.KeySize / $_.AvgDist
    $obj.AvgDist = $_.AvgDist
    $obj.Total = $obj.RankKeySizeRatio + $obj.Rank + $obj.KeySize # + ($obj.RankKeySizeRatio * $obj.KeySizeAvgDistRatio * $obj.AvgDist)
    $obj | Select-Object Rank,RankKeySizeRatio,KeySize,KeySizeAvgDistRatio,AvgDist,Total
    $i++
}