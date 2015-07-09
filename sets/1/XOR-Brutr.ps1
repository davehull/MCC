<#
.SYNOPSIS
XOR-Brutr.ps1 brute force decrypts XOR encrypted data. The data may be
read from the command line via the -String argument or from a file via
the -File argument.

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
        [String]$Encoding="base16",
    [Parameter(Mandatory=$False,Position=5)]
        [int]$top=5,
    [Parameter(Mandatory=$False,Position=6)]
        [float]$MaxNAvgHD=3.5,
    [Parameter(Mandatory=$False,Position=7)]
        [switch]$includeNonPrintable
)

function GetByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [Char]$key
)
    [System.Text.Encoding]::Default.GetBytes($key)
}

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
                [System.Convert]::ToByte($Paddedbase16, 16 )
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

function GetTransposedBlock {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [int]$KeySize,
    [Parameter(Mandatory=$True,Position=1)]
        [Array]$CipherByteArray,
    [Parameter(Mandatory=$True,Position=2)]
        [int]$KeyPosition
)
    # This function returns an array of every $KeySize byte beginning at $KeyPosition
    # If $KeySize is 4 and $KeyPosition is 0, it returns an array of 0, 4, 8, 12... bytes
    # If $KeySize is 29 and $KeyPosition is 1, it returns an array of 1, 30, 59... bytes
    
    # The byte array will be input to a separate single character XOR brute forcing 
    # function. If the $KeySize is right, the right byte value XOR'd against the array 
    # will produce output with a "letter frequency" score resembling English letter 
    # frequency. Whatever that byte value is, it is likely to be the right byte value for 
    # the given $KeyPosition

    $BlockArray = @()
    $index = $KeyPosition
    while($index -lt $CipherByteArray.Count) {
        $BlockArray += $CipherByteArray[$index]
        $index += $KeySize
    }
    $BlockArray
}

function Score-LetterFrequency {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$DecodedString
)
    $Score = 0
    $DecodedUpper = $DecodedString.ToUpper()

    # Score the string according to English letter frequency counts
    for($i = 0; $i -lt $DecodedUpper.Length; $i++) {
        switch -Regex ($DecodedUpper[$i]) {
            "[^-A-Z0-9!@#$~%^&*)(\[\]\.\\:;<>,.?/'```" ]" {
                $Score -= 100
            }
            "E" {
                $Score += 26
            }
            "T" {
                $Score += 25
            }
            "A" {
                $Score += 24
            }
            "O" {
                $Score += 23
            }
            "I" {
                $Score += 22
            }
            "N" {
                $Score += 21
            }
            "S" {
                $Score += 20
            }
            "R" {
                $Score += 19
            }
            "H" {
                $Score += 18
            }
            "L" {
                $Score += 17
            }
            "D" {
                $Score += 16
            }
            "C" {
                $Score += 15
            }
            "U" {
                $Score += 14
            }
            "M" {
                $Score += 13
            }
            "F" {
                $Score += 12
            }
            "P" {
                $Score += 11
            }
            "G" {
                $Score += 10
            }
            "W" {
                $Score += 09
            }
            "Y" {
                $Score += 08
            }
            "B" {
                $Score += 07
            }
            "V" {
                $Score += 06
            }
            "K" {
                $Score += 05
            }
            "X" {
                $Score += 04
            }
            "J" {
                $Score += 03
            }
            "Q" {
                $Score += 02
            }
            "Z" {
                $Score += 01
            }
            Default {
                $Score +=  0
            }
        }
    }
    $Score
}

function PopulateObject {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [byte[]]$xordbytes,
    [Parameter(ParameterSetName='unknownKey')]
        [Char]$keyChar
)

    $obj = "" | Select-Object Key,EncryptedText,DecryptedText,LetterFreqScore

    $DecodedString = $(
        foreach($byte in $xordBytes) {
            [Char]$byte
        }
    ) -join ""
    
    if ($keyChar) {
        $obj.Key = $keyChar
    }
    $obj.EncryptedText   = $String
    $obj.DecryptedText   = $DecodedString.Trim()
    $obj.LetterFreqScore = [int](Score-LetterFrequency -DecodedString $DecodedString)

    $obj | Select-Object Key,EncryptedText,DecryptedText,LetterFreqScore
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
$MaxAllowableSamples = [int]($CipherByteCount / 2)
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
$BytePairDist = @{}

for ($CalcKeySize = 2; $CalcKeySize -le $MaxKeySize; $CalcKeySize++) {
    $HDs = @()

    # Write-Verbose ("Keysize is {0}." -f $CalcKeySize)

    if ($NoUserMaxSamples) {
        $MaxSamples = ([int]($CipherByteArray.Count / $CalcKeySize))
    }

    for ($i = 0; $i -lt $MaxSamples; $i++) {
        $Start = (($CalcKeySize - 1) * $i) + $i
        $End   = (($CalcKeySize - 1) * ($i + 1) + $i)
        # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
        if ($End -gt $CipherByteCount) {
            # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
            # continue
        }
        $ByteArray1 = $CipherByteArray[$Start..$End]
        $Start = $End + 1
        $End   = (($CalcKeySize - 1) * ($i + 2) + 1) + $i
        # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
        if ($End -gt $CipherByteCount) {
            # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
            # continue
        }
        $ByteArray2 = $CipherByteArray[$Start..$End]
        if ($ByteArray1.Count -eq $ByteArray2.Count) {
            $HDs += (GetHammingDistance $ByteArray1 $ByteArray2 $BytePairDist)
            # Write-Verbose ("HDs : {0}, Normalized : {1}, ByteArray1 : {2}, ByteArray2 : {3}" -f $HDs[$i], ($HDs[$i] / $ByteArray1.Count), ($ByteArray1 -join ","), ($ByteArray2 -join ",")) 
            # Write-Verbose ("ByteArrays are: {0} and {1}" -f ($ByteArray1 -join ":"), ($ByteArray2 -join ":"))
            # if (($HDs.Count % 450) -eq 0) { Write-Verbose ("HDs is {0}. ByteArray.Count is {1}" -f ($HDs -join ","), $ByteArray1.Count) }
            # if (($ByteArray1.Count % 29) -eq 0) { Write-Verbose ("HDs : {0}, Normalized : {1}, ByteArray1 : {2}, ByteArray2 : {3}" -f $HDs[$i], ($HDs[$i] / $ByteArray1.Count), ($ByteArray1 -join ","), ($ByteArray2 -join ",")) }
        }
    }
    if ($HDs) {
        # Write-Verbose ("HD: {0}" -f ($HDs -join ","))
        $AvgHD = ($HDs | Measure-Object -Average | Select-Object -ExpandProperty Average)
        $NAvgHD = $AvgHD / $CalcKeySize
        $obj = "" | Select-Object CalcKeySize,AvgHD,NAvgHD
        $obj.CalcKeySize = $CalcKeySize
        $obj.AvgHD = $AvgHD
        $obj.NAvgHD = $NAvgHD
        $objs += $obj
    }
}

$TopObjs = $objs | Sort-Object NAvgHD | Select-Object -First $top

$GCDs = @{}
$obj = "" | Select-Object ProbableKeySize,Top${top}KeySizes,Top${top}NAvgHDs,GCD

for ($p = 0; $p -lt $TopObjs.Count - 1; $p++) {
    for ($q = $p + 1; $q -lt $TopObjs.Count -1; $q++) {

        $gcd = GetGreatestCommonDenominator -val1 $TopObjs[$p].CalcKeySize -val2 $TopObjs[$q].CalcKeySize
        if ($GCDs.Contains($gcd)) {
            $GCDs.set_item($gcd, $GCDs[$gcd] + 1)
        } else {
            $GCDs.Add($gcd, 1)
        }
        # Write-Verbose ("val1 is {0}, val2 is {1}, GCD is {2}, count is {3}" -f ($TopObjs[$p].CalcKeySize), ($TopObjs[$q].CalcKeySize), $gcd, ($GCDs[$gcd]) )
    }      

    $MostFreqGCD = $GCDs.GetEnumerator() | Sort-Object @{Expression={$_.Value -as [int]}},@{Expression={$_.Name -as [int]}} | Select-Object -Last 1 -ExpandProperty Name

    if (($TopObjs[0..($TopObjs.Count - 1)].CalcKeySize).Contains($MostFreqGCD) -and `
        ($TopObjs | ? { $_.CalcKeySize -eq $MostFreqGCD -and $_.NAvgHD -lt $MaxNAvgHD})) {
            $ProbableKeySize = $MostFreqGCD
    } else {
        # $ProbableKeySize = ([int]$TopObjs[0].CalcKeySize, [int]$TopObjs[1].CalcKeySize | Sort-Object) -join " or "
        $ProbableKeySize1 = ([int]$TopObjs[0].CalcKeySize, [int]$TopObjs[1].CalcKeySize | Measure -Minimum).Minimum
        
        $MinNAvgHD = ($TopObjs[0..($TopObjs.Count - 1)].NAvgHD | Measure-Object -Minimum).Minimum
        $ProbableKeySize2 = $TopObjs | ? { $_.NAvgHD -eq $MinNAvgHD } | Select-Object -ExpandProperty CalcKeySize
        
        if ($ProbableKeySize1 -eq $ProbableKeySize2) {
            $ProbableKeySize = $ProbableKeySize1
        } else {
            if ($TopObjs | ? { $_.CalcKeySize -eq $ProbableKeySize1 -and $_.NAvgHD -lt $MaxNAvgHD } ) {
                $ProbableKeySize = $ProbableKeySize1
            } else {
                $ProbableKeySize = $ProbableKeySize2
                # $ProbableKeySize = ($ProbableKeySize1,$ProbableKeySize2 | Sort-Object) -join " or "
            }
        }
    }
    $obj.ProbableKeySize = $ProbableKeySize
    $obj."Top${top}KeySizes" = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
    $obj."Top${top}NAvgHDs" = $TopObjs[0..($TopObjs.Count - 1)].NAvgHD -join " : "
    # $obj | Select-Object ProbableKeySize,Top${top}KeySizes,Top${top}NAvgHDs | Format-Table -AutoSize
    break
}

# (GetTransposedKeySizeBlocks -KeySize $obj.ProbableKeySize -CipherByteArray $CipherByteArray).GetEnumerator() | Select-Object -ExpandProperty Value
$ProbableKey = @()

(0..($obj.ProbableKeySize - 1)) | ForEach-Object {
    $ProbableKey += ""
    $HighScoreObj = $False
    $TransposedByteArray = GetTransposedBlock -KeySize $obj.ProbableKeySize -CipherByteArray $CipherByteArray -KeyPosition $_

    if ($includeNonPrintable) {
        (0..255) | ForEach-Object {
            $keyspace += $_
        }
    } else {
        $keyspace = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~``!@#$%^&*()_-+={}[]\|:;`"'<>,.?/ "
    }        

    for ($j = 0; $j -lt $keyspace.Length; $j++) {
        # Write-Verbose ("Now trying: {0}" -f ($keyspace[$j]))
        $keyByte = GetByte $keyspace[$j]
        $xordBytes = $(
            for ($i = 0; $i -lt $TransposedByteArray.Count; $i++) {
                $TransposedByteArray[$i] -bxor $keyByte
            }
        )
  
        $brutedObj = PopulateObject -xordbytes $xordBytes -keyChar $keyspace[$j]

        if (-not($HighScoreObj)) {
            $HighScoreObj = $brutedObj.PSObject.Copy()
        } else {
            if ($brutedObj.LetterFreqScore -gt $HighScoreObj.LetterFreqScore) {
                $HighScoreObj = $brutedObj.PSObject.Copy()
                $ProbableKey[$_] = $keyspace[$j]
                # Write-Verbose ("Position {0} byte is probably {1} as byte or {2} as char." -f $_, $KeyByte, $ProbableKey[$_])
            }
        }
    }
}

$keybytes   = GetBytes ($ProbableKey -join "")
$xordBytes  = $(
    for ($i = 0; $i -lt $CipherByteArray.Count) {
        for ($j = 0; $j -lt $keyBytes.Length; $j++) {
            $CipherByteArray[$i] -bxor $keybytes[$j]
            $i++
            if ($i -ge $CipherByteArray.Count) {
                $j = $keyBytes.Length
            }
        }
    }
)

$DecryptedString = $(
    foreach($byte in $xordBytes) {
        [Char]$byte
    }
) -join ""

$obj | Add-Member NoteProperty ProbableKey ($ProbableKey -join "")
$obj | Add-Member NoteProperty ProbableDecryptedValue $DecryptedString
$obj | Select-Object ProbableKeySize,ProbableKey,ProbableDecryptedValue,Top${top}KeySizes,Top${top}NavgHDs