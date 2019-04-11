<#
.SYNOPSIS
Crack-XORRepeatingKeyCrypto.ps1 uses well-known attack techniques to 
break XOR repeating key cryptography of English language text.
.DESCRIPTION
Crack-XORRepeatingKeyCrypto.ps1 uses Hamming Distance and Greatest
Common Denominator calculations to determine the probable size of a 
repeating XOR key that may have been used for encrypting a string or
file.

Once the key size has been determined, this script uses English 
language character frequencies to brute-force the key. Once the key has
been determined, the script will use that key to decrypt the string or 
file.

The script works with base16 or base64 input, either from a file or
from a string passed via the command line.

The script will return an object with some metadata about its analysis,
including the top n key sizes (where n is an argument provided by the
user via the -top parameter) and the normalized average Hamming
Distances for each of those top n key sizes.
.PARAMETER MinKeySize
an optional parameter for lower bound of the key
.PARAMETER MaxKeySize
An optional parameter that sets the upper-bound on the key size to try.
If not supplied by the user, the script will set this to half the size
of the ciphertext. If the user supplied value is more than half the
size of the ciphertext, the script will change MaxKeySize to half the
size of the ciphertext as anything larger would not be a repeating key.
.PARAMETER MaxSamples
An optional parameter that controls how many byte pair samples are
passed to the Hamming Distance calculator, the default is to use as
many as possible. Smaller values result in faster runtime, but less
accuracy for determining the correct key size.
.PARAMETER String
A string of ciphertext to be decrypted. This parameter must be present
unless the user has passed the -File parameter.
.PARAMETER File
A path to a file that contains the ciphertext to be decrypted. This
parameter must be present unless the user has passed the -String
parameter.
.PARAMETER Encoding
An optional parameter that tells the script whether the ciphertext is 
encoded as base16 (hexadecimal) or base64, other formats are not 
supported. Base16 is the default setting.
.PARAMETER top
An optional parameter that tells the script how many probable key sizes
to calculate. The default is five.
.PARAMETER MaxNAvgHD
An optional parameter that sets the maximum normalized average Hamming
Distance allowed for a probable key. The default is 3.5.
.PARAMETER includeNonPrintable
A switch that causes the script to expand the keyspace from printable
ASCII characters to all bytes 0x00 through 0xFF.
.EXAMPLE
Crack-XORRepeatingKeyCrypto.ps1 -String "JhkPTTlMBgoVBE0FHEUSERUFUA1FCxECCFAJHQQVEQEVTBENGRVNBwMXDgtBGhUACUUeDh9QGA0AWAkIHBxFAxENCE8=" -Encoding base64 -MaxKeySize 21


ProbableKeySize        : 7
ProbableKey            : example
ProbableDecryptedValue : Can I come up with a nice example that works well for the help file?
Top5KeySizes           : 9:7:19:14:3
Top5NAvgHDs            : 2.37037037037037 : 2.46428571428571 : 2.55263157894737 : 2.5952380952381 : 2.68253968253968
.EXAMPLE
Get-Content .\7-encrypted.txt
IwkQU0IIEEtBVwMAF1hIAB0AGhpYFVlGFhwCDQd+Kkk6ABZBGEUNHA1JF0EHF1lBTw1FHhUFBBIAChtJbCpLNg4RDR1TVAEaTgZTSwMLGwVJMU8aB08PLWFFKhtIEBxVBxQAA
E4PRQ4dBAUaTg5+KkFtBBMcEEgNHFcHU1QOADgGGAYbDRJMDH4qQXcDAAsRSB0bRUkbRQ1MSwQUVCFkeS1jO0UYAAUMFxEcDBZOZHkAL09LEhxUCwgdVEkXQQ9DDkUNGw8MB0
gMAS1rADwAWRcJBwcADRJOAkVLERYTDR0bRRt+KkFuBEUOEUgKEk4dU1QATABFGABICB9MZHkAMUwOBAoRSB0SSwxTTQQACgkWGg9keQA+G0UPABIKDFQbBRpEDFNPDwAPCg4
aZWN+KiEWWUFOAgscAA0MHS1jU3QJQR8WWSYNHRtBSTVSAE4ACRAaZWNTcwEWAAVPBRFZBg0EFk0LFlJBVAMAWSUdDBZOSRxGQXMEEBV5Ykk6VBpTSABSD0UNHQUMAAALFkYA
TAcAF1QcARYAGhxMBAAYEAsCAR8cUhp+KkFzAwBZAAAAHUsaU2kMAAgXGA4RZHkAKwZUQWkGRRMBGx1TRxscVwhOTEUWGAxkeS1jO0UYAAUMFxEcDBZOZHkAL09LEhxUDwYHA
AccVAlJBUJZHQZJEE8EHk8PLWFFLhFIChJOHVNEAE4IAFkABw4WVAEWUmwqSysWVB8MU0MIHVRBVAoJElQJHVNBBR8tawA7CRwVGwxTVAgYRUFNDkUYGAcHFC1jU3cJRQVFAB
sdSQBMABdFQU8FRR0bHwd+KmR5cxRSDkUVGwcCAAAOHE8FLWFFKh8JHRYACFNMCFQfCRxUBAYERRtTTg5XZm90fjwBFgAKBkUTVgRFHhsEDX4qSSdIBAANDBcRSCocTBweQgh
BBWhzVCUIGEVJB08PSQwNDVQJSQRPBxdFE0YeCVkAAAAdR2R5ADJBEkUQAEgIFEEAHS1rAD8NHFQLHBZSHxwABk8HAXR+SD0bRUkVSQ9FSyYWGB0EEUkIHS1rACYEEhFIHRxO
ABRIFQAKRQ4bBg0WUg8GTEFUAwwXE2VjU3QBFgACVQ4XDxtIDhxMDX4qQXQDAFkSAQcWACocTBRNCQwYGmVjU20IGEVBVAQLEBMAHVNBSQRPD0QOFx8BBEkHSAAdR2wqZm83G
0geFgAKEk4VAA8EFxcNSQdPDhZUCUUZaHNUJgZTVwxTQwBOH0UNFQQCU0EdU0ENTGZv

Crack-XORRepeatingKeyCrypto.ps1 -File .\7-encrypted.txt -Encoding base64 -MaxKeySize 26


ProbableKeySize        : 13
ProbableKey            : this is a key
ProbableDecryptedValue : Way back when, in sixty-seven
                          I was the dandy of gamma chi
                          Sweet things from Boston
                          So young and willing
                          Moved down to Scarsdale
                          Where the hell am I

                         Hey nineteen
                          No we cant dance together
                          We cant dance together
                          No we cant talk at all
                          Please take me along
                          When you slide on down

                         Hey nineteen
                          Thats Retha Franklin
                          She dont remember the Queen of Soul
                          Its hard times befallen the sole survivors
                          She thinks Im crazy
                          But Im just growin' old

                         Hey nineteen
                          No we got nothin' in common
                          We cant dance together
                          No we cant talk at all
                          Please take me along
                          When you slide on down

                         Sure looks good
                          Skate a little lower now

                         The cuervo gold
                          The fine Columbian
                          Make tonight a wonderful thing
                          Say it again
                          The cuervo gold
                          The fine Columbian
                          Make tonight a wonderful thing
                          The cuervo gold
                          The fine Columbian
                          Make tonight a wonderful thing

                         No we cant dance together
                          No we cant talk at all

Top5KeySizes           : 26:13:3:16:23
Top5NAvgHDs            : 2.79010989010989 : 2.90140845070423 : 3.07195767195767 : 3.07219827586207 : 3.09891304347826
.LINK
http://trustedsignal.blogspot.com/2015/07/cracking-repeating-xor-key-crypto.html
http://trustedsignal.blogspot.com/2015/06/xord-play-normalized-hamming-distance.html
https://github.com/davehull/MCC/blob/master/sets/1/Crack-XORRepeatingKeyCrypto.ps1
#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False,Position=2)]
        [int]$MaxKeySize=$False,
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
        [switch]$includeNonPrintable,
    [Parameter(Mandatory=$False,Position=8)]
        [int]$MinKeySize=$False
)

$error.clear()
$ErrorActionPreference = 'Stop'

function GetByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [Char]$key
)
    # Takes a character as input, returns the byte value
    # Example: GetByte "A" returns 65
    [System.Text.Encoding]::Unicode.GetBytes($key)[0]
}

function GetBytes {
Param(
    [Parameter(Mandatory=$True,Position=0,ValueFromPipeLine=$True)]
        [String]$string
)
    # Takes a string of characters and returns an array of bytes
    # Example: GetBytes "ABC" returns @(65,66,67)
    [System.Text.Encoding]::Default.GetBytes($string)
}

function GetBits {
Param(
    [Parameter(Mandatory=$True,Position=0,ValueFromPipeLine=$True)]
        [byte]$byte
)
    # Takes a byte and returns a string of 1s and 0s representing the given byte
    # Example: GetBits 65 returns 01000001
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
    # Calculates the Hamming Distance between two equal sized arrays of bytes
    # Also takes a hashtable of byte pairs separated by a colon as the key and
    # the value is their distance, this is because it's faster to lookup HDs in
    # this table than it is to calculate them. If a given byte pair is not in 
    # the table, the pair will be added along with their distance.
    # Example: GetHammingDistance -ByteArray1 (GetByteArray "ABC") -ByteArray2 (GetByteArray "BAC") -BytePairDist @{}
    # Returns: 4
    if ($ByteArray1.Count -ne $ByteArray2.Count) {
        Write-Error ("Hamming Distance can't be calculated because byte arrays are different lengths, {0} and {1}." -f $ByteArray1.Count, $ByteArray2.Count)
        return $False
    } else {
        $Total = 0
        for ($i = 0; $i -lt $ByteArray1.Count; $i++) {
            $bitCount = 0
            $pair  = $(($ByteArray1[$i],$ByteArray2[$i]) -join ":")
            $rpair = $(($ByteArray2[$i],$ByteArray1[$i]) -join ":")
            if ($pair -eq $rpair) { 
                # $pair and $rpair are equivalent (10:10 -eq 10:10)
                # Hamming Distance between identical bytes is 0
                continue
            } elseif ($BytePairDist.Contains($pair) -or $BytePairDist.Contains($rpair)) {
                # Our hashtable already has the Hamming Distance for 
                # this byte pair. Lookup the distance in the table and
                # move on, it's faster than recalculating
                $bitCount += $BytePairDist[$pair]
            } else {
                # Our hashtable doesn't contain this byte pair.
                # Calculate the Hamming Distance 
                $bits = (GetBits ($ByteArray1[$i] -bxor $ByteArray2[$i]))

                for ($j = 0; $j -lt $bits.Length; $j++) {
                    if ($bits[$j] -eq '1') {
                        $bitCount++
                    }
                }
                # Store the byte pair and the reverse in our hashtable
                # along with the distance, so we can look it up next
                # time. Lookup is faster than recalculating.
                # We store the reverse too because the HD between byte
                # pairs AB and BA is the same as the HD between byte
                # pairs BA and AB
                $BytePairDist.Add($pair,$bitCount)
                $BytePairDist.Add($rpair,$bitCount)
            }
            $Total += $bitCount
        }
        Write-Verbose ('Hamming Distance of {0} and {1} is {2}' -f ($ByteArray1 -join ' '), ($ByteArray2 -join ' '), $Total)
        $Total
    }
}

function ConvertBase16-ToByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$base16String
)
    # Converts a base16 (hexadecimal) string to a byte array
    # Example: ConvertBase16-ToByte -base16String "101011"
    # Returns: @(16,16,17)
    if ($base16String -match "([^a-fA-F0-9])") {
        Write-Error ("Input string or file does not appear to be encoded as base16. Quitting.")
        exit
    }
    $byteArray = $(if ($base16String.Length -eq 1) {
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
    $byteArray
}

function ConvertBase64-ToByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$base64String
)
    # Takes a Base64 encoded string and returns a byte array
    # Example: ConvertBase64-ToByte -base64String "AAAB"
    # Returns: @(0,0,1)
    Try {
        $Error.Clear()
        [System.Convert]::FromBase64String($base64String)
    } Catch {
        Write-Error ("Input string or file does not match Base64 encoding. Quitting.")
        exit
    }
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
    # Returns the GCD for the values 1 and 2
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
    # This function returns an array of every byte at $KeySize offsets
    # beginning at $KeyPosition. If $KeySize is 4 and $KeyPosition is
    # 0, it returns an array of bytes 0, 4, 8, 12... 
    # If $KeySize is 29 and $KeyPosition is 1, it returns an array of 
    # bytes 1, 30, 59...
    
    # The byte array will be input to a separate single character XOR
    # brute forcing function. If the $KeySize is right, the right byte
    # value XOR'd against the array will produce output with a "letter
    # frequency" score resembling English letter frequency. Whatever 
    # that byte value is, it is likely to be the right byte value for 
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
    # Scores were set arbitrarily by me, though I did play around 
    # with different values
    for($i = 0; $i -lt $DecodedUpper.Length; $i++) {
        switch -Regex ($DecodedUpper[$i]) {
            "[^-A-Z0-9!@#$~%^&*)(\[\]\.\\:;<>,.?/'```" \n]" {
                # byte is not an ASCII printable character, deduct
                # 100 points from the score
                $Score -= 100
            }
            "E" {
                # Below is the frequency table for English letters
                # We score each letter according to frequency
                $Score += 78
            }
            "T" {
                $Score += 75
            }
            "A" {
                $Score += 72
            }
            "O" {
                $Score += 69
            }
            "I" {
                $Score += 66
            }
            "N" {
                $Score += 63
            }
            "S" {
                $Score += 60
            }
            "R" {
                $Score += 57
            }
            "H" {
                $Score += 54
            }
            "L" {
                $Score += 51
            }
            "D" {
                $Score += 48
            }
            "C" {
                $Score += 45
            }
            "U" {
                $Score += 42
            }
            "M" {
                $Score += 39
            }
            "F" {
                $Score += 36
            }
            "P" {
                $Score += 33
            }
            "G" {
                $Score += 30
            }
            "W" {
                $Score += 27
            }
            "Y" {
                $Score += 24
            }
            "B" {
                $Score += 21
            }
            "V" {
                $Score += 18
            }
            "K" {
                $Score += 15
            }
            "X" {
                $Score += 12
            }
            "J" {
                $Score += 09
            }
            "Q" {
                $Score += 06
            }
            "Z" {
                $Score += 03
            }
            Default {

                $Score +=  0
            }
        }
    }
    $Score
}

function GetEnglishScore {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [byte[]]$xordbytes,
    [Parameter(ParameterSetName='unknownKey')]
        [Char]$keyChar
)
    # Returns a PowerShell object with the key and the score of the
    # letter frequency according to English letter frequencies
    $obj = "" | Select-Object Key,LetterFreqScore

    $DecodedString = $(
        foreach($byte in $xordBytes) {
            [Char]$byte
        }
    ) -join ""
    
    if ($keyChar) {
        $obj.Key = $keyChar
    }

    $obj.LetterFreqScore = [int](Score-LetterFrequency -DecodedString $DecodedString)

    $obj | Select-Object Key,LetterFreqScore
}



# All functions defined, let's get to work
# Create a byte array for our ciphertext
[byte[]]$CipherByteArray

# Were we called with -String, -File, -base16 or -base64
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
    # User didn't specificy a -MaxSamples value We'll set one later,
    # but we'll also need to know that the user didn't set one
    $NoUserMaxSamples = $True
}

# Get our count once, we're going to need it multiple places
$CipherByteCount = $CipherByteArray.Count

# For repeating key XOR, max can't exceed half the CipherByteCount
if ($CipherByteCount % 2)
{
    $MaxAllowableKeySize = $MaxAllowableSamples = [int]($CipherByteCount - 1) / 2
} else 
{
    $MaxAllowableKeySize = $MaxAllowableSamples = [int]($CipherByteCount) / 2
}


if ($MaxSamples -gt $MaxAllowableSamples) {
    Write-Verbose ("-MaxSamples of {0} was too large. Setting to {1}, ((CipherByteArray.Count / min(keysize)) - 1." -f $MaxSamples, $MaxAllowableSamples)
    $MaxSamples = $MaxAllowableSamples
}
if ($MinKeySize -eq $False) {
	$MinKeySize = 2
}
if ($MaxKeySize -eq $False) {
    Write-Verbose ("No MaxKeySize value provided, defaulting to half the input size. Depending on the input size, this could take some time.")
    $MaxKeySize = $MaxAllowableKeySize
} elseif ($MaxKeySize -gt $MaxAllowableKeySize) {
    Write-Verbose ("-MaxKeySize of {0} exceeds the length of the ciphertext. Setting to {1}, half the size of the ciphertext." -f $MaxKeySize, $MaxAllowableKeySize)
    $MaxKeySize = $MaxAllowableKeySize
}

$objs = @()  # this will be an array of objects
$BytePairDist = @{}  # a hashtable of Hamming Distances of byte pairs

# Now we're getting down to business. We're going to try calculate
# Hamming Distances for pairs of bytes from two bytes in length up to
# MaxKeySize. But what if the key size is one byte? If that's the case
# use XOR-Decrypt.ps1 for single-byte repeating XOR key crypto, it's
# faster and far more accurate.
for ($CalcKeySize = $MinKeySize; $CalcKeySize -le $MaxKeySize; $CalcKeySize++) {
    $HDs = @()  # An array of Hamming Distances

    Write-Verbose ('$CalcKeySize is: {0}' -f $CalcKeySize)
    if ($NoUserMaxSamples) {
        # As the keysize being tried increases, the sample size decreases
        if ($CipherByteCount % 2)
        {
            $MaxSamples = ([int]($CipherByteCount - 1) / $CalcKeySize)
        } else 
        {
            $MaxSamples = ([int]($CipherByteCount) / $CalcKeySize)    
        }        
    }
    Write-Verbose ('$MaxSamples: {0}' -f $MaxSamples)

    for ($i = 0; $i -lt $MaxSamples; $i++) {
        # Build a pair of byte arrays based on our keysize
        $Start = (($CalcKeySize - 1) * $i) + $i
        $End   = (($CalcKeySize - 1) * ($i + 1) + $i)
        $ByteArray1 = $CipherByteArray[$Start..$End]
        $Start = $End + 1
        $End   = (($CalcKeySize - 1) * ($i + 2) + 1) + $i
        $ByteArray2 = $CipherByteArray[$Start..$End]

        # Calculate the Hamming Distance of the two byte arrays
        if ($ByteArray1.Count -eq $ByteArray2.Count) {
            $HDs += (GetHammingDistance $ByteArray1 $ByteArray2 $BytePairDist)
        }
    }

    if ($HDs) {
        # Store the results in an object, then we'll add that object to
        # our array of objects
        $AvgHD = ($HDs | Measure-Object -Average | Select-Object -ExpandProperty Average)
        Write-Verbose ('$AvgHD: {0}' -f $AvgHD)
        $NAvgHD = $AvgHD / $CalcKeySize
        Write-Verbose ('Normalized AvgHD: {0}' -f $NAvgHD)
        $obj = "" | Select-Object CalcKeySize,AvgHD,NAvgHD
        $obj.CalcKeySize = $CalcKeySize
        $obj.AvgHD = $AvgHD
        $obj.NAvgHD = $NAvgHD
        $objs += $obj
    }
}

# Pull out the top n objects based on user's -top arg, default is five
# if there are less than $top objs, reset $top accordingly
if ($top -gt $objs.count)
{
    $top = $objs.count
}
$TopObjs = $objs | Sort-Object NAvgHD | Select-Object -First $top

# Make a hashtable for storing greatest common denominators and their
# frequency of occurrence
$GCDs = @{} 

# Instantiate a new $obj with different properties
$obj = "" | Select-Object ProbableKeySize,"Top ${top} KeySizes","Top ${top} NAvgHDs",GCD


# This nested loop will cacluate greatest common denominators for each
# of the caluclated key sizes in the top n objects
Write-Verbose ('$TopObjs.count is {0}' -f $TopObjs.count)
for ($p = 0; $p -lt $TopObjs.Count; $p++) {
    for ($q = $p + 1; $q -lt $TopObjs.Count; $q++) {

        $gcd = GetGreatestCommonDenominator -val1 $TopObjs[$p].CalcKeySize -val2 $TopObjs[$q].CalcKeySize
        if ($GCDs.Contains($gcd)) {
            # We've seen this GCD before, increment its count
            $GCDs.set_item($gcd, $GCDs[$gcd] + 1)
        } else {
            # We've not seen this GCD before, add it to out table
            $GCDs.Add($gcd, 1)
        }
    }      

    # $MostFreqGCD is the GCD that appeared most frequently in the list
    # of top n calculated key sizes, if this value is in the list of 
    # the top n calculated key sizes, it is almost certainly the actual
    # key size
    $MostFreqGCD = $GCDs.GetEnumerator() | Sort-Object @{Expression={$_.Value -as [int]}},@{Expression={$_.Name -as [int]}} | Select-Object -Last 1 -ExpandProperty Name
    Write-Verbose ('$MostFreqGCD is {0}' -f $MostFreqGCD)

    if (($TopObjs[0..($TopObjs.Count - 1)].CalcKeySize).Contains($MostFreqGCD) -and `
        ($TopObjs | ? { $_.CalcKeySize -eq $MostFreqGCD -and $_.NAvgHD -lt $MaxNAvgHD})) {
            $ProbableKeySize = $MostFreqGCD
    } else {
        # $MostFreqGCD was not in the top n calculated key sizes
        # Set $ProbableKeySize1 to the smaller of the first two
        # calculated key sizes
        $ProbableKeySize1 = ([int]$TopObjs[0].CalcKeySize, [int]$TopObjs[1].CalcKeySize | Measure -Minimum).Minimum
        
        # Get the minimum Normalized average Hamming Distance from the 
        # top n calculated key sizes and set $ProbableKeySize2 to that
        # calculated key size
        $MinNAvgHD = ($TopObjs[0..($TopObjs.Count - 1)].NAvgHD | Measure-Object -Minimum).Minimum
        $ProbableKeySize2 = $TopObjs | ? { $_.NAvgHD -eq $MinNAvgHD } | Select-Object -ExpandProperty CalcKeySize
        

        if ($ProbableKeySize1 -eq $ProbableKeySize2) {
            # The smallest calculated key size also has the smallest
            # NAvgHD and so is probably our key size
            $ProbableKeySize = $ProbableKeySize1
        } else {
            if ($TopObjs | ? { $_.CalcKeySize -eq $ProbableKeySize1 -and $_.NAvgHD -lt $MaxNAvgHD } ) {
                # Hm, if $ProbableKeySize1 has a NAvgHD below the max
                # allowed NAvgHD, let's take it as our key size
                $ProbableKeySize = $ProbableKeySize1
            } else {
                # Well, maybe the right key size is the one with the
                # smallest NAvgHD
                $ProbableKeySize = $ProbableKeySize2
            }
        }
    }
    # Now that we have the probable key size, build out object and exit
    $obj.ProbableKeySize = $ProbableKeySize
    $obj."Top ${top} KeySizes" = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
    $obj."Top ${top} NAvgHDs" = $TopObjs[0..($TopObjs.Count - 1)].NAvgHD -join " : "
    break
}

# Make an array for our probable key
$ProbableKey = @()

# Try and figure out what the byte is for each position in our key
(0..($obj.ProbableKeySize - 1)) | ForEach-Object {
    $ProbableKey += ""
    $HighScoreObj = $null
    Write-Verbose ('Starting...')

    # GetTransposedBlock will return an array of key size aligned bytes
    # if key size is 4, it will return bytes 0, 3, 7, 11... assuming
    # $KeyPosition is 0, if $KeyPosition is 2 and key size is 6, it
    # will return an array of bytes 2, 7, 13, 19...
    $TransposedByteArray = GetTransposedBlock -KeySize $obj.ProbableKeySize -CipherByteArray $CipherByteArray -KeyPosition $_

    # What's our keyspace? Default is ASCII printable characters only,
    # but if the user passed -includeNonPrintable, we'll try all bytes
    # 0 - 255
    if ($includeNonPrintable) 
    {
        $keyspace = [char[]](0..255) -join ''
    } else 
    {
        $keyspace = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~``!@#$%^&*()_-+={}[]\|:;`"'<>,.?/ "
    }  
    
    # Iterate through each byte of our keyspace, xoring each byte of
    # our transposed byte arrays and store the result in a new byte 
    # array, $xordBytes
    for ($j = 0; $j -lt $keyspace.Length; $j++) {
        $keyByte = GetByte $keyspace[$j]
        # Write-Verbose ('$keyByte is {0}' -f $keyByte)
        $xordBytes = $(
            for ($i = 0; $i -lt $TransposedByteArray.Count; $i++) {
                $TransposedByteArray[$i] -bxor $keyByte
            }
        )
  
        # Get an object with the key and the English letter frequency
        # score for the given transposed, xor'd block of bytes
        $brutedObj = GetEnglishScore -xordbytes $xordBytes -keyChar $keyspace[$j]
        # Write-Verbose ('English score is {0}' -f $brutedObj.LetterFreqScore)

        if ($HighScoreObj -eq $null) {
            # First run, no $HighScoreObj
            $HighScoreObj = $brutedObj.PSObject.Copy()
            Write-Verbose ('New English high score of {0} using byte value {1}' -f $HighScoreObj.LetterFreqScore, $keyByte)
        } else {
            # The English letter frequency score was higher for this
            # key byte, update the $HighScoreObj and store the new
            # ProbableKey for this byte position of the key
            if ([int]$brutedObj.LetterFreqScore -gt [int]$HighScoreObj.LetterFreqScore) {
                $HighScoreObj = $brutedObj.PSObject.Copy()
                $ProbableKey[$_] = $keyspace[$j]
                Write-Verbose ('New English high score of {0} using byte value {1}' -f $HighScoreObj.LetterFreqScore, $keyByte)
            }
        }
    }
}

# We've got the most probable key, build an array of those bytes
$keybytes   = GetBytes ($ProbableKey -join "")

# Now we're going to take our array of probable key bytes and xor the
# original $CipherByteArray against that array
$xordBytes  = $(
    for ($i = 0; $i -lt $CipherByteCount) {
        for ($j = 0; $j -lt $keyBytes.Length; $j++) {
            # We'll repeat the key until we reach ciphertext's end
            $CipherByteArray[$i] -bxor $keybytes[$j]
            $i++
            if ($i -ge $CipherByteCount) {
                # We've reached the end of the ciphertext, exit loop
                $j = $keyBytes.Length
            }
        }
    }
)


# Convert the decrypted bytes to a string
$DecryptedString = $(
    foreach($byte in $xordBytes) {
        [Char]$byte
    }
) -join ""

# Build an object to return to the user
$obj | Add-Member NoteProperty ProbableKey ($ProbableKey -join "")
$obj | Add-Member NoteProperty ProbableDecryptedValue $DecryptedString
$obj | Select-Object ProbableKeySize,ProbableKey,ProbableDecryptedValue,"Top ${top} KeySizes","Top ${top} NavgHDs"
