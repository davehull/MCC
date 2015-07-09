<#
.SYNOPSIS
XOR-Decrypt.ps1 takes a hexadecimal encrypted string an optional key
value and returns the decrypted string. If no key is supplied, the
script will attempt to brute force the key, which the script assumes is
a single ASCII printable characters as a key space, XORing the string
with each single character and returning a XOR decrypted string.
Future work will include brute forcing multi-byte keys.
.PARAMETER String
A required argument -- the hexadecimal encoded string to be decoded.
.PARAMETER Key
An optional key to use for decryption, without this parameter, the
script will attempt to brute-force the key and apply ngram and entropy
analysis to the results to make an educated guess about the correct
key.
.PARAMETER AllResults
An optional switch that causes the script to return the all decrypted 
objects, by default the script will only return the object with the 
highest score -- the object with the decrypted string that's most 
likely to be sensible English text based on letter frequency, bigrams
and trigrams. Oh my!
.EXAMPLE
XOR-Decrypt.ps1 -String 093235282e7a292e2833343d7a3d352e7a34357a283f3b293534
Key             : Z
EncryptedText   : 093235282e7a292e2833343d7a3d352e7a34357a283f3b293534
DecryptedText   : Short string got no reason
Entropy         : 3.38256808327608
LetterFreqScore : 457
BiGramScore     : 564
TriGramScore    : 192
TotalScore      : 1242.56333694935

This satisfies set 1, challenge 3 and can be used in a loop to satisfy
set 1, challenge 4. See the next EXAMPLE section for details.
.EXAMPLE
Loop scenario over corpus of potentially encrypted data:
$(foreach ($line in Get-Content 4.txt) { 
    XOR-Decrypt.ps1 -String $line }) | 
        Sort-Object TotalScore -Descending | Select-Object -First 1
Key             : [ Redacted to keep people honest ]
EncryptedText   : [ Redacted ]
DecryptedText   : [ Redacted ]
Entropy         : 3.98656924646063
LetterFreqScore : 337
BiGramScore     : 714
TriGramScore    : 531
TotalScore      : 1607.08422501096
.EXAMPLE
Known key scenario:
XOR-Decrypt.ps1 -String 36190f580f1b090107014e42140c1e5509550752 -key "fun!"
Key             : fun!
EncryptedText   : 36190f580f1b090107014e42140c1e5509550752
DecryptedText   : Playing at crypto is
Entropy         : 3.68418371977919
LetterFreqScore : 305
BiGramScore     : 362
TriGramScore    : 144
TotalScore      : 838.143054637349
#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$String,
    [Parameter(Mandatory=$False,Position=1)]
        [Switch]$AllResults,
    [Parameter(Mandatory=$False,Position=2)]
        [String]$key,
    [Parameter(Mandatory=$False,Position=3)]
        [ValidateSet("base16","base64")]
        [String]$Encoding="base16"
)


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

function Score-BiGrams {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$DecodedString
)
    $Score = 0
    $DecodedUpper = $DecodedString.ToUpper()

    # Score according to English bi-gram frequency
    for ($i = 0; $i -lt $DecodedUpper.Length; $i++) {
        switch (($DecodedUpper[$i..($i + 1)]) -join "") {
            "TH" {
                $Score += 50
            }
            "HE" {
                $Score += 49
            }
            "IN" {
                $Score += 48
            }
            "ER" {
                $Score += 47
            }
            "AN" {
                $Score += 46
            }
            "RE" {
                $Score += 45
            }
            "ON" {
                $Score += 44
            }
            "AT" {
                $Score += 43
            }
            "EN" {
                $Score += 43
            }
            "ND" {
                $Score += 41
            }
            "TI" {
                $Score += 40
            }
            "ES" {
                $Score += 39
            }
            "OR" {
                $Score += 38
            }
            "TE" {
                $Score += 37
            }
            "OF" {
                $Score += 36
            }
            "ED" {
                $Score += 35
            }
            "IS" {
                $Score += 34
            }
            "IT" {
                $Score += 33
            }
            "AL" {
                $Score += 32
            }
            "AR" {
                $Score += 31
            }
            "ST" {
                $Score += 30
            }
            "TO" {
                $Score += 29
            }
            "NT" {
                $Score += 28
            }
            "NG" {
                $Score += 27
            }
            "SE" {
                $Score += 26
            }
            "HA" {
                $Score += 25
            }
            "AS" {
                $Score += 24
            }
            "OU" {
                $Score += 23
            }
            "IO" {
                $Score += 22
            }
            "LE" {
                $Score += 21
            }
            "VE" {
                $Score += 20
            }
            "CO" {
                $Score += 19
            }
            "ME" {
                $Score += 18
            }
            "DE" {
                $Score += 17
            }
            "HI" {
                $Score += 16
            }
            "RI" {
                $Score += 15
            }
            "RO" {
                $Score += 14
            }
            "IC" {
                $Score += 13
            }
            "NE" {
                $Score += 12
            }
            "EA" {
                $Score += 11
            }
            "RA" {
                $Score += 10
            }
            "CE" {
                $Score += 09
            }
            "LI" {
                $Score += 08
            }
            "CH" {
                $Score += 07
            }
            "LL" {
                $Score += 06
            }
            "BE" {
                $Score += 05
            }
            "MA" {
                $Score += 04
            }
            "SI" {
                $Score += 03
            }
            "OM" {
                $Score += 02
            }
            "UR" {
                $Score += 01
            }
            Default {
                $Score += 0
            }
        }        
    }
    $Score * 2
}
       
function Score-TriGrams {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$DecodedString
)
    $Score = 0
    $DecodedUpper = $DecodedString.ToUpper()

    # Score according to English tri-gram frequency
    for ($i = 0; $i -lt $DecodedUpper.Length; $i++) {
        switch (($DecodedUpper[$i..($i + 2)]) -join "") {
            "THE" {
                $Score += 50
            }
            "AND" {
                $Score += 49
            }
            "ING" {
                $Score += 48
            }
            "ION" {
                $Score += 47
            }
            "TIO" {
                $Score += 46
            }
            "ENT" {
                $Score += 45
            }
            "ATI" {
                $Score += 44
            }
            "FOR" {
                $Score += 43
            }
            "HER" {
                $Score += 43
            }
            "TER" {
                $Score += 41
            }
            "HAT" {
                $Score += 40
            }
            "THA" {
                $Score += 39
            }
            "ERE" {
                $Score += 38
            }
            "ATE" {
                $Score += 37
            }
            "HIS" {
                $Score += 36
            }
            "CON" {
                $Score += 35
            }
            "RES" {
                $Score += 34
            }
            "VER" {
                $Score += 33
            }
            "ALL" {
                $Score += 32
            }
            "ONS" {
                $Score += 31
            }
            "NCE" {
                $Score += 30
            }
            "MEN" {
                $Score += 29
            }
            "ITH" {
                $Score += 28
            }
            "TED" {
                $Score += 27
            }
            "ERS" {
                $Score += 26
            }
            "PRO" {
                $Score += 25
            }
            "THI" {
                $Score += 24
            }
            "WIT" {
                $Score += 23
            }
            "ARE" {
                $Score += 22
            }
            "ESS" {
                $Score += 21
            }
            "NOT" {
                $Score += 20
            }
            "IVE" {
                $Score += 19
            }
            "WAS" {
                $Score += 18
            }
            "ECT" {
                $Score += 17
            }
            "REA" {
                $Score += 16
            }
            "COM" {
                $Score += 15
            }
            "EVE" {
                $Score += 14
            }
            "PER" {
                $Score += 13
            }
            "INT" {
                $Score += 12
            }
            "EST" {
                $Score += 11
            }
            "STA" {
                $Score += 10
            }
            "CTI" {
                $Score += 09
            }
            "ICA" {
                $Score += 08
            }
            "IST" {
                $Score += 07
            }
            "EAR" {
                $Score += 06
            }
            "AIN" {
                $Score += 05
            }
            "ONE" {
                $Score += 04
            }
            "OUR" {
                $Score += 03
            }
            "ITI" {
                $Score += 02
            }
            "RAT" {
                $Score += 01
            }
            Default {
                $Score += 0
            }
        }        
    }
    $Score * 3
}       
        
function GetShannonEntropy {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [string]$DecodedString
)
    $Entropy = 0.0
    $FrequencyTable = @{}
    $ByteArrayLength = 0

    for ($i = 0; $i -lt $DecodedString.Length; $i++) {
        $FrequencyTable[([System.Convert]::ToByte($DecodedString[$i]))]++
        $ByteArrayLength++
    }

    $byteMax = 255
    for($byte = 0; $byte -le $byteMax; $byte++) {
        $byteProb = ([double]$FrequencyTable[[byte]$byte])/$ByteArrayLength
        if ($byteProb -gt 0) {
            $Entropy += -$byteProb * [Math]::Log($byteProb, 2.0)
        }
    }
    $Entropy
}

function GetByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [Char]$key
)
    [System.Text.Encoding]::Default.GetBytes($key)
}

function GetBytes {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$key
)
    [System.Text.Encoding]::Default.GetBytes($key)
}

function PopulateObject {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [byte[]]$xordbytes,
    [Parameter(ParameterSetName='unknownKey')]
        [Char]$keyChar,
    [Parameter(ParameterSetName='knownKey')]
        [String]$keyString
)

    $obj = "" | Select-Object Key,EncryptedText,DecryptedText,Entropy,LetterFreqScore,BiGramScore,TriGramScore,TotalScore

    $DecodedString = $(
        foreach($byte in $xordBytes) {
            [Char]$byte
        }
    ) -join ""
    
    if ($keyChar) {
        $obj.Key = $keyChar
    } else {
        $obj.Key = $keyString
    }
    $obj.EncryptedText   = $String
    $obj.DecryptedText   = $DecodedString.Trim()
    $obj.Entropy         = (GetShannonEntropy -DecodedString $DecodedString)
    $obj.LetterFreqScore = [int](Score-LetterFrequency -DecodedString $DecodedString)
    $obj.BiGramScore     = [int](Score-BiGrams -DecodedString $DecodedString)
    $obj.TriGramScore    = [int](Score-TriGrams -DecodedString $DecodedString)
    $obj.TotalScore      = $obj.LetterFreqScore + $obj.BigramScore + $obj.TriGramScore + (100 / $obj.Entropy)

    $obj | Select-Object Key,EncryptedText,DecryptedText,Entropy,LetterFreqScore,BiGramScore,TriGramScore,TotalScore
}

function ConvertHex-ToByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$hexString
)
    $byteArray = $(if ($hexString.Length -eq 1) {
        ([System.Convert]::ToByte( $hexString, 16))
    } elseif ($hexString.Length % 2 -eq 0) {
        $hexString -split "([a-fA-F0-9]{2})" | ForEach-Object {
            if ($_) {
                $ByteInHex = [String]::Format("{0:D}", $_)
                $PaddedHex = $ByteInHex.PadLeft(2,"0")
                [System.Convert]::ToByte( $PaddedHex, 16 )
            }
        }
    })
    $byteArray
}

function ConvertBase16-ToBase64 {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$hexString
)
    $byteArray = $(if ( $hexString.Length -eq 1 ) {
        ([System.Convert]::ToByte( $hexString, 16 ))
    } elseif ( $hexString.Length % 2 -eq 0 ) {
        $hexString -split "([a-fA-F0-9]{2})" | ForEach-Object {
            if ($_) {
                [System.Convert]::ToByte( $_, 16 )
            }
        }
    })
    [System.Convert]::ToBase64String($byteArray)
}

function ConvertBase64-ToByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$base64String
)
    # Takes a Base64 encoded string and returns a byte array
    [System.Convert]::FromBase64String($base64String)
}

switch ($Encoding) {
    "base16" {
        $byteArray = ConvertHex-ToByte -hexString $String
    }
    "base64" {
        $byteArray = ConvertBase64-ToByte -base64String $String
    }
}


if ($key.Length -gt 1) {
    # We have a key, we don't need to guess
    # This needs to be refactored to remove duped code, but I wanted to
    # see if it worked.
    $keybytes   = GetBytes $key
    $xordBytes  = $(
        for ($i = 0; $i -lt $byteArray.Length) {
            for ($j = 0; $j -lt $keyBytes.Length; $j++) {
                $byteArray[$i] -bxor $keybytes[$j]
                $i++
                if ($i -ge $byteArray.Length) {
                    $j = $keyBytes.Length
                }
            }
        }
    )

    $obj = PopulateObject -xordbytes $xordBytes -keyString $key

    $obj | Select-Object Key,EncryptedText,DecryptedText,Entropy,LetterFreqScore,BiGramScore,TriGramScore,TotalScore

} else {

    # Should fix keyspace to be more than just Ascii printable characters because it's weaksauce
    $keyspace   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~``!@#$%^&*()_-+={}[]\|:;`"'<>,.?/ "

    for ($j = 0; $j -lt $keyspace.Length; $j++) {
        $keyByte = GetByte $keyspace[$j]
        $xordBytes = $(
            for ($i = 0; $i -lt $byteArray.length; $i++) {
                $byteArray[$i] -bxor $keyByte
            }
        )
        
        $obj = PopulateObject -xordbytes $xordBytes -keyChar $keyspace[$j]

        if ($AllResults) {
            $obj | Select-Object Key,EncryptedText,DecryptedText,Entropy,LetterFreqScore,BiGramScore,TriGramScore,TotalScore
        } else {
            if (-not($HighScoreObj)) {
                $HighScoreObj = $obj.PSObject.Copy()
            } else {
                if ($obj.TotalScore -gt $HighScoreObj.TotalScore) {
                    $HighScoreObj = $obj.PSObject.Copy()
                }
            }
        }
    }
    if (-not($AllResults)) {
        $HighScoreObj | Select-Object Key,EncryptedText,DecryptedText,Entropy,LetterFreqScore,BiGramScore,TriGramScore,TotalScore
    }
}