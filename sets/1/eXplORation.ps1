[CmdletBinding()]

Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$String,
    [Parameter(Mandatory=$False,Position=1)]
        [String]$key
)

function ValidateKey
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [String]$key,
        [Parameter(Mandatory=$True,Position=0)]
            [Int]$StringLength
    )
    # key length must be less than half $StringLength or it can't fully repeat
    if (($key.length * 2) -le $StringLength)
    {
        return $True
    }
    else 
    {
        return $False    
    }
}

function ConvertStringTo-BitArray
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [String]$String
    )
    # Takes a string as input and converts it to an array of bits
    $ByteLength = 8
    $BitArray = New-Object 'string[]' ($String.Length * $byteLength)
    for ($i = 0; $i -lt $String.length; $i++) 
    {
        $BitArray[$i] = [System.Convert]::ToString([byte][char]$String[$i],2).PadLeft(8,'0')
    }
    $BitArray
}

function CreateKey
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [String]$StringLength
    )
    if ($StringLength -gt 1)
    {
        $key = @()
        $KeyLength = Get-Random -Maximum ([Math]::Truncate($StringLength / 2))
        for ($i = 0; $i -lt $KeyLength; $i++)
        {
            $key += [char](Get-Random -Minimum 32 -Maximum 126)
        }
    }
    $key -join ''
}


function GetRepeatingKey
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [String]$Key,
        [Parameter(Mandatory=$True,Position=1)]
            [Int]$StringLength
    )
    # Return the key repeated as many times a needed to equal StringLength
    # If the string length is 9 and the key is 3, the key should repeat three x
    $KeyRepetitions = ($StringLength / $Key.Length) + 1
    $RepeatedKey = $Key * $KeyRepetitions
    $RepeatedKey.Substring(0,$StringLength)
}


function GetBytes 
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [String]$String
    )
    # Takes a string of characters and returns an array of bytes
    # Example: GetBytes "ABC" returns @(65,66,67)
    [System.Text.Encoding]::Default.GetBytes($string)
}


function GetXORdBits
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [Array]$StringBytes,
        [Parameter(Mandatory=$True,Position=1)]
            [Array]$KeyBytes
    )
    $(
        for ($i = 0; $i -lt $StringBytes.Length) {
            for ($j = 0; $j -lt $KeyBytes.Length; $j++) {
                # We'll repeat the key until we reach ciphertext's end
                $StringBytes[$i] -bxor $KeyBytes[$j]
                $i++
                if ($i -ge $StringBytes.Length) {
                    # We've reached the end of the ciphertext, exit loop
                    $j = $KeyBytes.Length
                }
            }
        }
    )
}


function ConvertBytesTo-String
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [Array]$ByteArray
    )
    $(
        foreach($byte in $ByteArray) {
            [Char]$byte
        }
    ) -join ''
}


function CountOnes
{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [String]$BitString
    )
    $OnesCount = 0
    for ($i = 0; $i -lt $BitString.Length; $i++)
    {
        if ($BitString[$i] -eq '1')
        {
            $OnesCount++
        }
    }
    $OnesCount
}


function FormatOutput{
    Param(
        [Parameter(Mandatory=$True,Position=0)]
            [PSObject]$String,
        [Parameter(Mandatory=$True,Position=1)]
            [PSObject]$StringBits,
        [Parameter(Mandatory=$True,Position=2)]
            [PSObject]$RepeatingKeyBits,
        [Parameter(Mandatory=$True,Position=3)]
            [PSObject]$XorBits,
        [Parameter(Mandatory=$False,Position=4)]
            [Int]$Cols=10
    )
    $ByteSize = 8
    $StringBitsLength       = $StringBits.Length
    $RepeatingKeyBitsLength = $RepeatingKeyBits.Length
    $XorBitsLength          = $XorBits.Length
    $TotalBytes             = $StringBitsLength / $ByteSize
    $OutputLineCount        = ([Math]::Ceiling($TotalBytesOut / $Cols))

    $BytesOut = 0
    While ($BytesOut -lt $TotalBytes)
    {
        $(for ($i = $BytesOut; $i -lt $Cols + $BytesOut; $i++)
        {
            [System.Convert]::ToString($String[$i]).PadRight(8,' ')
        }) -join ' '
        $StringBits[$BytesOut..($BytesOut + $Cols - 1)] -join ' '
        $(for ($i = $BytesOut; $i -lt $Cols + $BytesOut; $i++)
        {
            [System.Convert]::ToString($RepeatingKey[$i]).PadRight(8,' ')
        }) -join ' '
        $RepeatingKeyBits[$BytesOut..($BytesOut + $Cols - 1)] -join ' '
        $XorBits[$BytesOut..($BytesOut + $Cols - 1)] -join ' '
        $BytesOut += $Cols
        ' '
    }    
}


$error.clear()

if ([string]::IsNullOrEmpty($key))
{
    Write-Host 'No key. Generating one.'
    $key = CreateKey -StringLength $String.Length
    $IsValidKey = $True
}
else 
{
    $IsValidKey = ValidateKey -key $key -StringLength $String.Length    
}

if (-not $IsValidKey)
{
    Write-Host 'Invalid key. Generating one.'
    $key = CreateKey -StringLength $String.Length
}

$StringBits       = ConvertStringTo-BitArray -String $String
$KeyBits          = ConvertStringTo-BitArray -String $key
$RepeatingKey     = GetRepeatingKey -Key $key -StringLength $String.Length
$RepeatingKeyBits = ConvertStringTo-BitArray $RepeatingKey
$StringBytes      = GetBytes -String $String
$KeyBytes         = GetBytes -String $Key
$XorResult        = GetXORdBits -StringBytes $StringBytes -KeyBytes $KeyBytes
$XorString        = ConvertBytesTo-String -ByteArray $XorResult
$XorBits          = ConvertStringTo-BitArray -String $XorString

<#
Write-Output ('Key: ''{0}''' -f $key)
Write-Output ('Bits: {0}' -f ($KeyBits -join ' '))
Write-Output ('Input string: ''{0}''' -f $String)
Write-Output ('Repeated key: ''{0}''' -f $RepeatingKey)
Write-Output ('String bits: {0}' -f ($StringBits -join ' ').Trim())
Write-Output ('Key bits:    {0}' -f ($RepeatingKeyBits -join ' ').Trim())
Write-Output ('XOR:         {0}' -f ($XorBits -join ' ').Trim())
#>

FormatOutput -String $String -StringBits $StringBits -RepeatingKeyBits $RepeatingKeyBits -XorBits $XorBits -Cols $Key.Length