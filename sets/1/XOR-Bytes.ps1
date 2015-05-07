<#
.SYNOPSIS
XOR-Bytes.ps1 takes two hexadecimal strings, converts them to byte 
arrays then XORs them against each other and returns the result as
a hexadecimal string.
This satisfies set 1, challenge 2
#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$hexString1,
    [Parameter(Mandatory=$True,Position=1)]
        [String]$hexString2
)

function ConvertHex-ToByte {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$hexString
)
    $byteString = $(if ( $hexString.Length -eq 1 ) {
        ([System.Convert]::ToByte( $hexString, 16 ))
    } elseif ( $hexString.Length % 2 -eq 0 ) {
        $hexString -split "([a-fA-F0-9]{2})" | ForEach-Object {
            if ($_) {
                [System.Convert]::ToByte( $_, 16 )
            }
        }
    })

    $byteString
}

$byteString1 = ConvertHex-ToByte $hexString1
$byteString2 = ConvertHex-ToByte $hexString2

$xordBytes = $(for ($i = 0; $i -lt $byteString1.length; $i++) {
    $byteString1[$i] -bxor $byteString2[$i]
}) 

$($xordBytes | ForEach-Object {
    [String]::Format("{0:X}", $_)
}) -join ""