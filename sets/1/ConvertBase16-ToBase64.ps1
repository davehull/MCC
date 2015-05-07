<#
.SYNOPSIS
hex2base64.ps1 takes a hexadecimal string and returns a base64 encoded
string.
#>


[CmdletBinding()]
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

[System.Convert]::ToBase64String($byteString)