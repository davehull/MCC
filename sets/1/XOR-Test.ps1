<#
Run MaxKeySize iterations
Generate a new key for each iteration, with the key getting longer on each iteration
Keys should consist of random bytes from 0x00 - 0xFF
XOR-Encrypt a piece of text with the key in each iteration
Run XOR-Brutr against the resulting ciphertext in an attempt to determine the key length
Output the actual key size and probable key sizes based on normalized Hamming Distance
and greatest common denominator calculation of first three probable key siszes
#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [int]$MaxKeySize=10,
    [Parameter(Mandatory=$True,Position=1)]
        [int]$MinKeySize=2,
    [Parameter(Mandatory=$False,Position=2)]
        [float]$MaxNAvgHD=3.5,
    [Parameter(Mandatory=$False,Position=3)]
        [int]$MaxSamples,
    [Parameter(Mandatory=$False,Position=4)]
        [int]$top=5
)



function GetPlaintextOld {
    # Here's our plaintext
    switch (Get-Random -Maximum 11 -Minimum 1) {
        1 {
$plaintext = @"
Abstract 

We develop a framework for analyzing the strengths and weaknesses 
of firms engaged in providing services, synthesizing and building on the 
literature addressing service operations. First, we summarize the 
distinguishing characteristics of service products, as compared to 
manufactured goods. We then partition the context in which firms operate 
into three segments. The external environment encompasses product 
definition and differentiation, as well as competitive forces. The internal 
environment concerns issues similar to those in traditional management of 
manufacturing operations. The customer interface is the most critical 
segment, representing the service firm's "moment of truth." We discuss 
each environment in turn. 



L Introduction 

The service sector has become an important part of the world 
economy over the past several decades, as manufacturings share of total 
employment and output has fallen dramatically. ^ Furthermore, service 
has become an important feature of manufactured products; repair and 
maintenance, sales, and training are examples of services that enhance 
and differentiate manufactured products. Today, there are very few firms 
that do not view providing service as part of their strategy. In this paper, 
we develop a framework for analyzing the strengths and weaknesses of 
service operations. There is a growing body of literature focusing on 
management of operations in service firms, and we use this work as 
fundamental building blocks in creating a unified framework. We begin by 
partitioning the context in which a firm operates into three segments: the 
external environment, the internal environment, and the customer 
interface. We then summarize the characteristics that distinguish service 
products from manufactured products. These characteristics will be our 
focus for the three remaining sections of the paper, in which we discuss 
each segment in depth. 

EL The Framework 

It is useful to classify the questions that we address according to the 
environments to which they pertain. Figure 1 illustrates this basic 
framework. 2 Although it can not capture all of the complexity of the firm's 
environment, the framework presents a way of thinking about the 
relationships between the major functions and participants in service 
operations.
"@
} 
        2 {
$plaintext = @"
This Investigation Report summarizes the results of studies undertaken to characterize the 
extent of soil and groundwater contamination at the Former A Range on the Massachusetts 
Military Reservation (MMR). The Former A Range Investigation was conducted under 
U.S. Environmental Protection Agency Safe Drinking Water Act Administrative Orders SDWA 
1-97-1019 and SDWA 1-2000-0014, and in consideration of the substantive cleanup standards 
of the Massachusetts Contingency Plan (MCP). 

The Former A Range (also known as the Gravity Anti-Tank Range) is an inactive anti-tank 
artillery and rocket practice range. It is located to the west of the Camp Edwards Impact Area in 
the southern portion of Training Area B-9. Wood Road and Training Area B-8 lie to the 
immediate south. The range was originally constructed in 1941 and functioned as an anti-tank 
artillery and rocket site until the 1960s. A prominent feature of the range was the gravity 
propelled movement of cars along a short downhill rail line to provide moving targets. During the 
early 1960s to the mid-1970s, the range was used for machine gun practice. 

Groundwater monitoring data for four wells on the range indicate the presence of trace levels of 
a few explosives-related compounds. 2,4,6-trinitrotoluene (TNT) and two of its degradation 
products 2-amino-4,6-dinitrotoluene (2A-DNT) and 4-amino-2,6-dinitrotoluene (4A-DNT) were 
observed at low concentrations (<1.0 microgram per liter [|ig/L]) in one well (MW-249M3) 
downgradient of the target area, although not in well MW-206S immediately beneath the target 
area. The explosives compounds hexahydro-1,3,5-trinitro-1,3,5-triazine (RDX) and 1,3,5- 
trinitrobenzene were also detected once in MW-249M3 at concentrations of 0.31 J |ig/L and 
0.33J |ig/L, respectively. 

Overall investigation results indicate that the principal contaminants detected in soils at the 
range are explosives, semivolatile organic compounds (SVOCs), and metals. These 
contaminants are primarily observed in the target area of the range. Detections of these 
contaminants were sporadic. Explosives, SVOCs, and/or metals contaminants in soils are co- 
located at some but not all sampling locations. 

Explosives compounds were detected in a limited number of surface and shallow subsurface 
soil samples located throughout the target area. The principal explosives that were observed 
include TNT and its degradation products, 2A-DNT and 4A-DNT. The highest reported TNT 
concentration (9 milligrams per kilogram [mg/Kg]) was observed in the backstop berm portions 
of the target area. The highest levels of 2A-DNT (6.8 mg/Kg) and 4A-DNT (2.4 mg/Kg) were 
reported in the lower berm portions of the target area. Explosives compounds were detected 
infrequently and at low concentrations in soil samples located outside the target area berms. 
Semivolatile polycyclic aromatic hydrocarbon (PAH) compounds were also detected 
sporadically at several locations within the target area. However, most of the higher observed 
PAH concentrations were clustered in surface and shallow subsurface soils along portions of 
the rail line. Maximum observed values of most of the more frequently detected PAHs, including 
fluoranthene (47 mg/Kg), phenanthrene (45 mg/Kg), and pyrene (40 mg/Kg), were all detected 
at various surface soil locations along the rail line. 
"@
}
        3 {
$plaintext = @"
Two minor matters require a brief reference. The 
illustrations of historical subjects are not inserted as 
" pictures,' but with the prosaic and utilitarian object of 
conveying some idea of the marine architecture of the 
period, the conditions of naval warfare at that period, 
and occasionally the meteorological conditions during 



PREFACE II 

the battle also. It will be noted that where modern 
ships are illustrated they are, where possible, rejjro- 
duced from photographs. When otherwise, they are 
in each case drawn either from my own sketches of 
the actual ships or from photographs that did not 
lend themselves to direct reproduction. 

As everyone has his own rendering of Russian 
spelling, and as of many ships several widely different 
spellings are in existence, the more popular forms of 
spelling are here and there adopted. As a general rule, 
however, the correct more or less phonetic spelling 
suitable for the English language is also introduced. 

The name Ksenia — Xenia, or Zenia — is a case in 
point, the first being a Russian spelling, the last an 
English adaption. When possible the phonetic sound 
is indicated by the use of accents over the vowels 
in order to avoid an ugly appearance. Rossia and 
Sevastopol are names in point. 

The matter is not one of supreme importance, and 
is only drawn attention to because in a number of 
cases the usual English pronunciation bears no relation 
at all to the Russian one. When such a simple name 
as Rossia is s]3elt in English (as it occasionally is) 
" Rossija," and recklessly pronounced " Rossyjar," one 
may well acquit the Russian officer who told an 
Englishman that they had no such ship in their 
Navy. 

The substance of the chapter on Anglo-Russian 
relations, though some definite alterations have since 
been made, appeared serially in the Daily Chronicle,
"@
}
        4 {
$plaintext = @"
The international security research community has greatly contributed to our understanding of computer security over the last 20+ years. Highly international speaker line-ups are the norm, and cooperation between people from different nations and continents is the norm
rather than the exception.
"@
}
        5 {
$plaintext = @"
Once upon a time and a very good time it was there was 
a moocow coming down along the road and this moocow 
that was down along the road met a nicens little boy 
named baby tuckoo. . , . 

His father told him that story : his father looked at him 
through a glass : he had a hairy face. 

He was baby tuckoo. The moocow came down the road 
where Betty Byrne lived : she sold lemon platt. 

0, the mid rose blossoms 
On the little green place. 

He sang that song. That was his song. 

0, the green wothe hotheth. 

When you wet the bed, first it is warm then it gets 
cold. Ilis mother put on the oilsheet. That had the 
queer smell. 

His mother had a nicer smell than his father. She 

[1] 



played on the piano the sailor's hornpipe for him to 
dance. He danced: 

Tralala lala, 
Tralala iralaladdy, 
Tralala lala, 
Tralala lala. 

Uncle Charles and Dante clapped. They were older 
than his father and mother but Uncle Charles was older 
than Dante. 

Dante had two brushes in her press. The brush with 
the maroon velvet back was for Michael Davitt and the 
brush with the green velvet back was for Parnell. Dante 
gave him a cachou every time he brought her a piece of 
tissue paper. 

The Vances lived in number seven. They had a dif- 
ferent father and mother. They were Eileen's father 
and mother. When they were grown up he was going to 
marry Eileen. He hid under the table. His mother said : 

— 0, Stephen will apologise. 
Dante said: 

— 0, if not, the eagles will come and pull out his 
eyes. — : 

Pull out his eyes, 

Apologise, 

Apologise, 

Pull out his eyes. 

Apologise, 
Pull out his eyes, 
Pull out his eyes. 
Apologise. 

TP W w * 

12] 
"@
}
        6 {
$plaintext = @"
Fourth Method^. Ask some one to select a number less 
than 90. Request him to perform the following operations, 
(i) To multiply it by 10, and to add any number he pleases, 
a, which is less than 10. (ii) To divide the result of step (i) 
by 3, and to mention the remainder, say, b. (iii) To multiply 
the quotient obtained in step (ii) by 10, and to add any number 
he pleases, c, which is less than 10. (iv) To divide the result 
of step (iii) by 3, and to mention the remainder, say d, and 
the third digit (from the right) of the quotient; suppose 
this digit is e. Then, if the numbers a, b, c, d, e are known, 
the original number can be at once determined. In fact, if 
the number is 9% + y, where x %■ 9 and y rf- 8, and if r is the 

• Bachet, problem v, p. 80. 

t Educational Times, London, May 1, 1895, vol. XLvin, p. 234. This example 
is said to have been made up by J. Clerk Maxwell in his boyhood: it is in- 
teresting to note how widely it differs from the simple Bachet problems pre- 
viously mentioned. 



6 ARITHMETICAL RECREATIONS [CH I 

remainder when a - b + 3 (c - d) is divided by 9, we have 
x = e, y = 9 — r. 

The demonstration is not difficult. Suppose the selected num- 
ber is 9a; + y. Step (i) gives 90a: + lOy + a. Let y + a = 3n + b, 
then the quotient obtained in step (ii) is 30x + 2y + n. Step 
(in) gives 300a; + 30y + 10n, + c. Let n + c = 3m + d, then the 
quotient obtained in step (iv) is 100a; + lOy + 3n + m, which I 
will denote by Q. Now the third digit in Q must be x, because, 
since y if- 8 and a $■ 9, we have n ^ 5 ; and since n^-5 and c ^ 9, 
we have m ^ 4 ; therefore lOy + 3n + m $■ 99. Hence the third 
or hundreds digit in Q is x. 

Again, from the relations y + a = 3w + b and n + c = 3m + d, 
we have 9m — y = a-b + 3(c — d): hence, if r is the remainder 
when a — b + 3 (c — d) is divided by 9, we have y = 9 — r. [This 
is always true, if we make r positive ; but if a — b + 3 (c — d) 
is negative, it is simpler to take y as equal to its numerical 
value ; or we may prevent the occurrence of this case by 
assigning proper values to a and c.J Thus x and y are both 
known, and therefore the number selected, namely 9x + y, is 
known. 

Fifth Method*. Ask any one to select a number less 
than 60. Eequest him to perform the following operations, 
(i) To divide it by 3 and mention the remainder ; suppose it 
to be a. (ii) To divide it by 4, and mention the remainder; 
suppose it to be b. (iii) To divide it by 5, and mention the 
remainder; suppose it to be c. Then the number selected is 
the remainder obtained by dividing 40a + 456 + 36c by 60. 

This method can be generalized and then will apply to any 
number chosen. Let a', 6', c', ... be a series of numbers prime 
to one another, and let p be their product. Let n be any 
number less than p, and let a, b, c, ... be the remainders 
when n is divided by a, b', c', . . . respectively. Find a number 
A which is a multiple of the product b'c'd' . . . and which 
exceeds by unity a multiple of a'. Find a number B which is 
a multiple of a'c'd' ... and which exceeds by unity a multiple 

* Bachet, problem vi, p. 84 : Bachet added, on p. 87, a note on the previous 
history of the problem.
"@
}
        7 {
$plaintext = @"
F. MESSAGE BIT INDEPENDENT INSERTION PROTOCOLS 

The protocols in the previous section require the receiver to have both the original 
wrapper file and the stegotext to extract the message. This is because the insertion point 
bit(s) are selected based on the value of the message bit. Therefore the only way for the 
receiver to identify the insertion points is to compare the wrapper with the stegotext. This 
is entirely different from the key- or algorithm-based protocol event selection techniques 
mentioned earlier. 

Frequently, it is inconvenient or impossible for the receiver to have the original 
wrapper file. For example, in an image downgrading scenario, it is possible for a misfeasor 
to embed classified data in an image which he expects to be downgraded. Once the wrapper 
image is downgraded, the original wrapper file is no longer available to be used for 
comparison in an extraction algorithm For this reason, when designing a steganographic 
"@
}
        8 {
$plaintext = @"
Alice was beginning to get very tired of sitting by her sister on the
bank, and of having nothing to do: once or twice she had peeped into the
book her sister was reading, but it had no pictures or conversations in
it, 'and what is the use of a book,' thought Alice 'without pictures or
conversations?'
"@
}
        9 {
$plaintext = @"
TOWARD the end of the year 1811, a tremendous armament 
and concentration of forces took place in Western Europe ; 
and in 1812, these forces millions of men, counting those 
who were concerned in the transport and victualling of the 
armies were moved from west to east toward the borders of 
Russia, where the Russian forces were drawn up just as they 
had been the year before.
"@
}
        10 {
$plaintext = @"
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
"@
        }
        11 {
            $plaintext = @"
In computer science, the Aho–Corasick string matching algorithm is a string searching algorithm invented by Alfred V. Aho and Margaret J. Corasick.[1] It is a kind of dictionary-matching algorithm that locates elements of a finite set of strings (the "dictionary") within an input text. It matches all patterns simultaneously. The complexity of the algorithm is linear in the length of the patterns plus the length of the searched text plus the number of output matches. Note that because all matches are found, there can be a quadratic number of matches if every substring matches (e.g. dictionary = a, aa, aaa, aaaa and input string is aaaa).
"@
        }
    }
    $plaintext
}

function GetPlainText {
    Begin {
        $files = @()
        $files = ls ${pwd}\texts\*.txt
    }

    Process {
        # Randomly pick a book
        $BookNum = Get-Random -Minimum 0 -Maximum $files.Count

        # Get its content
        $Content = Get-Content $files[$BookNum] | ? { $_ }
        
        # Get a random number of lines in the range of 0..(($Content.Length)-80)
        $Start = Get-Random -Minimum 0 -Maximum (($Content.Length)-80)
        $End   = Get-Random -Minimum $Start -Maximum (Get-Random -Minimum ($Start + 1) -Maximum ($Start + 78))
        $Content[$Start..$End] -join "" | Out-String
    }

    End {}
}

function GetBits {
Param(
    [Parameter(Mandatory=$True,Position=0,ValueFromPipeLine=$True)]
        [byte]$byte
)
    [System.Convert]::ToString($byte,2).PadLeft(8,'0') 
}

function GetBytes {
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [String]$String
)
    [System.Text.Encoding]::Default.GetBytes($String)
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

if (-not($MaxSamples)) {
    $NoUserMaxSamples = $True
} else {
    $NoUserMaxSamples = $False
}

$BytePairDist = @{}

# In the outter loop here we encrypt our plaintext with a randomly generated key
for ($i = $MinKeySize; $i -le $MaxKeySize ; $i++) {

    # Here's a key byte array
    [byte[]]$keyArray = @()

    # Convert our plaintext to a byte array
    $plaintext = GetPlaintext
    
    $byteArray = GetBytes -String $plaintext
    
    [byte[]]$CipherByteArray,[byte[]]$sample,[byte[]]$keyArray = @()

    for ($j = 1; $j -le $i; $j++) {
        $keyArray += Get-Random -Minimum 0x00 -Maximum 0xFF 
        # $keyArray += Get-Random -Minimum 0x20 -Maximum 0x7F # ASCII printables are in 0x20 - 0x7F
    }
    # Write-Verbose ("KeyArray is {0}" -f ($keyArray -join ":"))

    $CipherByteArray = $(
        for ($q = 0; $q -lt $byteArray.Count; ) {
            for ($k = 0; $k -lt $keyArray.Count; $k++) {
                $byteArray[$q] -bxor $keyArray[$k]
                $q++
                if ($q -ge $byteArray.Length) {
                    $k = $keyArray.Count
                }
            }
        }
    )    

    $CipherByteCount = $CipherByteArray.Count
    $MaxAllowableSamples = [int]($CipherByteCount / 2) - 1
    $MaxAllowableKeySize = [int]($CipherByteCount)
    $MaxCalcKeySize = [int]($i * 4)

    if ($MaxSamples -gt $MaxAllowableSamples) {
        Write-Verbose ("-MaxSamples of {0} was too large. Setting to {1}, ((CipherByteArray.Count / min(keysize)) - 1." -f $MaxSamples, $MaxAllowableSamples)
        $MaxSamples = $MaxAllowableSamples
    }

    if ($MaxCalcKeySize -gt $MaxAllowableKeySize) {
        Write-Verbose ("-MaxKeySize of {0} exceeds the length of the ciphertext. Setting to {1}, [int](CipherByteArray.Count)." -f $MaxKeySize, $CipherByteArray.Count)
        $MaxCalcKeySize = $MaxAllowableKeySize
    }

    $objs = @()

    # The inner loop here uses Hamming Distance to determine probably key size
    for ($CalcKeySize = 2; $CalcKeySize -le $MaxCalcKeySize; $CalcKeySize++) {
        $HDs = @()

        # Write-Verbose ("CalcKeySize is {0}." -f $CalcKeySize)

        if ($NoUserMaxSamples) {
            $MaxSamples = (($CipherByteArray.Count / $CalcKeySize) - 1)
        }

        # Write-Verbose ("MaxSamples is {0}" -f $MaxSamples)
        for ($a = 0; $a -lt $MaxSamples; $a++) {
            $Start = (($CalcKeySize - 1) * $a) + $a
            $End   = (($CalcKeySize - 1) * ($a + 1) + $a)
            # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
            if ($End -gt $CipherByteCount) {
                # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
                # continue
            }
            $ByteArray1 = $CipherByteArray[$Start..$End]
            $Start = $End + 1
            $End   = (($CalcKeySize - 1) * ($a + 2) + 1) + $a
            # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
            if ($End -gt $CipherByteCount) {
                # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
                # continue
            }
            $ByteArray2 = $CipherByteArray[$Start..$End]
            if ($ByteArray1.Count -eq $ByteArray2.Count) {
                $HDs += ((GetHammingDistance $ByteArray1 $ByteArray2 $BytePairDist))
                # Write-Verbose ("HDs : {0}, Normalized : {1}, ByteArray1 : {2}, ByteArray2 : {3}" -f $HDs[$a], ($HDs[$a] / $ByteArray1.Count), ($ByteArray1 -join ","), ($ByteArray2 -join ",")) 
                # Write-Verbose ("ByteArrays are: {0} and {1}" -f ($ByteArray1 -join ":"), ($ByteArray2 -join ":"))
                # if (($HDs.Count % 450) -eq 0) { Write-Verbose ("HDs is {0}. ByteArray.Count is {1}" -f ($HDs -join ","), $ByteArray1.Count) }
            }
        }
        if ($HDs) {
            $AvgHD = ($HDs | Measure-Object -Average | Select-Object -ExpandProperty Average)
            $NAvgHD = $AvgHD / $CalcKeySize
            $obj = "" | Select-Object KeySize,CalcKeySize,AvgHD,NAvgHD
            $obj.KeySize = $i
            $obj.CalcKeySize = $CalcKeySize
            $obj.AvgHD = $AvgHD
            $obj.NAvgHD = $NAvgHD
            $objs += $obj
        }
    }

    $TopObjs = $objs | Sort-Object NAvgHD | Select-Object -First $top

    <#
    $a = 1
    $AvgHDSortObj = @()
 
    # Sort objects on average Hamming Distance, set AvgHDRank and
    # populate new object array, $AvgHDSortObj
    $objs | sort AvgHD | ForEach-Object {
        $obj = "" | Select-Object KeySize,AvgHDRank,CalcKeySize,AvgHD,NAvgHD
        $obj.KeySize = $_.KeySize
        $obj.AvgHDRank = $a
        $obj.CalcKeySize = $_.CalcKeySize
        $obj.AvgHD = $_.AvgHD
        $obj.NAvgHD = $_.NAvgHD
        $a++
        $AvgHDSortObj += $obj
    }

    $objs = @()
    $a = 1

    $TopObjs = ($AvgHDSortObj | sort NAvgHD | ForEach-Object {
        $obj = "" | Select-Object KeySize,AvgHDRank,NAvgHDRank,CalcKeySize,AvgHD,NAvgHD
        $obj.Keysize = $_.KeySize
        $obj.AvgHDRank = $_.AvgHDRank
        $obj.NAvgHDRank = $a
        $obj.CalcKeySize = $_.CalcKeySize
        $obj.AvgHD = $_.AvgHD
        $obj.NAvgHD = $_.NAvgHD
        $a++
        $obj | Select-Object KeySize,CalcKeySize,NAvgHDRank,NAvgHD
    } | ? { $_.NAvgHDRank -le 6 })
    #>

    $GCDs = @{}
    $obj = "" | Select-Object ActualKeySize,ProbableKeySize,Top${top}KeySizes,Top${top}NAvgHDs,GCD,PlainText,Key

    <#
    $TopObjs.CalcKeySize | ForEach-Object {
        if ($GCDs.Contains($_)) {
            $GCDs.set_item($_, $GCDs[$_] + 1)
        } else {
            $GCDs.Add($_, 1)
        }
    }
    #>

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
        $obj.ActualKeySize = $TopObjs[$p].KeySize
        $obj.ProbableKeySize = $ProbableKeySize
        $obj."Top${top}KeySizes" = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
        $obj."Top${top}NAvgHDs" = $TopObjs[0..($TopObjs.Count - 1)].NAvgHD -join " : "
        $obj.PlainText = $plaintext
        $obj.Key = $keyArray -join ":"
        $obj | Select-Object ActualKeySize,ProbableKeySize,Top${top}KeySizes,Top${top}NAvgHDs,PlainText,Key
        break

<#
        $gcd12 = (GetGreatestCommonDenominator -val1 ($TopObjs[$p].CalcKeySize) -val2 ($TopObjs[$p + 1].CalcKeySize))
        $gcd13 = (GetGreatestCommonDenominator -val1 ($TopObjs[$p].CalcKeySize) -val2 ($TopObjs[$p + 2].CalcKeySize))
        $gcd23 = (GetGreatestCommonDenominator -val1 ($TopObjs[$p + 1].CalcKeySize) -val2 ($TopObjs[$p + 2].CalcKeySize))

        if ($gcd12 -ne 1) {
            if ($gcd12 -eq $gcd13 -eq $gcd23) {
                if (($TopObjs[0..($TopObjs.Count - 1)].CalcKeySize).Contains($gcd12)) {
                    $ProbableKeySize = $gcd12
                }
            } elseif (($gcd12 -eq $gcd23) -and ($gcd23 -ne 1) -and (($TopObjs[0..($TopObjs.Count - 1)].CalcKeySize).Contains($gcd23))) {
                $ProbableKeySize = $gcd23
            } elseif (($gcd13 -eq $gcd23) -and ($gcd13 -ne 1) -and (($TopObjs[0..($TopObjs.Count - 1)].CalcKeySize).Contains($gcd23))) {
                $ProbableKeySize = $gcd23
            } elseif (($TopObjs[0..($TopObjs.Count - 1)].CalcKeySize).Contains($gcd12)) {
                $ProbableKeySize = $gcd12
            } else {
                $ProbableKeySize = ($TopObjs[0].CalcKeySize)
            }
            $obj.ActualKeySize = $TopObjs[$p].KeySize
            $obj.ProbableKeySize = $ProbableKeySize
            $obj."Top${top}KeySizes" = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
            $obj.PlainText = $plaintext
            $obj.Key = $keyArray -join ":"
            $obj | Select-Object ActualKeySize,ProbableKeySize,Top${top}KeySizes,PlainText,Key
            break
        } else {
            $obj.ActualKeySize = $TopObjs[$p].KeySize
            $obj.ProbableKeySize = ("{0} uncertain" -f ($TopObjs[$p].CalcKeySize))
            $obj."Top${top}KeySizes" = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
            $obj.PlainText = $plaintext
            $obj.Key = $keyArray -join ":"
            $obj | Select-Object ActualKeySize,ProbableKeySize,Top${top}KeySizes,PlainText,Key
            break
        }

<#
        if (($gcd12 -ne 1) -and (($TopObjs[0..($TopObjs.Count - 1)].CalcKeySize).Contains($gcd12)) -and (($gcd12 -eq $gcd13 -eq $gcd23) -or ($gcd12 -eq $TopObjs[$p].CalcKeySize) -or ($gcd12 -eq $TopObjs[$p + 1].CalcKeySize))) {
            $obj.ActualKeySize = $TopObjs[$p].KeySize
            $obj.ProbableKeySize = $gcd12
            $obj."Top${top}KeySizes" = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
            $obj.PlainText = $plaintext
            $obj.Key = $keyArray -join ":"
            $obj | Select-Object ActualKeySize,ProbableKeySize,Top${top}KeySizes,PlainText,Key
            break
        } else {
            $obj.ActualKeySize = $TopObjs[$p].KeySize
            $obj.ProbableKeySize = ("{0} uncertain" -f ($TopObjs[$p].CalcKeySize))
            $obj."Top${top}KeySizes" = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
            $obj.PlainText = $plaintext
            $obj.Key = $keyArray -join ":"
            $obj | Select-Object ActualKeySize,ProbableKeySize,Top${top}KeySizes,PlainText,Key
            break
        }
#>
        # Write-Verbose ("KeySize is {0}, GCD is {3}, CalcKeySize is {1}, next CalcKeySize is {2}" -f $TopObjs[$p].KeySize, $TopObjs[$p].CalcKeySize, $TopObjs[$p + 1].CalcKeySize, $gcd)
    }
}