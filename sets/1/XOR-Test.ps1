<#
Run 50 iterations
Generate a new key for each iteration, with the key getting longer on each iteration
Keys should consist of random bytes from 0x00 - 0xFF
XOR-Encrypt a piece of text with the key in each iteration
Run XOR-Brutr against the resulting ciphertext in an attempt to determine the key length
Output the actual key size, followed by the normal XOR-Brutr output as csv.


#>

# Here's our plaintext
if ((Get-Random -Maximum 10 -Minimum 1) % 2) {
$plaintext = @"
One morning, when Gregor Samsa woke from troubled dreams, he found
himself transformed in his bed into a horrible vermin.  He lay on
his armour-like back, and if he lifted his head a little he could
see his brown belly, slightly domed and divided by arches into stiff
sections.  The bedding was hardly able to cover it and seemed ready
to slide off any moment.  His many legs, pitifully thin compared
with the size of the rest of him, waved about helplessly as he
looked.

"What's happened to me?" he thought.  It wasn't a dream.  His room,
a proper human room although a little too small, lay peacefully
between its four familiar walls.  A collection of textile samples
lay spread out on the table - Samsa was a travelling salesman - and
above it there hung a picture that he had recently cut out of an
illustrated magazine and housed in a nice, gilded frame.  It showed
a lady fitted out with a fur hat and fur boa who sat upright,
raising a heavy fur muff that covered the whole of her lower arm
towards the viewer.

Gregor then turned to look out the window at the dull weather.
Drops of rain could be heard hitting the pane, which made him feel
quite sad.  "How about if I sleep a little bit longer and forget all
this nonsense", he thought, but that was something he was unable to
do because he was used to sleeping on his right, and in his present
state couldn't get into that position.  However hard he threw
himself onto his right, he always rolled back to where he was.  He
must have tried it a hundred times, shut his eyes so that he
wouldn't have to look at the floundering legs, and only stopped when
he began to feel a mild, dull pain there that he had never felt
before.

"Oh, God", he thought, "what a strenuous career it is that I've
chosen! Travelling day in and day out.  Doing business like this
takes much more effort than doing your own business at home, and on
top of that there's the curse of travelling, worries about making
train connections, bad and irregular food, contact with different
people all the time so that you can never get to know anyone or
become friendly with them.  It can all go to Hell!"  He felt a
slight itch up on his belly; pushed himself slowly up on his back
towards the headboard so that he could lift his head better; found
where the itch was, and saw that it was covered with lots of little
white spots which he didn't know what to make of; and when he tried
to feel the place with one of his legs he drew it quickly back
because as soon as he touched it he was overcome by a cold shudder.
"@
} else {
$plaintext = @"
The art of constructing cryptographs or ciphers—intelligible to
those who know the key and unintelligible to others—has been studied
for centuries. Their usefulness on certain occasions, especially in time
of war, is obvious, while it may be a matter of great importance to
those from whom the key is concealed to discover it. But the romance
connected with the subject, the not uncommon desire to discover a
secret, and the implied challenge to the ingenuity of all from whom the
key is hidden, have attracted to the subject the attention of many to
whom its utility is a matter of indifference.
The leading authorities on the subject, few of which are less than
a century old, are enumerated in an article by J.E. Bailey in the ninth
edition of the Encyclopaedia Britannica, and references to various historic
ciphers are there given. My knowledge of the subject, however, is
limited to ciphers which I have met with in the course of casual reading,
and I prefer to discuss the subject as it has presented itself to me,
with no attempt to make it historically complete and no reference to
other authorities. In fact the theory of the subject is not sufficiently
important to make it worth while to try to deal with it historically
or exhaustively.
Most writers use the words cryptograph and cipher as synonymous.
I employ them, however, with different meanings, which I proceed to
define.
A cryptograph may be defined as a manner of writing in which the
letters or symbols employed are used in their normal sense, but are so
arranged that the communication is intelligible only to those possessing
the key. The word is sometimes used to denote the communication
made. A simple example is a communication in which every word is
spelt backwards. Thus:
ymene deveileb ot eb gniriter troper noitisop no ssorc daor.
A cipher may be defined as a manner of writing by characters arbitrarily
invented or by an arbitrary use of letters, words, or characters
in other than their ordinary sense, intelligible only to those possessing
the key. The word is sometimes used to denote the communication
made. A simple example is when each letter is replaced by the one
that immediately follows it in the natural order of the alphabet, a being
replaced by b, b by c, and so on, and finally z by a. In this cipher
the above message would read:
fofnz cfmjfwfe up cf sfujsjoh sfqpsu qptjujpo po dsptt spbe.
In both cryptographs and ciphers the essential feature is that the
communication may be freely given to all the world though it is unintelligible
save to those who possess the key. The key must not be
accessible to anyone, and if possible it should be known only to those
using the cryptograph or cipher. The art of constructing a cryptograph
lies in the concealment of the proper order of the essential letters or
words: the art of constructing a cipher lies in concealing what letters
or words are represented by the symbols used. In an actual communication
cipher symbols may be arranged cryptographically, and thus
further hinder a reading of the message. Thus the message given above
would read in a cryptographic cipher as
znfof efwfjmfc pu fc hojsjufs uspqfs opjujtpq op ttpsd ebps.
If the message were sent in Latin or some foreign language it would
further diminish the chance of it being read by a stranger through whose
hands it passed. But I may confine myself to messages in English, and
for the present to simple cryptographs and ciphers.
"@
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

# Here's a key byte array
[byte[]]$keyArray = @()

# Convert our plaintext to a byte array
$byteArray = GetBytes -String $plaintext

if (-not($MaxSamples)) {
    $NoUserMaxSamples = $True
}

# set up our loop
for ($i = 1; $i -le 300; $i++) {
    
    [byte[]]$CipherByteArray,[byte[]]$sample,[byte[]]$keyArray = @()

    for ($j = 1; $j -le $i; $j++) {
        $keyArray += Get-Random -Minimum 0x00 -Maximum 0xFF
    }

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
    $MaxKeySize = [int]($i * 4)

    if ($MaxSamples -gt $MaxAllowableSamples) {
        Write-Verbose ("-MaxSamples of {0} was too large. Setting to {1}, ((CipherByteArray.Count / min(keysize)) - 1." -f $MaxSamples, $MaxAllowableSamples)
        $MaxSamples = $MaxAllowableSamples
    }

    if ($MaxKeySize -gt $MaxAllowableKeySize) {
        Write-Verbose ("-MaxKeySize of {0} exceeds the length of the ciphertext. Setting to {1}, [int](CipherByteArray.Count)." -f $MaxKeySize, $CipherByteArray.Count)
        $MaxKeySize = $MaxAllowableKeySize
    }

    $objs = @()

    for ($CalcKeySize = 2; $CalcKeySize -le $MaxKeySize; $CalcKeySize++) {
        $HDs = @()

        # Write-Verbose ("CalcKeySize is {0}." -f $CalcKeySize)

        if ($NoUserMaxSamples) {
            $MaxSamples = (($CipherByteArray.Count / $CalcKeySize) - 1)
        }

        for ($a = 0; $a -lt $MaxSamples; $a++) {
            $Start = $CalcKeySize * $a
            $End   = $CalcKeySize * ($a + 1)
            # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
            if ($End -gt $CipherByteCount) {
                # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
                continue
            }
            $ByteArray1 = $CipherByteArray[$Start..$End]
            $Start = $End
            $End   = $CalcKeySize * ($a * 2)
            # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
            if ($End -gt $CipherByteCount) {
                # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
                continue
            }
            $ByteArray2 = $CipherByteArray[$Start..$End]
            if ($ByteArray1.Count -eq $ByteArray2.Count) {
                $HDs += ((GetHammingDistance $ByteArray1 $ByteArray2) / $CalcKeySize)
            }
        }
        if ($HDs) {
            $AvgDist = $HDs | Measure-Object -Average | Select-Object -ExpandProperty Average
            $obj = "" | Select-Object KeySize,CalcKeySize,AvgDist,GCD
            $obj.KeySize = $i
            $obj.CalcKeySize = $CalcKeySize
            $obj.AvgDist = $AvgDist
            $obj.GCD = 1
            $objs += $obj
            $NoUserMaxSamples = $True
        }
    }

    $a,$gcd = 1

   
    <# for ($b = 0; $b -lt $objs.Count; $b++) {
        $objs[$b]
        $temp = GetGreatestCommonDenominator $objs[0].CalcKeySize $objs[$b].CalcKeySize
        Write-Verbose ("GCD of {0} and {1} is {2}." -f $objs[$b].CalcKeySize, $objs[($b+1)].CalcKeySize, $temp)
        if ($objs[$b].GCD -lt $temp) {
            $objs[$b].GCD = $temp
        }        
    }
    #>

    $objs | sort AvgDist | ForEach-Object {
        $obj = "" | Select-Object KeySize,Rank,RankCalcKeySizeRatio,CalcKeySize,AvgDist,Total
        $obj.KeySize = $_.KeySize
        $obj.Rank = $a
        $obj.RankCalcKeySizeRatio = $_.CalcKeySize / $a
        $obj.CalcKeySize = $_.CalcKeySize
        $obj.AvgDist = $_.AvgDist
        # $obj.GCD = $_.GCD
        $obj.Total = (($obj.CalcKeySize * $obj.Rank) + $obj.RankCalcKeySizeRatio) * $obj.AvgDist
        $obj | Select-Object KeySize,CalcKeySize,Rank,RankCalcKeySizeRatio,AvgDist,Total
        $a++
    } | Sort-Object Total # | Select-Object -First 5
}