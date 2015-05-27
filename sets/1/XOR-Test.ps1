<#
Run 50 iterations
Generate a new key for each iteration, with the key getting longer on each iteration
Keys should consist of random bytes from 0x00 - 0xFF
XOR-Encrypt a piece of text with the key in each iteration
Run XOR-Brutr against the resulting ciphertext in an attempt to determine the key length
Output the actual key size, followed by the normal XOR-Brutr output as csv.


#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=0)]
        [int]$MaxKeySize=10,
    [Parameter(Mandatory=$False,Position=1)]
        [int]$MaxSamples,
    [Parameter(Mandatory=$False,Position=2)]
        [int]$top=5
)



function GetPlaintext {
    # Here's our plaintext
    switch (Get-Random -Maximum 10 -Minimum 1) {
        1 {
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
} 
        2 {
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
        3 {
$plaintext = @"
Suzanne Church almost never had to bother with the blue blazer these
days. Back at the height of the dot-boom, she'd put on her business
journalist drag -- blazer, blue sailcloth shirt, khaki trousers,
loafers -- just about every day, putting in her obligatory appearances
at splashy press-conferences for high-flying IPOs and mergers. These
days, it was mostly work at home or one day a week at the San Jose
Mercury News's office, in comfortable light sweaters with loose necks
and loose cotton pants that she could wear straight to yoga after
shutting her computer's lid.

Blue blazer today, and she wasn't the only one. There was Reedy from
the NYT's Silicon Valley office, and Tribbey from the WSJ, and that
despicable rat-toothed jumped-up gossip columnist from one of the UK
tech-rags, and many others besides. Old home week, blue blazers fresh
from the dry-cleaning bags that had guarded them since the last time
the NASDAQ broke 5,000.

The man of the hour was Landon Kettlewell -- the kind of outlandish
prep-school name that always seemed a little made up to her -- the new
CEO and front for the majority owners of Kodak/Duracell. The
despicable Brit had already started calling them Kodacell. Buying the
company was pure Kettlewell: shrewd, weird, and ethical in a twisted
way.

"Why the hell have you done this, Landon?" Kettlewell asked himself
into his tie-mic. Ties and suits for the new Kodacell execs in the
room, like surfers playing dress-up. "Why buy two dinosaurs and stick
'em together? Will they mate and give birth to a new generation of
less-endangered dinosaurs?"

He shook his head and walked to a different part of the stage,
thumbing a PowerPoint remote that advanced his slide on the jumbotron
to a picture of a couple of unhappy cartoon brontos staring desolately
at an empty nest. "Probably not. But there is a good case for what
we've just done, and with your indulgence, I'm going to lay it out for
you now."

"Let's hope he sticks to the cartoons," Rat-Toothed hissed beside
her. His breath smelled like he'd been gargling turds. He had a
not-so-secret crush on her and liked to demonstrate his alpha-maleness
by making half-witticisms into her ear. "They're about his speed."

She twisted in her seat and pointedly hunched over her computer's
screen, to which she'd taped a thin sheet of polarized plastic that
made it opaque to anyone shoulder-surfing her. Being a halfway
attractive woman in Silicon Valley was more of a pain in the ass than
she'd expected, back when she'd been covering rustbelt shenanigans in
Detroit, back when there was an auto industry in Detroit.

The worst part was that the Brit's reportage was just spleen-filled
editorializing on the lack of ethics in the valley's board-rooms (a
favorite subject of hers, which no doubt accounted for his
fellow-feeling), and it was also the crux of Kettlewell's schtick. The
spectacle of an exec who talked ethics enraged Rat-Toothed more than
the vilest baby-killers. He was the kind of revolutionary who liked
his firing squads arranged in a circle.
"@
}
        4 {
$plaintext = @"
Kansa is an incident response framework written in PowerShell, useful for data collection and analysis. Most of the analysis capabilities in Kansa require Logparser, which is a very handy tool for creating SQL-like queries over data sets that may be comprised of a single file or many files.

Because adversaries usually want to leave a small footprint, one technique for finding them is frequency analysis -- looking for outliers across many systems. This technique has been written about before. As such, most of the analysis tools in Kansa are scripts that stack-rank or perform frequency analysis of specific fields in a given data set. Some examples include:
Get-ASEPImagePathMD5Stack.ps1
Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1
Get-ASEPImagePathLaunchStringMD5UnsignedTimeStack.ps1

And the list goes on. These script names are fairly descriptive, but they are a mouthful and they are not very flexible as they contain hardcoded Logparser queries with set field names.

Kansa needed a more flexible stack-ranking solution and now it has one.

Get-LogparserStack.ps1 can be used to perform frequency analysis against any delimited file or set of files, so long as the set all has the same schema and the same header row across each file. Unlike all other Kansa utilities, Get-LogparserStack.ps1 is interactive. After reading the first two lines of each input file and confirming that they all have the same header row, the script prompts the user for the field she wishes to pass to Logparser's COUNT() function, then the script prompts the user for the fields she wishes to GROUP BY.

Below is a screen shot of the script in action against a small set of Autorunsc data from five systems. The frequency analysis is against the "Image Path" field with both "Image Path" and MD5 being added to the GROUP BY clause. As you can see in the screen shot, the resulting query quickly bubbles up an outlier, a dll from one system does not match the same dll from the other four systems.

Get-LogparserStack.ps1 is a new utility and as such, may mature a bit in time. One potential feature would be to make it non-interactive, so it can be scripted.

As with nearly all of the scripts that make up Kansa, Get-LogparserStack.ps1 can be used in conjunction with Logparser.exe outside the framework to perform frequency analysis of any data set, providing the schemas match and each file in the set has a header row.

If you use it and encounter any bugs, please open an issue in Kansa's GitHub page.
"@
}
        5 {
$plaintext = @"
WELL, I got a good going-over in the morning from old Miss Watson on
account of my clothes; but the widow she didn't scold, but only cleaned
off the grease and clay, and looked so sorry that I thought I would
behave awhile if I could.  Then Miss Watson she took me in the closet
and prayed, but nothing come of it.  She told me to pray every day, and
whatever I asked for I would get it.  But it warn't so.  I tried it.
Once I got a fish-line, but no hooks.  It warn't any good to me without
hooks.  I tried for the hooks three or four times, but somehow I
couldn't make it work.  By and by, one day, I asked Miss Watson to
try for me, but she said I was a fool.  She never told me why, and I
couldn't make it out no way.

I set down one time back in the woods, and had a long think about it.
 I says to myself, if a body can get anything they pray for, why don't
Deacon Winn get back the money he lost on pork?  Why can't the widow get
back her silver snuffbox that was stole?  Why can't Miss Watson fat up?
No, says I to my self, there ain't nothing in it.  I went and told the
widow about it, and she said the thing a body could get by praying for
it was "spiritual gifts."  This was too many for me, but she told me
what she meant--I must help other people, and do everything I could for
other people, and look out for them all the time, and never think about
myself. This was including Miss Watson, as I took it.  I went out in the
woods and turned it over in my mind a long time, but I couldn't see no
advantage about it--except for the other people; so at last I reckoned
I wouldn't worry about it any more, but just let it go.  Sometimes the
widow would take me one side and talk about Providence in a way to make
a body's mouth water; but maybe next day Miss Watson would take hold
and knock it all down again.  I judged I could see that there was two
Providences, and a poor chap would stand considerable show with the
widow's Providence, but if Miss Watson's got him there warn't no help
for him any more.  I thought it all out, and reckoned I would belong
to the widow's if he wanted me, though I couldn't make out how he was
a-going to be any better off then than what he was before, seeing I was
so ignorant, and so kind of low-down and ornery.

Pap he hadn't been seen for more than a year, and that was comfortable
for me; I didn't want to see him no more.  He used to always whale me
when he was sober and could get his hands on me; though I used to take
to the woods most of the time when he was around.  Well, about this time
he was found in the river drownded, about twelve mile above town, so
people said.  They judged it was him, anyway; said this drownded man was
just his size, and was ragged, and had uncommon long hair, which was all
like pap; but they couldn't make nothing out of the face, because it had
been in the water so long it warn't much like a face at all.  They said
he was floating on his back in the water.  They took him and buried him
on the bank.  But I warn't comfortable long, because I happened to think
of something.  I knowed mighty well that a drownded man don't float on
his back, but on his face.  So I knowed, then, that this warn't pap, but
a woman dressed up in a man's clothes.  So I was uncomfortable again.
 I judged the old man would turn up again by and by, though I wished he
wouldn't.
"@
}
        6 {
$plaintext = @"
It was the best of times,
it was the worst of times,
it was the age of wisdom,
it was the age of foolishness,
it was the epoch of belief,
it was the epoch of incredulity,
it was the season of Light,
it was the season of Darkness,
it was the spring of hope,
it was the winter of despair,
we had everything before us,
we had nothing before us,
we were all going direct to Heaven,
we were all going direct the other way--
in short, the period was so far like the present period, that some of
its noisiest authorities insisted on its being received, for good or for
evil, in the superlative degree of comparison only.
"@
}
        7 {
$plaintext = @"
Morning-room in Algernon's flat in Half-Moon Street.  The room is
luxuriously and artistically furnished.  The sound of a piano is heard in
the adjoining room.

[Lane is arranging afternoon tea on the table, and after the music has
ceased, Algernon enters.]

Algernon.  Did you hear what I was playing, Lane?

Lane.  I didn't think it polite to listen, sir.
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
The international security research community has greatly contributed to our understanding of computer security over the last 20+ years. Highly international speaker line-ups are the norm, and cooperation between people from different nations and continents is the norm rather than the exception. 
"@
}
        10 {
$plaintext = @"
In computer science, the Aho–Corasick string matching algorithm is a string searching algorithm invented by Alfred V. Aho and Margaret J. Corasick.[1] It is a kind of dictionary-matching algorithm that locates elements of a finite set of strings (the "dictionary") within an input text. It matches all patterns simultaneously. The complexity of the algorithm is linear in the length of the patterns plus the length of the searched text plus the number of output matches. Note that because all matches are found, there can be a quadratic number of matches if every substring matches (e.g. dictionary = a, aa, aaa, aaaa and input string is aaaa).

Informally, the algorithm constructs a finite state machine that resembles a trie with additional links between the various internal nodes. These extra internal links allow fast transitions between failed pattern matches (e.g. a search for cat in a trie that does not contain cat, but contains cart, and thus would fail at the node prefixed by ca), to other branches of the trie that share a common prefix (e.g., in the previous case, a branch for attribute might be the best lateral transition). This allows the automaton to transition between pattern matches without the need for backtracking.

When the pattern dictionary is known in advance (e.g. a computer virus database), the construction of the automaton can be performed once off-line and the compiled automaton stored for later use. In this case, its run time is linear in the length of the input plus the number of matched entries.

The Aho–Corasick string matching algorithm formed the basis of the original Unix command fgrep.
"@
        }
    }
    $plaintext
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
for ($i = 2; $i -le $MaxKeySize ; $i++) {

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
    $MaxCalcKeySize = [int]($i * 3)

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
            $Start = ($CalcKeySize - 1) * $a
            $End   = ($CalcKeySize - 1) * ($a + 1)
            # Write-Verbose ("Start is {0}. End is {1}. CipherByteCount is {2}." -f $Start, $End, $CipherByteCount)
            if ($End -gt $CipherByteCount) {
                # Write-Verbose ("Index too high, can't read {0} bytes from CipherByteArray. Continuing." -f $End)
                # continue
            }
            $ByteArray1 = $CipherByteArray[$Start..$End]
            $Start = $End + 1
            $End   = ($CalcKeySize - 1) * ($a + 2) + 1
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

    $gcd = 0
    $obj = "" | Select-Object ActualKeySize,ProbableKeySizes,GCD,PlainText,Key

    for ($p = 0; $p -lt $TopObjs.Count - 1; $p++) {
        $gcd12 = (GetGreatestCommonDenominator -val1 ($TopObjs[$p].CalcKeySize) -val2 ($TopObjs[$p + 1].CalcKeySize))
        $gcd13 = (GetGreatestCommonDenominator -val1 ($TopObjs[$p].CalcKeySize) -val2 ($TopObjs[$p + 2].CalcKeySize))
        $gcd23 = (GetGreatestCommonDenominator -val1 ($TopObjs[$p + 1].CalcKeySize) -val2 ($TopObjs[$p + 2].CalcKeySize))

        if ($gcd12 -eq $gcd13 -eq $gcd23) {
            $obj.ActualKeySize = $TopObjs[$p].KeySize
            $obj.ProbableKeySizes = $gcd12
            $obj.PlainText = $plaintext
            $obj.Key = $keyArray -join ":"
            $obj | Select-Object ActualKeySize,ProbableKeySizes,PlainText,Key
            break
        } else {
            $obj.ActualKeySize = $TopObjs[$p].KeySize
            $obj.ProbableKeySizes = $TopObjs[0..($TopObjs.Count - 1)].CalcKeySize -join ":"
            $obj.PlainText = $plaintext
            $obj.Key = $keyArray -join ":"
            $obj | Select-Object ActualKeySize,ProbableKeySizes,PlainText,Key
            break
        }
        # Write-Verbose ("KeySize is {0}, GCD is {3}, CalcKeySize is {1}, next CalcKeySize is {2}" -f $TopObjs[$p].KeySize, $TopObjs[$p].CalcKeySize, $TopObjs[$p + 1].CalcKeySize, $gcd)
    }
}