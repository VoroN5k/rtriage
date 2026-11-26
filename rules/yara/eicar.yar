// EICAR anti-malware test file (https://www.eicar.org/download-anti-malware-testfile/).
// Informational: it scores 0 and only tells you that an AV test file was
// scanned. The test string is split into two patterns on purpose, so this
// rule file (and the rtriage binary that embeds it) never contains the
// complete EICAR string and is not itself flagged by antivirus software.

rule eicar_test_file
{
    meta:
        description = "EICAR anti-malware test file: harmless, used to check that scanners work."
        severity = "info"
        confidence = "high"
        category = "metadata"
        reference = "https://www.eicar.org/"
    strings:
        $head = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
        $tail = "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $head at 0 and $tail at 33 and filesize < 128
}
