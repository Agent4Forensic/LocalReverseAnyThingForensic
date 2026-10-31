// Own, small rule set of sw-analyst (ADR-0006: rules are pinned with the image). A hit shows that bytes are present, not that
// code uses them: the gateway reports hits as hypotheses. Extend by review, never from the model.
rule crypto_aes_sbox {
    meta: description = "AES forward S-box bytes"
    strings: $a = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition: $a
}
rule crypto_aes_inverse_sbox {
    meta: description = "AES inverse S-box bytes"
    strings: $a = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
    condition: $a
}
rule crypto_sha256_constants {
    meta: description = "SHA-256 round constants, little or big endian"
    strings:
        $le = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9 }
        $be = { 42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5 }
    condition: any of them
}
rule crypto_md5_init {
    meta: description = "MD5 or SHA-1 initial state"
    strings: $a = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
    condition: $a
}
rule crypto_chacha_salsa_constant {
    meta: description = "ChaCha or Salsa20 constant"
    strings: $a = "expand 32-byte k"
    condition: $a
}
rule packer_upx_markers {
    meta: description = "UPX section names and marker"
    strings:
        $a = "UPX0"
        $b = "UPX1"
        $c = "UPX!"
    condition: 2 of them
}
rule embedded_pe_after_start {
    meta: description = "Second MZ/PE header after the start of the file"
    strings: $a = "This program cannot be run in DOS mode"
    condition: #a > 0 and @a[#a] > 1024
}
rule script_powershell_encoded {
    meta: description = "PowerShell encoded command or base64 call"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "FromBase64String" nocase
    condition: any of them
}
