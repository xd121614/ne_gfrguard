/*
 * encryption.yar - 加密行为特征检测规则
 *
 * 检测文件中嵌入的加密密钥、部分加密结构和文件头破坏特征。
 * 这些规则用于识别已被加密的文件或加密工具的配置。
 */

rule Ransomware_EmbeddedKey
{
    meta:
        description = "Detects embedded RSA/encryption key with ransomware config context"
        severity = "high"
        false_positive = "medium"

    strings:
        /* RSA public key header */
        $rsa_pub = "-----BEGIN PUBLIC KEY-----" ascii
        $rsa_enc = "-----BEGIN RSA PUBLIC KEY-----" ascii

        /* Must be combined with ransomware config indicators */
        $cfg1 = "\"encrypt\"" ascii
        $cfg2 = "\"extension\"" ascii
        $cfg3 = "\"note\"" ascii
        $cfg4 = "\"kill\"" ascii
        $cfg5 = "\"wipe\"" ascii
        $cfg6 = "\"paths\"" ascii

    condition:
        ($rsa_pub or $rsa_enc) and 2 of ($cfg*)
}

rule Ransomware_PartialEncryption
{
    meta:
        description = "Detects partial/intermittent encryption patterns"
        severity = "high"
        false_positive = "low"

    strings:
        /* Configuration for partial encryption (common in modern ransomware) */
        $partial1 = "encrypt_percent" ascii
        $partial2 = "skip_step" ascii
        $partial3 = "chunk_size" ascii
        $partial4 = "encrypt_size" ascii
        $partial5 = "file_size_limit" ascii
        $partial6 = "intermittent" ascii nocase

        /* Must have multiple indicators */
        $enc1 = "AES" ascii
        $enc2 = "ChaCha" ascii nocase
        $enc3 = "Salsa20" ascii nocase
        $enc4 = "encrypt" ascii nocase

    condition:
        (2 of ($partial*) and any of ($enc*))
}

rule Ransomware_FileHeaderCorruption
{
    meta:
        description = "Detects encrypted files with known ransomware footer patterns"
        severity = "medium"
        false_positive = "medium"

    strings:
        /*
         * Known ransomware encryption footers at end of file.
         * Each pattern is family-specific to avoid FP on generic ELF binaries.
         *
         * Ryuk/Hermes: appends 6-byte "HERMES" marker
         * Phobos/Dharma: appends 5-byte ID + 0xFF padding
         * WannaCry: appends "WANACRY!" marker
         * General: encrypted file with 256-bit key block at footer
         */
        $hermes = "HERMES" ascii
        $wanacry = "WANACRY!" ascii
        $wcry = "wcry" ascii

        /* Key block at file footer: 32-byte aligned zero-padded key info */
        $key_footer = { 00 00 00 00 00 00 00 00 [4-8] FF FF FF FF [0-16] 00 00 00 00 00 00 00 00 }

    condition:
        ($key_footer at (filesize - 64)) or
        any of ($hermes*, $wanacry*, $wcry*)
}
