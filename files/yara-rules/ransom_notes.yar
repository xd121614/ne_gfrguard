/*
 * ransom_notes.yar - 赎金信/赎金通知检测规则
 *
 * 检测勒索软件在文件中嵌入的赎金信文本、Tor链接和加密货币钱包地址。
 * 触发级别：critical（直接关联勒索行为）
 *
 * v2 changes (2025-07-06, from 143-sample TP scan):
 *   - RansomNote_Generic: expanded from 12 to 22 patterns based on real sample strings
 *   - RansomNote_CryptoWallet: tightened context (removed generic "decrypt"/"encrypted",
 *     added "ransom" and ransom-specific phrases)
 *   - RansomNote_DataLeak: NEW — detects data leak/extortion blog threats (modern double-extortion)
 */

rule RansomNote_Generic
{
    meta:
        description = "Detects common ransomware ransom note text patterns"
        severity = "critical"
        false_positive = "low"

    strings:
        /* Direct encryption notification */
        $note1  = "Your files have been encrypted" ascii nocase
        $note2  = "All your files are encrypted" ascii nocase
        $note3  = "Your files are encrypted" ascii nocase
        $note4  = "your files and data" ascii nocase

        /* Decryption / recovery instructions */
        $note5  = "your personal decryption" ascii nocase
        $note6  = "decrypt your files" ascii nocase
        $note7  = "decrypt your data" ascii nocase
        $note8  = "restore your files" ascii nocase
        $note9  = "recover your files" ascii nocase
        $note10 = "recover your data" ascii nocase

        /* Payment demands */
        $note11 = "pay the ransom" ascii nocase
        $note12 = "send bitcoin" ascii nocase
        $note13 = "bitcoin wallet" ascii nocase
        $note14 = "send us" ascii nocase

        /* Threats — double extortion */
        $note15 = "data will be published" ascii nocase
        $note16 = "we have downloaded" ascii nocase
        $note17 = "we have taken" ascii nocase
        $note18 = "will be leaked" ascii nocase

        /* Warnings / instructions */
        $note19 = "do not modify" ascii nocase
        $note20 = "do not rename" ascii nocase
        $note21 = "contact us for decryption" ascii nocase
        $note22 = "private key" ascii nocase

    condition:
        2 of them
}

rule RansomNote_Filename
{
    meta:
        description = "Detects well-known ransomware note filename indicators in content"
        severity = "critical"
        false_positive = "very low"

    strings:
        /* All-caps patterns (Windows-style) */
        $fn1  = "README_TO_DECRYPT" ascii nocase
        $fn2  = "HOW_TO_RECOVER" ascii nocase
        $fn3  = "DECRYPT_INSTRUCTIONS" ascii nocase
        $fn4  = "HOW_TO_DECRYPT" ascii nocase
        $fn5  = "RECOVER_YOUR_FILES" ascii nocase
        $fn6  = "FILES_ENCRYPTED" ascii nocase
        $fn7  = "RESTORE_FILES" ascii nocase
        $fn8  = "DECRYPT_INFORMATION" ascii nocase
        $fn9  = "ATTENTION_README" ascii nocase
        $fn10 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase

        /* Variant-specific note filenames (from 143-sample analysis) */
        $fn11 = "read_me_lkdtt" ascii nocase
        $fn12 = "RECOVER-FILES" ascii nocase
        $fn13 = "readme_howtorecover.txt" ascii nocase
        $fn14 = "how_to_decrypt.txt" ascii nocase
        $fn15 = "how_to_decrypt.hta" ascii nocase
        $fn16 = "akira_readme.txt" ascii nocase

    condition:
        any of them
}

rule RansomNote_TorLink
{
    meta:
        description = "Detects Tor onion links in ransom communications"
        severity = "high"
        false_positive = "low"

    strings:
        /* Tor v2/v3 onion addresses */
        $tor1 = /[a-z2-7]{16,56}\.onion/ ascii
        $tor2 = "torproject.org" ascii nocase
        $tor3 = "Tor Browser" ascii nocase

        /* Ransom / payment context required */
        $pay1 = "payment" ascii nocase
        $pay2 = "decrypt" ascii nocase
        $pay3 = "recover" ascii nocase
        $pay4 = "ransom" ascii nocase
        $pay5 = "restore" ascii nocase

    condition:
        any of ($tor*) and any of ($pay*)
}

rule RansomNote_CryptoWallet
{
    meta:
        description = "Detects cryptocurrency wallet addresses in ransom notes"
        severity = "high"
        false_positive = "medium"

    strings:
        /* Bitcoin addresses (P2PKH, P2SH, Bech32) */
        $btc1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $btc2 = /bc1[a-zA-HJ-NP-Z0-9]{39,59}/ ascii

        /* Monero address */
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii

        /* Ransom-specific context — MUST be present alongside crypto address.
         * NOTE: "encrypted" and "decrypt" intentionally REMOVED from previous
         * version — they matched Go/Rust stdlib crypto symbols (FP risk).
         * Replaced with ransomware-specific terms that don't appear in
         * legitimate crypto libraries. */
        $ctx1 = "ransom" ascii nocase
        $ctx2 = "payment" ascii nocase
        $ctx3 = "bitcoin" ascii nocase
        $ctx4 = "monero" ascii nocase
        $ctx5 = "wallet" ascii nocase
        $ctx6 = "restore your" ascii nocase
        $ctx7 = "contact us" ascii nocase
        $ctx8 = "your files" ascii nocase

    condition:
        any of ($btc*, $xmr) and 2 of ($ctx*)
}

rule RansomNote_DataLeak
{
    meta:
        description = "Detects double-extortion data leak / darknet blog threats"
        severity = "critical"
        false_positive = "low"

    strings:
        /* Darknet leak blog mentions */
        $leak1 = ".onion" ascii nocase
        $leak2 = "dark web" ascii nocase
        $leak3 = "darknet" ascii nocase

        /* Data exfiltration / publication threats */
        $threat1 = "we have downloaded" ascii nocase
        $threat2 = "we have taken" ascii nocase
        $threat3 = "your data" ascii nocase
        $threat4 = "data will be published" ascii nocase
        $threat5 = "published in our blog" ascii nocase
        $threat6 = "sell personal information" ascii nocase
        $threat7 = "trade secrets" ascii nocase
        $threat8 = "will be leaked" ascii nocase

    condition:
        (any of ($leak*) and any of ($threat*)) or 2 of ($threat*)
}
