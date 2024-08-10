rule icmp_abnormalities {
    meta:
        description = "Detects abnormalities in ICMP packets from string data"
        author = "Joel Mathew"

    strings:
        // Detect ICMP packets with suspicious payload content
        $icmp_shellcode = { 6a 0b 58 99 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 53 89 e1 cd 80 }  // Common shellcode pattern
        $icmp_reverse_shell = /bash\s+-i\s+>&\s+\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}\s+0<\&1/
        $icmp_reverse_shell = /bash\s+-i\s+>&\s+\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}\s+0<\&1/
    condition:
        any of ($icmp_*)
}

