rule unusual_tcp_payload {
    meta:
        description = "Detects unusual or suspicious TCP payloads"
        author = "Joel Mathew"

    strings:
        // Detects long sequences of NOP instructions, often used in buffer overflow attacks
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 }
        
        // Detects common shellcode patterns
        $common_shellcode = { 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 b0 0b cd 80 }
        
        // Detects SQL injection attempts
        //$sql_injection = /(?:\%27)|(?:\')|(?:\-\-)|(?:\%23)|(?:\#)|(?:\%3D)|(?:=)/
        
        // Detects encoded payloads that might be used in XSS or other attacks
        $encoded_payload = /(%[0-9a-fA-F]{2}){5,}/
        
        // Detects commands used in reverse shells
        $reverse_shell = /bash\s+-i\s+>&\s+\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}\s+0<\&1/
        

    condition:
        any of ($nop_sled, $common_shellcode, $encoded_payload, $reverse_shell)
}

rule meterpreter_reverse_tcp {
   meta:
      description = "meterpreter reverse tcp session may be open"
      author = "yarGen Rule Generator"
      date = "2023-06-25"
      hash1 = "f9b0d98e29556216aebdf568ba7779d5575735ba576b8b82659e54236190b88c"
   strings:
      $s1 = "Error reading private key %s - mbedTLS: (-0x%04X) %s" fullword ascii
      $s2 = "processing command: %u id: '%s'" fullword ascii
      $s3 = "Failed reading the chunked-encoded stream" fullword ascii
      $s4 = "0 0 0 0 PC Service User:" fullword ascii
      $s5 = "Dumping cert info:" fullword ascii
      $s6 = "Error reading client cert file %s - mbedTLS: (-0x%04X) %s" fullword ascii
      $s7 = "[fqdn] gethostbyaddr(%s) failed: %s" fullword ascii
      $s8 = "NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer" fullword ascii
      $s9 = "process_new: got %zd byte executable to run in memory" fullword ascii
      $s10 = "[fqdn] gethostbyname(%s) failed: %s" fullword ascii
      $s11 = "thread vulnerable" fullword ascii
      $s12 = /\/(\d+\.)(\d+\.)(\d+\.)(\d+)/
   condition:
      uint16(0) == 0x457f and
      8 of them
}
