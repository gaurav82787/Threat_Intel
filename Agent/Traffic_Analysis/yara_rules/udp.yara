
rule udp_large_payload {
    meta:
        description = "Detects UDP packets with unusually large payloads"
        author = "Joel Mathew"

    strings:
        $large_payload = /.{512,}/  // UDP payload larger than 512 bytes

    condition:
        $large_payload
}

rule udp_shellcode {
    meta:
        description = "Detects shellcode patterns in UDP payloads"
        author = "Joel Mathew"

    strings:
        $shellcode = { 6a 0b 58 99 52 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 52 53 89 e1 cd 80 }  // Common shellcode pattern

    condition:
        $shellcode
}

rule udp_reverse_shell {
    meta:
        description = "Detects reverse shell commands in UDP payloads"
        author = "Joel Mathew"

    strings:
        $reverse_shell = /bash\s+-i\s+>&\s+\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}\s+0<\&1/  // Reverse shell command

    condition:
        $reverse_shell
}

rule udp_dns_tunnel {
    meta:
        description = "Detects potential DNS tunneling over UDP"
        author = "Joel Mathew"

    strings:
        $dns_tunnel = /[a-zA-Z0-9]{50,}/  // Long alphanumeric strings typical in DNS tunneling

    condition:
        $dns_tunnel
}

rule udp_unusual_commands {
    meta:
        description = "Detects unusual commands in UDP payloads"
        author = "Joel Mathew"

    strings:
        $wget_command = /wget\s+http/
        $curl_command = /curl\s+-O/
        $powershell_command = /powershell\s+-encodedCommand/

    condition:
        any of ($wget_command, $curl_command, $powershell_command)
}

