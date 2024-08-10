rule sql_injection_attempts {
    meta:
        description = "Detects common SQL injection patterns in strings"
        author = "Joel Mathew"

    strings:
        // Common SQL Injection patterns
        $sql_injection_1 = /('|"|;)--/
        $sql_injection_2 = /('|"|;)#/
        $sql_injection_3 = /('|"|;)\*/
        $sql_injection_4 = /UNION(\s+ALL\s+)?SELECT/i
        $sql_injection_5 = /SELECT.*FROM/i
        $sql_injection_6 = /INSERT\s+INTO/i
        $sql_injection_7 = /UPDATE\s+\w+\s+SET/i
        $sql_injection_8 = /DELETE\s+FROM/i
        $sql_injection_9 = /DROP\s+(TABLE|DATABASE)/i
        $sql_injection_10 = /ALTER\s+TABLE/i
        $sql_injection_11 = /--(\s|\n|\r)/  // Comments in SQL
        $sql_injection_12 = /\/\*\*/        // Inline comments in SQL
        $sql_injection_13 = /xp_cmdshell/i  // Common in MSSQL injections
        $sql_injection_14 = /benchmark\s*\(/i  // MySQL timing attacks
        $sql_injection_15 = /waitfor\s+delay/i  // MSSQL timing attacks
        $sql_injection_16 = /(\%27)|(\')|(\-\-)|(\%23)|(#)/i  // URL encoded attacks

    condition:
        any of them
}
