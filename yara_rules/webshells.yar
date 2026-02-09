/*
    Cereberus YARA Rules - Webshell Detection
    Detects PHP, ASP, ASPX, and JSP webshells including common obfuscation
    techniques and known webshell families.
*/

// ---------------------------------------------------------------------------
// PHP Webshells
// ---------------------------------------------------------------------------

rule Webshell_PHP_Generic_Eval {
    meta:
        author = "Cereberus"
        description = "Detects PHP webshells using eval with dynamic input"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $eval1 = "eval($_" ascii nocase
        $eval2 = "eval($HTTP_" ascii nocase
        $eval3 = "eval(base64_decode(" ascii nocase
        $eval4 = "eval(gzinflate(" ascii nocase
        $eval5 = "eval(gzuncompress(" ascii nocase
        $eval6 = "eval(gzdecode(" ascii nocase
        $eval7 = "eval(str_rot13(" ascii nocase
        $eval8 = /eval\s*\(\s*\$[a-zA-Z_]+\s*\(/ ascii
    condition:
        $php and any of ($eval*)
}

rule Webshell_PHP_System_Exec {
    meta:
        author = "Cereberus"
        description = "Detects PHP webshells that execute system commands via user input"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $input1 = "$_GET[" ascii
        $input2 = "$_POST[" ascii
        $input3 = "$_REQUEST[" ascii
        $input4 = "$_COOKIE[" ascii
        $exec1 = "system(" ascii
        $exec2 = "passthru(" ascii
        $exec3 = "shell_exec(" ascii
        $exec4 = "exec(" ascii
        $exec5 = "popen(" ascii
        $exec6 = "proc_open(" ascii
        $exec7 = "pcntl_exec(" ascii
        $exec8 = "`$_" ascii
    condition:
        $php and
        (1 of ($input*) and 1 of ($exec*)) or
        $exec8
}

rule Webshell_PHP_Assert_Backdoor {
    meta:
        author = "Cereberus"
        description = "Detects PHP webshells using assert() as an eval alternative"
        severity = "high"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $assert1 = "assert($_" ascii nocase
        $assert2 = "assert($HTTP_" ascii nocase
        $assert3 = /assert\s*\(\s*base64_decode\s*\(/ ascii
        $assert4 = /assert\s*\(\s*str_rot13\s*\(/ ascii
        $assert5 = "@assert(" ascii
    condition:
        $php and any of ($assert*)
}

rule Webshell_PHP_Preg_Replace_Eval {
    meta:
        author = "Cereberus"
        description = "Detects PHP webshells abusing preg_replace /e modifier for code execution"
        severity = "high"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $preg1 = /preg_replace\s*\(\s*['"]\/.+\/e['"]/ ascii
        $preg2 = "preg_replace(\"/.*/" ascii
        $create1 = "create_function(" ascii
        $create2 = /call_user_func\s*\(\s*['"]assert['"]/ ascii
        $create3 = /call_user_func_array\s*\(/ ascii
    condition:
        $php and any of ($preg*) or
        ($php and any of ($create*) and filesize < 50KB)
}

rule Webshell_PHP_Obfuscated {
    meta:
        author = "Cereberus"
        description = "Detects obfuscated PHP webshells using string manipulation for evasion"
        severity = "high"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        // chr() concatenation to build function names
        $obf1 = /\$\w+\s*=\s*chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)/ ascii
        // Variable function calls: $var($input)
        $obf2 = /\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ ascii
        // Hex-encoded strings
        $obf3 = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/ ascii
        // Array-based obfuscation
        $obf4 = /\$\w+\s*=\s*array\(\s*['"][a-zA-Z]{1,3}['"]\s*(,\s*['"][a-zA-Z]{1,3}['"]\s*){5,}/ ascii
        // Reverse string tricks
        $obf5 = "strrev(" ascii
        $obf6 = "str_replace(" ascii
        $obf7 = "substr(" ascii
        // Long base64 blob
        $b64_blob = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition:
        $php and
        (2 of ($obf*)) or
        ($php and $b64_blob and filesize < 100KB)
}

rule Webshell_PHP_Known_Families {
    meta:
        author = "Cereberus"
        description = "Detects known PHP webshell families by unique strings"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        // C99 shell
        $c99_1 = "c99shell" ascii nocase
        $c99_2 = "c99_buff_prepare" ascii
        // R57 shell
        $r57_1 = "r57shell" ascii nocase
        $r57_2 = "r57_get_phpini" ascii
        // WSO (Web Shell by oRb)
        $wso_1 = "WSO " ascii
        $wso_2 = "Web Shell by oRb" ascii
        // b374k
        $b374k_1 = "b374k" ascii nocase
        $b374k_2 = "b374k shell" ascii nocase
        // p0wny
        $p0wny = "p0wny@shell" ascii
        // weevely
        $weevely1 = "weevely" ascii nocase
        // FilesMan
        $fm1 = "FilesMan" ascii
        $fm2 = "Fil3sM4n" ascii
        // Antak
        $antak = "Antak" ascii
        // China Chopper
        $cc1 = "China Chopper" ascii nocase
    condition:
        $php and any of ($c99_*, $r57_*, $wso_*, $b374k_*, $p0wny, $weevely*, $fm*, $antak, $cc1)
}

rule Webshell_PHP_Upload_Shell {
    meta:
        author = "Cereberus"
        description = "Detects PHP scripts that accept file uploads and write to disk (upload shells)"
        severity = "high"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $upload1 = "move_uploaded_file(" ascii
        $upload2 = "$_FILES[" ascii
        $upload3 = "file_put_contents(" ascii
        $upload4 = "fwrite(" ascii
        $input1 = "$_POST[" ascii
        $input2 = "$_GET[" ascii
        $exec1 = "system(" ascii
        $exec2 = "exec(" ascii
        $exec3 = "passthru(" ascii
        $exec4 = "shell_exec(" ascii
    condition:
        $php and
        (1 of ($upload*) and 1 of ($input*) and 1 of ($exec*)) and
        filesize < 100KB
}

// ---------------------------------------------------------------------------
// ASP / ASPX Webshells
// ---------------------------------------------------------------------------

rule Webshell_ASP_Generic {
    meta:
        author = "Cereberus"
        description = "Detects classic ASP webshells with command execution"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $asp1 = "<%@ " ascii nocase
        $asp2 = "<%" ascii
        $exec1 = "WScript.Shell" ascii nocase
        $exec2 = "Shell.Application" ascii nocase
        $exec3 = "Scripting.FileSystemObject" ascii nocase
        $exec4 = "ADODB.Stream" ascii nocase
        $exec5 = "cmd.exe" ascii nocase
        $exec6 = "CreateObject" ascii nocase
        $exec7 = "Execute(" ascii nocase
        $exec8 = "Eval(Request" ascii nocase
        $input1 = "Request(" ascii nocase
        $input2 = "Request.Form" ascii nocase
        $input3 = "Request.QueryString" ascii nocase
    condition:
        1 of ($asp*) and
        2 of ($exec*) and
        1 of ($input*)
}

rule Webshell_ASPX_CSharp {
    meta:
        author = "Cereberus"
        description = "Detects ASPX webshells using C# for command execution"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $aspx1 = "<%@ Page" ascii nocase
        $aspx2 = "Language=\"C#\"" ascii nocase
        $aspx3 = "runat=\"server\"" ascii nocase
        $exec1 = "Process.Start" ascii
        $exec2 = "ProcessStartInfo" ascii
        $exec3 = "System.Diagnostics" ascii
        $exec4 = "cmd.exe" ascii nocase
        $exec5 = "/c " ascii
        $io1 = "System.IO.File" ascii
        $io2 = "StreamReader" ascii
        $io3 = "StandardOutput" ascii
        $input1 = "Request[" ascii
        $input2 = "Request.Form" ascii
        $input3 = "Request.QueryString" ascii
    condition:
        1 of ($aspx*) and
        2 of ($exec*) and
        (1 of ($io*) or 1 of ($input*))
}

rule Webshell_ASPX_Known_Families {
    meta:
        author = "Cereberus"
        description = "Detects known ASPX webshell families"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        // ASPXSpy
        $spy1 = "ASPXSpy" ascii nocase
        $spy2 = "aspxspy" ascii nocase
        // China Chopper ASPX variant
        $cc1 = "eval(Request.Item[" ascii nocase
        $cc2 = "unsafe" ascii
        // Tunna
        $tunna = "Tunna" ascii
        // SharPyShell
        $sharpy = "SharPyShell" ascii nocase
        // Godzilla
        $godzilla1 = "Godzilla" ascii nocase
        $godzilla2 = /xc\s*=\s*new\s+X509Certificate2/ ascii
        // Generic ASPX one-liner
        $oneliner = /<%@\s*Page.*%><%\s*Response\.Write\(/ ascii
    condition:
        any of them
}

// ---------------------------------------------------------------------------
// JSP Webshells
// ---------------------------------------------------------------------------

rule Webshell_JSP_Generic {
    meta:
        author = "Cereberus"
        description = "Detects JSP webshells with runtime command execution"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $jsp1 = "<%@ page" ascii nocase
        $jsp2 = "<%@page" ascii nocase
        $jsp3 = "<jsp:" ascii nocase
        $exec1 = "Runtime.getRuntime().exec(" ascii
        $exec2 = "ProcessBuilder" ascii
        $exec3 = "getRuntime()" ascii
        $input1 = "request.getParameter(" ascii
        $input2 = "request.getHeader(" ascii
        $io1 = "BufferedReader" ascii
        $io2 = "InputStreamReader" ascii
        $io3 = "getInputStream()" ascii
        $cmd1 = "cmd.exe" ascii nocase
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "/bin/bash" ascii
    condition:
        1 of ($jsp*) and
        1 of ($exec*) and
        1 of ($input*) and
        (1 of ($io*) or 1 of ($cmd*))
}

rule Webshell_JSP_Behinder {
    meta:
        author = "Cereberus"
        description = "Detects Behinder (Ice Scorpion) JSP webshell family"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $behinder1 = "AES/ECB/" ascii
        $behinder2 = "javax.crypto.Cipher" ascii
        $behinder3 = "ClassLoader" ascii
        $behinder4 = "defineClass" ascii
        $behinder5 = "base64Decode" ascii
        $behinder6 = "request.getReader()" ascii
        $key = /String\s+k\s*=\s*"[a-f0-9]{16}"/ ascii
    condition:
        3 of ($behinder*) or $key
}

rule Webshell_JSP_Godzilla {
    meta:
        author = "Cereberus"
        description = "Detects Godzilla JSP webshell"
        severity = "critical"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $gz1 = "javax.crypto" ascii
        $gz2 = "SecretKeySpec" ascii
        $gz3 = "AES" ascii
        $gz4 = "defineClass" ascii
        $gz5 = "newInstance" ascii
        $gz6 = "getClass().getMethod(" ascii
        $gz7 = /session\.setAttribute\(/ ascii
        $gz8 = "pageContext" ascii
    condition:
        5 of them
}

// ---------------------------------------------------------------------------
// Generic Webshell Indicators (Cross-Language)
// ---------------------------------------------------------------------------

rule Webshell_Tiny_Oneliner {
    meta:
        author = "Cereberus"
        description = "Detects very small files (under 1KB) with both input reading and command execution — classic one-liner webshells"
        severity = "high"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        // PHP one-liners
        $php1 = "<?php system($_GET" ascii nocase
        $php2 = "<?php eval($_POST" ascii nocase
        $php3 = "<?php passthru($_REQUEST" ascii nocase
        $php4 = "<?=`$_GET" ascii
        // ASP one-liners
        $asp1 = "<%eval request(" ascii nocase
        $asp2 = "<%execute request(" ascii nocase
        // JSP one-liners
        $jsp1 = "Runtime.getRuntime().exec(request.getParameter" ascii
    condition:
        filesize < 1KB and any of them
}

rule Webshell_Encoded_Payload {
    meta:
        author = "Cereberus"
        description = "Detects webshells that decode and execute base64 or hex-encoded payloads"
        severity = "high"
        mitre_technique = "T1140"
        category = "webshell"
    strings:
        // PHP base64 decode chains
        $php_b64_1 = "base64_decode($_" ascii
        $php_b64_2 = /eval\(base64_decode\(\$_(POST|GET|REQUEST|COOKIE)/ ascii
        $php_b64_3 = "gzinflate(base64_decode(" ascii
        // ASP/ASPX encoded
        $asp_b64 = "FromBase64String" ascii
        $asp_b64_exec = "Convert.FromBase64String(Request" ascii nocase
        // JSP encoded
        $jsp_b64_1 = "Base64.getDecoder().decode(request" ascii
        $jsp_b64_2 = "new sun.misc.BASE64Decoder()" ascii
    condition:
        any of them
}

rule Webshell_File_Manager_Functionality {
    meta:
        author = "Cereberus"
        description = "Detects web scripts with combined file management and command execution capabilities"
        severity = "high"
        mitre_technique = "T1505.003"
        category = "webshell"
    strings:
        $fm1 = "file_manager" ascii nocase
        $fm2 = "filemanager" ascii nocase
        $fm3 = "file manager" ascii nocase
        $dir1 = "opendir(" ascii
        $dir2 = "scandir(" ascii
        $dir3 = "DirectoryInfo" ascii
        $edit1 = "file_get_contents(" ascii
        $edit2 = "file_put_contents(" ascii
        $edit3 = "fopen(" ascii
        $perm1 = "chmod(" ascii
        $perm2 = "chown(" ascii
        $del1 = "unlink(" ascii
        $del2 = "rmdir(" ascii
    condition:
        (1 of ($fm*) or 3 of ($dir*, $edit*, $perm*, $del*)) and
        filesize < 500KB
}
