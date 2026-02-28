/*
 * Web Shell Detection Rules
 * Category: Webshells
 * Author: rawqubit
 */

rule PHPWebshellGeneric
{
    meta:
        description = "Detects common PHP web shell patterns"
        severity = "critical"
        tags = "webshell, php, backdoor"

    strings:
        $eval_post   = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $base64_eval = /eval\s*\(\s*base64_decode/
        $assert_post = /assert\s*\(\s*\$_(POST|GET|REQUEST)/
        $preg_replace = /preg_replace\s*\(\s*['"]\/.*\/e['"]/
        $system_post = /system\s*\(\s*\$_(POST|GET|REQUEST)/
        $passthru    = /passthru\s*\(\s*\$_(POST|GET|REQUEST)/

    condition:
        any of them
}

rule ChinaChopper
{
    meta:
        description = "Detects China Chopper web shell"
        severity = "critical"
        tags = "webshell, china-chopper, apt"
        reference = "https://attack.mitre.org/software/S0020/"

    strings:
        $chopper1 = "eval(Request.Item[" nocase
        $chopper2 = "eval(Request[" nocase
        $chopper3 = "eval($_POST[" nocase
        $chopper4 = {65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D}

    condition:
        any of them
}

rule JSWebshell
{
    meta:
        description = "Detects JavaScript/Node.js web shell patterns"
        severity = "critical"
        tags = "webshell, javascript, nodejs"

    strings:
        $exec1 = "require('child_process')" nocase
        $exec2 = "require(\"child_process\")" nocase
        $exec3 = "child_process.exec(" nocase
        $spawn  = "child_process.spawn(" nocase
        $req_body = "req.body" nocase
        $req_query = "req.query" nocase

    condition:
        ($exec1 or $exec2 or $exec3 or $spawn) and ($req_body or $req_query)
}

rule AspxWebshell
{
    meta:
        description = "Detects ASPX web shell patterns"
        severity = "critical"
        tags = "webshell, aspx, dotnet"

    strings:
        $process_start = "Process.Start(" nocase
        $cmd_exec      = "cmd.exe" nocase
        $request_form  = "Request.Form[" nocase
        $request_qs    = "Request.QueryString[" nocase
        $shell_exec    = "Shell(" nocase

    condition:
        ($process_start or $shell_exec) and ($request_form or $request_qs) and $cmd_exec
}
