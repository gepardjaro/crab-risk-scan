# Run with a trusted installation of PSScriptAnalyzer.
param(
    [Parameter(Mandatory)][string] $SourceDirectory,
    [Parameter(Mandatory)][string] $ReportFile
)
$ErrorActionPreference = 'Stop'
# Specify the built-in rule explicitly. The report has no script text or diagnostic messages.
$records = @(Invoke-ScriptAnalyzer -Path $SourceDirectory -Recurse -IncludeRule PSAvoidUsingPlainTextForPassword | ForEach-Object {
    [ordered]@{
        RuleName = $_.RuleName
        ScriptPath = $_.ScriptPath
        Severity = $_.Severity.ToString()
        Extent = [ordered]@{
            StartLineNumber = $_.Extent.StartLineNumber
            EndLineNumber = $_.Extent.EndLineNumber
            StartColumnNumber = $_.Extent.StartColumnNumber
            EndColumnNumber = $_.Extent.EndColumnNumber
        }
    }
})
$json = ConvertTo-Json -InputObject $records -Depth 4
[IO.File]::WriteAllText($ReportFile, $json, [Text.UTF8Encoding]::new($false))
