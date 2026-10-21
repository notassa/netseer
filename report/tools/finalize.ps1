# Opens the built report in Word, refreshes the TOC / list of tables / list of figures,
# saves the .docx and exports a PDF next to it.
# Kept deliberately plain: Repaginate(), Fields.Update() and strict error mode have each
# left an invisible Word instance hanging on this document. Paths are cast to [string]
# because a PSObject-wrapped path makes ExportAsFixedFormat stall.
$root = Split-Path -Parent $PSScriptRoot
[string]$docx = Join-Path $root "FYP2-Report-revised.docx"
[string]$pdf  = Join-Path $root "FYP2-Report-revised.pdf"
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
$doc = $word.Documents.Open($docx, $false, $false, $false)
$n = $doc.TablesOfContents.Count
for ($k = 1; $k -le $n; $k++) { $doc.TablesOfContents.Item($k).Update() }
$doc.Save()
$doc.ExportAsFixedFormat($pdf, 17)
$doc.Close()
$word.Quit()
Write-Output "Saved $docx and $pdf"
