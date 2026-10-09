param([string]$PythonPath = 'python', [int]$Port = 8765)
$env:PYTHONPATH = Join-Path $PSScriptRoot 'src'
Push-Location $PSScriptRoot
try {
    & $PythonPath -m probekit.server --port $Port
} finally {
    Pop-Location
}
