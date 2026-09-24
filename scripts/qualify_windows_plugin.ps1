[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Archive,
  [Parameter(Mandatory = $true)][string]$Codex,
  [Parameter(Mandatory = $true)][string]$WorkRoot,
  [string]$MarketplaceRoot = "",
  [switch]$VerifyPublicIdentity
)

$ErrorActionPreference = "Stop"
$Archive = (Resolve-Path $Archive).Path
$Codex = (Resolve-Path $Codex).Path
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null

if ($MarketplaceRoot) {
  $MarketplaceRoot = (Resolve-Path $MarketplaceRoot).Path
  if ($VerifyPublicIdentity) {
    & python scripts/verify_public_marketplace.py --archive $Archive --marketplace $MarketplaceRoot
    if ($LASTEXITCODE -ne 0) { throw "Public marketplace identity verification failed" }
  }
} else {
  $MarketplaceRoot = Join-Path $WorkRoot "marketplace"
  New-Item -ItemType Directory -Force -Path (Join-Path $MarketplaceRoot "plugins") | Out-Null
  tar -xf $Archive -C (Join-Path $MarketplaceRoot "plugins")
  if ($LASTEXITCODE -ne 0) { throw "Plugin archive extraction failed" }
  New-Item -ItemType Directory -Force -Path (Join-Path $MarketplaceRoot ".agents/plugins") | Out-Null
  '{"name":"windows-test","plugins":[{"name":"openubmc","source":{"source":"local","path":"./plugins/openubmc"}}]}' |
    Set-Content -Encoding utf8NoBOM (Join-Path $MarketplaceRoot ".agents/plugins/marketplace.json")
}

$manifest = Get-Content -Raw (Join-Path $MarketplaceRoot ".agents/plugins/marketplace.json") | ConvertFrom-Json
$marketplaceName = $manifest.name
$plugin = Join-Path $MarketplaceRoot "plugins/openubmc"
if (-not (Test-Path (Join-Path $plugin "plugin-lock.json"))) { throw "Marketplace plugin payload is missing" }

$env:CODEX_HOME = Join-Path $WorkRoot "codex-home"
New-Item -ItemType Directory -Force -Path $env:CODEX_HOME | Out-Null
& $Codex plugin marketplace add $MarketplaceRoot
if ($LASTEXITCODE -ne 0) { throw "Codex marketplace installation failed" }
& $Codex plugin add "openubmc@$marketplaceName" --json
if ($LASTEXITCODE -ne 0) { throw "Codex plugin installation failed" }
$servers = (& $Codex mcp list --json | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw "Codex MCP inventory failed" }
foreach ($name in @("openubmc-target-runtime", "openubmc-kb")) {
  $server = $servers | Where-Object { $_.name -eq $name }
  if ($null -eq $server -or $server.transport.command -ne "node") {
    throw "Windows MCP launcher was not installed for $name"
  }
}

$env:OPENUBMC_PLUGIN_HOST_PLATFORM = "win32"
$env:OPENUBMC_PLUGIN_WSL_EXE = Join-Path $WorkRoot "missing-wsl.exe"
foreach ($capability in @("runtime", "kb")) {
  $request = @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}',
    '{"jsonrpc":"2.0","method":"notifications/initialized"}',
    '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  )
  $responses = $request | node (Join-Path $plugin "scripts/openubmc-mcp-bootstrap.js") $capability
  if ($LASTEXITCODE -ne 0) { throw "$capability setup-mode process failed" }
  $initialize = $responses[0] | ConvertFrom-Json
  $tools = $responses[1] | ConvertFrom-Json
  if ($initialize.result.serverInfo.name -ne "openubmc-$capability-setup") {
    throw "$capability setup initialize failed"
  }
  if ($tools.result.tools.name -notcontains "openubmc_setup_status") {
    throw "$capability setup tools are unavailable"
  }
}

@{
  ok = $true
  marketplace = $marketplaceName
  archive = $Archive
  public_identity_verified = [bool]$VerifyPublicIdentity
  capabilities = @("runtime", "kb")
} | ConvertTo-Json -Compress
