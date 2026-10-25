# AVE Access Probe: use a free GitHub macOS runner to build the real unsigned IPA.
# This script creates ONLY a new public repository with the included app sources.
# It does not touch or modify any iPhone and never asks for an Apple ID/password.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
  Write-Host "`n=== AVE ACCESS PROBE : FREE IOS APP BUILD ===" -ForegroundColor Cyan
  Write-Host 'This will create a public GitHub repository with the app source files in this folder.'
  Write-Host 'It will NOT upload firmware, logs, phone identifiers, Apple IDs or passwords.'
  $answer = Read-Host 'Proceed with PUBLIC GitHub source repository? Type YES'
  if ($answer -cne 'YES') { throw 'Cancelled before any remote changes.' }

  $winget = Get-Command winget -ErrorAction SilentlyContinue
  function Refresh-Commands {
    $dirs = @(
      "$env:ProgramFiles\Git\cmd", "$env:ProgramFiles\GitHub CLI",
      "$env:LOCALAPPDATA\Microsoft\WinGet\Links"
    )
    foreach ($dir in $dirs) { if ((Test-Path $dir) -and ($env:PATH -notlike "*$dir*")) { $env:PATH = "$dir;$env:PATH" } }
  }
  function Require-Tool([string]$command,[string]$package) {
    Refresh-Commands
    if (Get-Command $command -ErrorAction SilentlyContinue) { return }
    if (-not $winget) { throw "Missing $command. Install $package (free) and run this helper again." }
    Write-Host "Installing free $command with winget..." -ForegroundColor Cyan
    & winget install --id $package --exact --source winget --accept-package-agreements --accept-source-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) { throw "Could not install $command. Try installing $package from its official website." }
    Refresh-Commands
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Installed $command, but your current terminal cannot see it. Reopen PowerShell and rerun." }
  }
  Require-Tool 'git' 'Git.Git'
  Require-Tool 'gh' 'GitHub.cli'

  $oldPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & gh auth status -h github.com *> $null
    $isAuthenticated = ($LASTEXITCODE -eq 0)
  } finally { $ErrorActionPreference = $oldPreference }
  if (-not $isAuthenticated) {
    Write-Host "`nSign into a FREE GitHub account in your browser:" -ForegroundColor Cyan
    & gh auth login --hostname github.com --git-protocol https --web
    if ($LASTEXITCODE -ne 0) { throw 'GitHub browser login was not completed.' }
  }
  & gh auth setup-git
  if ($LASTEXITCODE -ne 0) { throw 'Could not configure GitHub git authentication.' }
  $user = (& gh api user --jq '.login' | Select-Object -First 1).Trim()
  if (!$user) { throw 'Could not determine GitHub account name.' }
  $repo = 'AVEAccessProbe-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
  $slug = "$user/$repo"
  Write-Host "`nRepository: https://github.com/$slug" -ForegroundColor Cyan

  if (-not (Test-Path -LiteralPath '.git')) {
    & git init -b main
    if ($LASTEXITCODE -ne 0) { throw 'git init failed.' }
  }
  $localName = (& git config --local user.name)
  if (!$localName) { & git config --local user.name 'AVE Probe Builder' }
  $localEmail = (& git config --local user.email)
  if (!$localEmail) { & git config --local user.email "$user@users.noreply.github.com" }
  & git add -- 'AVEAccessProbe' '.github/workflows/build-ipa.yml' 'project.yml' 'README.md' '.gitignore' 'BUILD-ON-WINDOWS.ps1'
  if ($LASTEXITCODE -ne 0) { throw 'git add failed.' }
  & git commit -m 'Add safe AppleAVE2 iOS access diagnostic'
  if ($LASTEXITCODE -ne 0) { throw 'git commit failed.' }
  & git branch -M main
  if ($LASTEXITCODE -ne 0) { throw 'git branch failed.' }
  Write-Host "`nUploading code and triggering a free macOS/Xcode build..." -ForegroundColor Cyan
  & gh repo create $slug --public --source . --remote origin --push
  if ($LASTEXITCODE -ne 0) { throw "Repository creation or push failed. Check https://github.com/$slug" }

  $runId = ''
  for ($n=0; $n -lt 24; $n++) {
    Start-Sleep -Seconds 5
    $candidate = & gh run list -R $slug --workflow build-ipa.yml --branch main --limit 1 --json databaseId --jq '.[0].databaseId'
    if ($LASTEXITCODE -eq 0 -and $candidate -match '^\d+$') { $runId = [string]$candidate; break }
  }
  if (!$runId) { throw "Build may be waiting. Open https://github.com/$slug/actions and select 'Build unsigned iOS probe'." }
  Write-Host "`nWaiting for the actual iOS app to compile on GitHub's Mac..." -ForegroundColor Cyan
  & gh run watch $runId -R $slug --exit-status
  if ($LASTEXITCODE -ne 0) { throw "Build failed. Review https://github.com/$slug/actions/runs/$runId for compiler errors." }
  $output = Join-Path $root 'build-output'
  New-Item -ItemType Directory -Force -Path $output | Out-Null
  & gh run download $runId -R $slug --name AVEAccessProbe-Unsigned --dir $output
  if ($LASTEXITCODE -ne 0) { throw "Build succeeded but download failed. View https://github.com/$slug/actions/runs/$runId" }
  $ipa = Join-Path $output 'AVEAccessProbe-Unsigned.ipa'
  if (-not (Test-Path -LiteralPath $ipa)) { throw 'Downloaded artifact did not contain the expected IPA.' }
  Write-Host "`nSUCCESS: Real iOS ARM64 app was built." -ForegroundColor Green
  Write-Host "Unsigned IPA: $ipa" -ForegroundColor Green
  Write-Host 'NEXT: Use Sideloadly (https://sideloadly.io/) to sign/install this IPA with a FREE Apple ID.'
  Write-Host 'On the iPhone open AVE Access Probe, tap Run connection check, then Copy results.'
  Start-Process explorer.exe -ArgumentList ('"' + $output + '"')
} catch {
  Write-Host "`nSTOPPED: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host 'This script has NOT touched or modified your iPhone.'
  exit 1
} finally { Pop-Location }
