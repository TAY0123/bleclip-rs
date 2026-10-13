# PowerShell publishing fallback for Windows.
$ErrorActionPreference = 'Stop'
$Owner = 'TAY0123'
$Repo = "$Owner/bleclip-rs"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Install Git first.' }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'Install GitHub CLI (gh) first.' }

gh auth status 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login before publishing.' }
$ConnectedUser = (& gh api user --jq .login).Trim()
if ($LASTEXITCODE -ne 0 -or $ConnectedUser -ne $Owner) {
    throw "Authenticated as '$ConnectedUser', expected '$Owner'. Use gh auth switch -u $Owner."
}

gh repo view $Repo --json name 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw "Repository $Repo already exists; refusing to overwrite it." }

if (-not (Test-Path -LiteralPath '.git')) {
    git init -b main
    if ($LASTEXITCODE -ne 0) { throw 'git init failed.' }
}
if ((& git remote | Measure-Object -Line).Lines -gt 0) {
    throw 'Existing git remotes found; refusing to alter them.'
}

git add -- .github .gitignore Cargo.toml LICENSE README.md SECURITY.md src publish-github.sh publish-github.ps1
if ($LASTEXITCODE -ne 0) { throw 'git add failed.' }
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    git commit -m 'Initial public release: encrypted multi-peer BLE clipboard sync'
    if ($LASTEXITCODE -ne 0) { throw 'git commit failed; configure git user.name and user.email.' }
}

gh repo create $Repo --public `
  --description 'Rust serverless encrypted multi-peer BLE clipboard sync for Windows and Linux (experimental)' `
  --source . --remote origin --push
if ($LASTEXITCODE -ne 0) { throw 'GitHub repository creation or push failed.' }
Write-Output "Published: https://github.com/$Repo"
