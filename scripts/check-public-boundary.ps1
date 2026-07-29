[CmdletBinding()]
param()

# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = "Stop"

function Fail {
    param([string]$Message)
    Write-Error $Message
    exit 1
}

$repositoryRoot = (& git rev-parse --show-toplevel 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $repositoryRoot) {
    Fail "This check must run inside a Git repository."
}

$repositoryRoot = [IO.Path]::GetFullPath($repositoryRoot.Trim())
$candidateFiles = @(& git -C $repositoryRoot ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE -ne 0) {
    Fail "Unable to enumerate tracked and unignored files."
}

$requiredPublicFiles = @(
    "LICENSE",
    "NOTICE",
    "CITATION.cff",
    "TRADEMARKS.md",
    "CONTRIBUTING.md",
    "DUAL_USE_POLICY.md",
    "SECURITY.md",
    "docs/decisions/0005-topic-00-project-constitution.md",
    "docs/decisions/0006-topic-01-evidence-go-no-go.md",
    "docs/governance/publication-and-ip-review.md",
    "docs/research/claims-register.md",
    "docs/research/prior-art-and-interoperability.md",
    "docs/research/predeclared-comparison-protocol.md"
)

$forbiddenExactPaths = @(
    "TRUSCOR_Bible_v4_0.md",
    "SOVA_TRUSCOR_Patent_and_Publication_Strategy_v1_0.md",
    "SOVA_OSS_Master_Idea_Doc_v4_7_FINAL.md",
    "Atlas_MCP_Confidential_Technical_Report_v1.0 (1).pdf",
    "SOVA_OSS_PARTS_INDEX.md"
)

$forbiddenPathSegments = @(
    "private",
    "confidential",
    "private-corpus",
    "matched-loss",
    "client-data",
    "client-findings",
    "truscor-engine",
    "tafa ar",
    "trade-secrets",
    "internal-only",
    "honeypot-internal",
    "atlas-confidential",
    "artifacts/private",
    "browser-profiles",
    "receipts"
)

$forbiddenSecretPaths = @(
    ".env",
    ".env.local",
    ".env.production"
)

$violations = [Collections.Generic.List[string]]::new()

foreach ($requiredFile in $requiredPublicFiles) {
    if ($candidateFiles -notcontains $requiredFile) {
        $violations.Add("required public governance file is missing: $requiredFile")
    }
}

foreach ($candidateFile in $candidateFiles) {
    $normalized = $candidateFile.Replace("\", "/").TrimStart([char[]]"./")
    $lower = $normalized.ToLowerInvariant()

    if ($forbiddenExactPaths -contains $normalized) {
        $violations.Add("forbidden tracked file: $normalized")
    }

    foreach ($segment in $forbiddenPathSegments) {
        if (("/$lower/").Contains("/$($segment.ToLowerInvariant())/")) {
            $violations.Add("forbidden path class '$segment': $normalized")
        }
    }

    if (($forbiddenSecretPaths -contains $lower) -or
        ($lower.StartsWith(".env.") -and $lower -ne ".env.example")) {
        $violations.Add("local secret configuration is tracked: $normalized")
    }

    if ($lower -match '\.(pem|key|p12|pfx)$') {
        $violations.Add("private key or certificate container is tracked: $normalized")
    }
}

$textExtensions = @(
    ".md", ".txt", ".cff", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini",
    ".xml", ".html", ".css", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".rs", ".go", ".java", ".kt", ".swift", ".rb", ".php", ".sh",
    ".ps1", ".psm1", ".cs", ".cpp", ".c", ".h", ".hpp", ".sql"
)

$contentExclusions = @(
    ".gitignore",
    "scripts/check-public-boundary.ps1",
    "docs/governance/public-repository-boundary.md",
    "docs/governance/publication-and-ip-review.md",
    "docs/decisions/0003-open-source-and-proprietary-boundary.md"
)

$secretPatterns = [ordered]@{
    "private key" = '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
    "GitHub token" = '\bgh[pousr]_[A-Za-z0-9_]{20,}\b'
    "AWS access key" = '\b(AKIA|ASIA)[A-Z0-9]{16}\b'
    "Google API key" = '\bAIza[0-9A-Za-z_-]{30,}\b'
    "OpenAI-style API key" = '\bsk-[A-Za-z0-9_-]{20,}\b'
}

$confidentialMarkers = @(
    "TRUSCOR CONFIDENTIAL",
    "CLIENT CONFIDENTIAL",
    "SOVA PRIVATE",
    "ATLAS CONFIDENTIAL",
    "TRADE SECRET"
)

$claimControlExclusions = @(
    "docs/research/claims-register.md",
    "docs/research/prior-art-and-interoperability.md",
    "docs/governance/publication-and-ip-review.md",
    "docs/decisions/0006-topic-01-evidence-go-no-go.md"
)

$retiredClaimPatterns = [ordered]@{
    "conditional-trigger category described as unoccupied" = 'conditional[- ]trigger.{0,80}\b(unoccupied|nobody)\b'
    "attacker/recorder exclusivity claim" = '\bonly system where the attacker and (the )?recorder\b'
    "universal attack-to-evidence absence claim" = '\bnobody connects.{0,120}\b(attack|evidence)\b'
    "counterfactual attribution described as unaddressed" = '\bcounterfactual.{0,80}\bunaddressed\b'
    "universal reproduction-rate novelty claim" = '\b(reproduction rate|semantic reproduction).{0,80}\bnobody\b'
    "Phantom Fuzzer unmatched claim" = '\bPhantom Fuzzer.{0,80}\bunmatched\b'
    "obsolete blanket EU enforcement date" = '\benforcement powers (activate|activated) (on )?2 August 2026\b'
    "adversarial-testing-specific fine claim" = '\b(EUR\s*)?15\s*(million|m).{0,80}\badversarial[- ]testing\b'
}

foreach ($candidateFile in $candidateFiles) {
    $normalized = $candidateFile.Replace("\", "/")
    if ($contentExclusions -contains $normalized) {
        continue
    }

    $extension = [IO.Path]::GetExtension($normalized).ToLowerInvariant()
    $leaf = [IO.Path]::GetFileName($normalized)
    if (($textExtensions -notcontains $extension) -and
        ($leaf -notin @("LICENSE", "NOTICE"))) {
        continue
    }

    $absolute = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $normalized))
    if (-not $absolute.StartsWith($repositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $violations.Add("tracked path escaped repository root: $normalized")
        continue
    }

    if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        $violations.Add("tracked file is missing from checkout: $normalized")
        continue
    }

    $content = [IO.File]::ReadAllText($absolute)

    foreach ($entry in $secretPatterns.GetEnumerator()) {
        if ([regex]::IsMatch($content, $entry.Value)) {
            $violations.Add("possible $($entry.Key) in $normalized")
        }
    }

    foreach ($marker in $confidentialMarkers) {
        if ($content.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $violations.Add("confidentiality marker '$marker' in $normalized")
        }
    }

    if (($extension -eq ".md") -and
        ($claimControlExclusions -notcontains $normalized)) {
        foreach ($entry in $retiredClaimPatterns.GetEnumerator()) {
            if ([regex]::IsMatch(
                $content,
                $entry.Value,
                [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                [Text.RegularExpressions.RegexOptions]::Singleline
            )) {
                $violations.Add("retired public claim '$($entry.Key)' in $normalized")
            }
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host "PUBLIC_BOUNDARY_CHECK=FAILED"
    foreach ($violation in ($violations | Sort-Object -Unique)) {
        Write-Host " - $violation"
    }
    exit 1
}

Write-Host "PUBLIC_BOUNDARY_CHECK=PASS"
Write-Host "TRACKED_OR_UNIGNORED_FILES_SCANNED=$($candidateFiles.Count)"
