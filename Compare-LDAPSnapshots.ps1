# 11/10/2025
# compare two LDAP snapshotrs, used as part of the PKI investigation for CES and CEP roles with LDAP.

param (
    [Parameter(Mandatory = $true)]
    [string]$BeforeFile,

    [Parameter(Mandatory = $true)]
    [string]$AfterFile
)

Write-Host "[*] Starting LDIF comparison..." -ForegroundColor Cyan
Write-Host "[*] Before file : $BeforeFile" -ForegroundColor DarkCyan
Write-Host "[*] After file  : $AfterFile" -ForegroundColor DarkCyan

if (-not (Test-Path $BeforeFile)) {
    Write-Error "Before file not found: $BeforeFile"
    exit 1
}
if (-not (Test-Path $AfterFile)) {
    Write-Error "After file not found: $AfterFile"
    exit 1
}

function Parse-Ldif {
    param([string]$Path)

    Write-Host "[*] Parsing $Path ..." -ForegroundColor Cyan

    $entries = @{}
    $currentDN = $null
    $currentAttrs = @{}
    $currentAttrName = $null

    $lines = Get-Content $Path
    foreach ($line in $lines) {

        # ldap continuation (folded lines) start with a space, rfc2849
        if ($line -match '^\s' -and $currentAttrName -ne $null -and $currentDN -ne $null) {
            # add to end for new val
            $lastIndex = $currentAttrs[$currentAttrName].Count - 1
            $currentAttrs[$currentAttrName][$lastIndex] += $line.TrimStart()
            continue
        }

        # when we get a new dn
        if ($line -match '^dn:\s*(.+)$') {
            # save prev
            if ($currentDN) {
                $entries[$currentDN] = $currentAttrs
            }
            $currentDN = $matches[1].Trim()
            $currentAttrs = @{}
            $currentAttrName = $null
            continue
        }

        # attrbiute line
        if ($line -match '^(\S+):\s*(.*)$') {
            $attr = $matches[1]
            $val  = $matches[2]

            if (-not $currentAttrs.ContainsKey($attr)) {
                $currentAttrs[$attr] = @()
            }
            $currentAttrs[$attr] += $val
            $currentAttrName = $attr
            continue
        }
    }

    # ultimate
    if ($currentDN) {
        $entries[$currentDN] = $currentAttrs
    }

    Write-Host "[*] Parsed $($entries.Count) LDAP objects from $Path" -ForegroundColor Green
    return $entries
}

$before = Parse-Ldif $BeforeFile
$after  = Parse-Ldif $AfterFile

Write-Host "[*] Comparing entries..." -ForegroundColor Cyan

# check if there anything new totallyt created
$allDNs = ($before.Keys + $after.Keys) | Sort-Object -Unique
$results = @()

foreach ($dn in $allDNs) {
    $inBefore = $before.ContainsKey($dn)
    $inAfter  = $after.ContainsKey($dn)

    if (-not $inAfter) {
        Write-Host "`n[-] REMOVED: $dn" -ForegroundColor Red
        $results += [pscustomobject]@{
            DN       = $dn
            Change   = "Removed"
            Attribute = ""
            Before   = ""
            After    = ""
        }
        continue
    }

    if (-not $inBefore) {
        Write-Host "`n[+] ADDED:   $dn" -ForegroundColor Green
        $results += [pscustomobject]@{
            DN       = $dn
            Change   = "Added"
            Attribute = ""
            Before   = ""
            After    = ""
        }
        continue
    }

    # if exist in both we need to start comparing attrs
    # where i am doing this for entire contexts (e.g configuration)
    # this might take a while
    # should probably optimise somehow but wont rn
    $beforeAttrs = $before[$dn]
    $afterAttrs  = $after[$dn]

    $allAttrs = ($beforeAttrs.Keys + $afterAttrs.Keys) | Sort-Object -Unique
    $modifiedThisDN = $false

    foreach ($attr in $allAttrs) {

        $beforeVal = $null
        $afterVal  = $null

        if ($beforeAttrs.ContainsKey($attr)) {
            $beforeVal = ($beforeAttrs[$attr] -join "`n")
        }
        if ($afterAttrs.ContainsKey($attr)) {
            $afterVal = ($afterAttrs[$attr] -join "`n")
        }

        if ($beforeVal -ne $afterVal) {
            if (-not $modifiedThisDN) {
                Write-Host "`n[~] MODIFIED: $dn" -ForegroundColor Yellow
                $modifiedThisDN = $true
            }

            Write-Host "=====>  Attribute: $attr" -ForegroundColor Yellow
            Write-Host "      Before:" -ForegroundColor DarkYellow
            Write-Host ($beforeVal | ForEach-Object { "        $_" })
            Write-Host "      After :" -ForegroundColor DarkYellow
            Write-Host ($afterVal | ForEach-Object { "        $_" })

            $results += [pscustomobject]@{
                DN        = $dn
                Change    = "Modified"
                Attribute = $attr
                Before    = $beforeVal
                After     = $afterVal
            }
        }
    }
}

Write-Host "`n[*] Comparison complete." -ForegroundColor Green

Write-Host "`n==== SUMMARY ====" -ForegroundColor Cyan
$results |
    Sort-Object DN, Change |
    Format-Table DN, Change, Attribute -AutoSize



Write-Host "Done. thx 4 using" -ForegroundColor Green
