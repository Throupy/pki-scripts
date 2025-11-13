## 13/11/2025
## script to effectively simulate the enrollment process that a cisco device would use 
## (or as close as possible) to test an NDES instance.

## example
# .\Simulate-SCEPEnrollment.ps1 `
#   -ScepUrl "http://ndes001/certsrv/mscep/mscep.dll" `
#   -Otp "FB7D7424C9078C01" `
#   -OutDir "C:\Users\Administrator\Documents\certout"

param (
    [Parameter(Mandatory = $true)]
    [string]$ScepUrl, # should point at /certsrv/mscep.dll

    [Parameter(Mandatory = $true)]
    [string]$Otp, # challenge password / otp

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [string]$CommonName = "NDES-TEST-CLIENT", # foor the cert
    [int]$KeyLength = 2048,
    [switch]$MachineContext
)

$ErrorActionPreference = "Stop"

Write-Host "[*] SCEP URL       : $ScepUrl"
Write-Host "[*] OTP            : $Otp"
Write-Host "[*] Common Name    : $CommonName"
Write-Host "[*] Key Length     : $KeyLength"
Write-Host "[*] MachineContext : $MachineContext"
Write-Host "[*] OutDir         : $OutDir"
Write-Host ""

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

# 1 user- 2 machine (x509EnrolmlentContext)
$enrollmentContext = if ($MachineContext) { 2 } else { 1 }

# construct pcks10
$pkcs10 = New-Object -ComObject "X509Enrollment.CX509CertificateRequestPkcs10"
$pkcs10.Initialize([int]$enrollmentContext)

$subject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
$subject.Encode("CN=$CommonName")
$pkcs10.Subject = $subject

$pkcs10.KeyContainerNamePrefix = "NDES_PS_"
$pkcs10.ChallengePassword      = $Otp
$pkcs10.PrivateKey.Length      = $KeyLength

# lucky a 509scep enrollment hleper exists :)
$helper = New-Object -ComObject "X509Enrollment.CX509SCEPEnrollmentHelper"
$helper.Initialize($ScepUrl, [string]::Empty, $pkcs10, [string]::Empty)

$SCEPProcessDefault = 0
$disposition = $helper.Enroll($SCEPProcessDefault)

$SCEPDispositionSuccess = 0
$SCEPDispositionFailure = 2

# determine response code
switch ($disposition) {
    $SCEPDispositionFailure {
        throw "SCEP enrollment failed: $($helper.ResultMessageText)"
    }

    $SCEPDispositionSuccess {
        # 0 = XCN_CRYPT_STRING_BASE64HEADER
        $XCN_CRYPT_STRING_BASE64HEADER = 0
        $certPem = $helper.X509SCEPEnrollment.Certificate($XCN_CRYPT_STRING_BASE64HEADER)

        $certPath = Join-Path $OutDir "scep-cert.cer"
        [IO.File]::WriteAllText($certPath, $certPem)

        Write-Host ""
        Write-Host "[+] SCEP enrollment succeeded."
        Write-Host "[+] Certificate saved to: $certPath"

        # can use .net to parse but will top and tail b64 first
        $base64Body = $certPem `
            -replace '-----BEGIN CERTIFICATE-----','' `
            -replace '-----END CERTIFICATE-----','' `
            -replace '\s',''

        $rawBytes = [Convert]::FromBase64String($base64Body)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawBytes)

        Write-Host "[+] Subject       : $($cert.Subject)"
        Write-Host "[+] Issuer        : $($cert.Issuer)"
        Write-Host "[+] Serial Number : $($cert.SerialNumber)"
        Write-Host "[+] Thumbprint    : $($cert.Thumbprint)"
    }

    default {
        throw "Unexpected SCEP disposition: $disposition (Message: $($helper.ResultMessageText))"
    }
}