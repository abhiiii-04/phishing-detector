# Phish-Detect Test Script
# Run this to verify all URL variants work correctly

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "PHISH-DETECT VERIFICATION TEST" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

# Test 1: https://www.nidoos.ae/
Write-Host "[TEST 1] Testing: https://www.nidoos.ae/" -ForegroundColor Yellow
$result1 = Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method Post -ContentType "application/json" -Body '{"url": "https://www.nidoos.ae/"}'
Write-Host "  Status:     " -NoNewline; Write-Host $result1.status.ToUpper() -ForegroundColor $(if($result1.status -eq "secure"){"Green"}else{"Red"})
Write-Host "  Confidence: $($result1.confidence * 100)%"
Write-Host "  Source:     $($result1.source)"
Write-Host ""

# Test 2: www.nidoos.ae
Write-Host "[TEST 2] Testing: www.nidoos.ae" -ForegroundColor Yellow
$result2 = Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method Post -ContentType "application/json" -Body '{"url": "www.nidoos.ae"}'
Write-Host "  Status:     " -NoNewline; Write-Host $result2.status.ToUpper() -ForegroundColor $(if($result2.status -eq "secure"){"Green"}else{"Red"})
Write-Host "  Confidence: $($result2.confidence * 100)%"
Write-Host "  Source:     $($result2.source)"
Write-Host ""

# Test 3: nidoos.ae
Write-Host "[TEST 3] Testing: nidoos.ae" -ForegroundColor Yellow
$result3 = Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method Post -ContentType "application/json" -Body '{"url": "nidoos.ae"}'
Write-Host "  Status:     " -NoNewline; Write-Host $result3.status.ToUpper() -ForegroundColor $(if($result3.status -eq "secure"){"Green"}else{"Red"})
Write-Host "  Confidence: $($result3.confidence * 100)%"
Write-Host "  Source:     $($result3.source)"
Write-Host ""

# Test 4: Malicious URL
Write-Host "[TEST 4] Testing: secure-login-verify-account..." -ForegroundColor Yellow
$result4 = Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method Post -ContentType "application/json" -Body '{"url": "http://secure-login-verify-account-88234-update.xyz/auth/session-id-99/"}'
Write-Host "  Status:     " -NoNewline; Write-Host $result4.status.ToUpper() -ForegroundColor $(if($result4.status -eq "malicious"){"Red"}else{"Green"})
Write-Host "  Confidence: $($result4.confidence * 100)%"
Write-Host "  Source:     $($result4.source)"
Write-Host ""

# Summary
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

$allSecure = ($result1.status -eq "secure") -and ($result2.status -eq "secure") -and ($result3.status -eq "secure")
$maliciousDetected = ($result4.status -eq "malicious")
$allWhitelisted = ($result1.source -eq "Trusted Domain Whitelist") -and ($result2.source -eq "Trusted Domain Whitelist") -and ($result3.source -eq "Trusted Domain Whitelist")

if ($allSecure -and $maliciousDetected -and $allWhitelisted) {
    Write-Host "✓ ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host "  - All nidoos.ae variants: SECURE (100% confidence, Whitelist)" -ForegroundColor Green
    Write-Host "  - Malicious URL: DETECTED (AI Neural Network)" -ForegroundColor Green
} else {
    Write-Host "✗ SOME TESTS FAILED" -ForegroundColor Red
    if (-not $allSecure) { Write-Host "  - nidoos.ae variants not all secure" -ForegroundColor Red }
    if (-not $maliciousDetected) { Write-Host "  - Malicious URL not detected" -ForegroundColor Red }
    if (-not $allWhitelisted) { Write-Host "  - nidoos.ae not using whitelist" -ForegroundColor Red }
}

Write-Host ""
