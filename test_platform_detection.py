"""Test script to verify platform detection for new AI services."""

from ai_usage_evidence_analyzer.signatures import match_domain, ALL_SIGNATURES

print("=" * 70)
print("Testing AI Platform Detection for New Enterprise Services")
print("=" * 70)

# Test cases for new platforms
test_cases = [
    # Adobe Firefly
    ("https://firefly.adobe.com/generate", "Adobe Firefly"),
    ("firefly.adobe.com", "Adobe Firefly"),
    
    # Checkr
    ("https://dashboard.checkr.com/candidates", "Checkr"),
    ("app.checkr.com", "Checkr"),
    
    # Tidio
    ("https://panel.tidio.com/dashboard", "Tidio"),
    ("tidio.com", "Tidio"),
    
    # Lindy
    ("https://app.lindy.ai/agents", "Lindy"),
    ("lindy.ai", "Lindy"),
    
    # Synthesia
    ("https://app.synthesia.io/video", "Synthesia"),
    ("synthesia.io", "Synthesia"),
    
    # Lattice AI
    ("https://app.lattice.com/performance", "Lattice AI"),
    ("lattice.com", "Lattice AI"),
    
    # DataRobot
    ("https://app.datarobot.com/projects", "DataRobot"),
    ("datarobot.com", "DataRobot"),
    
    # Leena AI
    ("https://app.leena.ai/dashboard", "Leena AI"),
    ("leena.ai", "Leena AI"),
    
    # Nexos AI
    ("https://app.nexos.ai/supply-chain", "Nexos AI"),
    ("nexos.ai", "Nexos AI"),
]

print("\n✓ Domain Detection Tests:")
print("-" * 70)

passed = 0
failed = 0

for url, expected_platform in test_cases:
    detected = match_domain(url)
    if detected and detected.value == expected_platform:
        print(f"✓ {url:50s} → {detected.value}")
        passed += 1
    else:
        print(f"✗ {url:50s} → Expected: {expected_platform}, Got: {detected}")
        failed += 1

print("-" * 70)
print(f"\nTest Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")

if failed == 0:
    print("\n🎉 All detection tests passed!")
else:
    print(f"\n⚠️  {failed} test(s) failed")

print("\n" + "=" * 70)
print("Platform detection system ready for forensic analysis!")
print("=" * 70)
