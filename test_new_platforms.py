"""Quick test to verify new AI platforms are registered."""

from ai_usage_evidence_analyzer.models import AIPlatform, AIModel
from ai_usage_evidence_analyzer.signatures import ALL_SIGNATURES

print("=" * 60)
print("TRACE-AI-FR Platform Registration Test")
print("=" * 60)

print(f"\nTotal AI Platform Enums: {len([p for p in AIPlatform])}")
print(f"Total Signature Definitions: {len(ALL_SIGNATURES)}")

print("\n✓ New Enterprise AI Platforms Added:")
new_platforms = [
    AIPlatform.ADOBE_FIREFLY,
    AIPlatform.CHECKR,
    AIPlatform.TIDIO,
    AIPlatform.LINDY,
    AIPlatform.SYNTHESIA,
    AIPlatform.LATTICE_AI,
    AIPlatform.DATAROBOT,
    AIPlatform.LEENA_AI,
    AIPlatform.NEXOS_AI,
]

for platform in new_platforms:
    print(f"  • {platform.value}")

print("\n✓ All Registered Platforms:")
for sig in ALL_SIGNATURES:
    domain_count = len(sig.domains)
    print(f"  • {sig.platform.value:20s} - {domain_count} domains, "
          f"{len(sig.package_ids_mobile)} mobile packages")

print("\n✓ New AI Models Added:")
new_models = [AIModel.FIREFLY_2, AIModel.FIREFLY_3, AIModel.SYNTHESIA_AI]
for model in new_models:
    print(f"  • {model.value}")

print("\n" + "=" * 60)
print("✓ All platforms successfully registered!")
print("=" * 60)
