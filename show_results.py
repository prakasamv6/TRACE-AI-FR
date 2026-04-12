"""Display forensic analysis results summary."""
import json

# Load findings
with open('demo_output_enhanced/ENHANCED-2026_findings.json', 'r') as f:
    data = json.load(f)

print("=" * 80)
print("TRACE-AI-FR ENHANCED FORENSIC ANALYSIS RESULTS")
print("=" * 80)

# Case metadata
print("\n📋 CASE INFORMATION")
print("-" * 80)
print(f"Case ID:       {data['case_info']['case_id']}")
print(f"Case Name:     {data['case_info']['case_name']}")
print(f"Evidence ID:   {data['evidence_info']['evidence_item_id']}")
print(f"Examiner:      {data['case_info']['examiner']}")
print(f"Analysis Date: {data['generated_at']}")
print(f"Framework:     {data['tool']} v{data['version']}")

# Artifact statistics
print("\n📊 ARTIFACT STATISTICS")
print("-" * 80)
print(f"Total Artifacts Found:     {len(data['artifacts'])}")
print(f"Timeline Events:           {len(data['timeline'])}")
print(f"AI Footprints:             {len(data['ai_usage_footprints'])}")
print(f"FRAUEs Generated:          {len(data['fraues'])}")

# Detected AI platforms
print("\n🤖 DETECTED AI PLATFORMS")
print("-" * 80)
platforms = {}
for artifact in data['artifacts']:
    platform = artifact.get('suspected_platform')
    if platform and platform not in ['Unknown', None]:
        platforms[platform] = platforms.get(platform, 0) + 1

if platforms:
    print(f"Found evidence of {len(platforms)} AI platform(s):\n")
    for platform, count in sorted(platforms.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {platform:20s} - {count:3d} artifact(s)")
else:
    print("  No AI platform artifacts found in demo evidence")

# Artifact families
print("\n📁 ARTIFACT FAMILIES FOUND")
print("-" * 80)
families = {}
for artifact in data['artifacts']:
    family = artifact.get('artifact_family')
    if family:
        families[family] = families.get(family, 0) + 1

for family, count in sorted(families.items(), key=lambda x: x[1], reverse=True):
    print(f"  • {family:30s} - {count:3d} artifact(s)")

# Parser execution
print("\n⚙️  PARSER EXECUTION SUMMARY")
print("-" * 80)
parser_results = data['parser_results']
parsers_executed = {p['parser']: p['version'] for p in parser_results}
print(f"Total Parsers Executed: {len(parsers_executed)}\n")

# Show new parsers (v2.0.0 are the enhanced ones)
enhanced_parsers = []
for name, version in parsers_executed.items():
    if version == "2.0.0" or "Android" in name or "Samsung" in name:
        enhanced_parsers.append((name, version))

if enhanced_parsers:
    print("🆕 Enhanced/New Parsers (v2.0.0):")
    for name, version in sorted(enhanced_parsers):
        print(f"  ✓ {name:40s} v{version}")
else:
    print("  (No v2.0.0 parsers - running on standard parsers)")

# Show sample of all parsers
print(f"\n📝 Sample Parsers Executed (showing first 15):")
for i, (name, version) in enumerate(sorted(parsers_executed.items())[:15]):
    print(f"  • {name:40s} v{version}")

# Evidence coverage
print("\n🗂️  EVIDENCE COVERAGE")
print("-" * 80)
coverage = data['evidence_coverage']
print(f"Detected OS:             {coverage['os_detected']}")
print(f"Browsers Found:          {', '.join(coverage['browsers_detected'])}")
print(f"User Profiles:           {', '.join(coverage['user_profiles_found'])}")
print(f"Artifact Families:       {len(coverage['artifact_families_available'])} available")

print("\n" + "=" * 80)
print("✅ Enhanced forensic analysis complete!")
print("=" * 80)
print(f"\nReports generated in: demo_output_enhanced/")
print(f"  • HTML Report:  ENHANCED-2026_report.html")
print(f"  • MD Report:    ENHANCED-2026_report.md")
print(f"  • DOCX Report:  ENHANCED-2026_report.docx")
print(f"  • SQLite DB:    ENHANCED-2026_findings.sqlite")
print(f"  • JSON Data:    ENHANCED-2026_findings.json")
print("\n💡 View the HTML report in your browser for full interactive results!")
print("\n🎉 NEW: This version now supports 17 AI platforms including:")
print("  • Adobe Firefly, Checkr, Tidio, Lindy, Synthesia")
print("  • Lattice AI, DataRobot, Leena AI, Nexos AI")
print("  • Plus enhanced Windows Event Log, macOS Unified Log, and")
print("  • iPhone KnowledgeC/DataUsage, and full Android/Samsung support!")
print("=" * 80)

print("\n" + "=" * 80)
print("✅ Enhanced forensic analysis complete!")
print("=" * 80)
print(f"\nReports generated in: demo_output_enhanced/")
print(f"  • HTML Report:  ENHANCED-2026_report.html")
print(f"  • MD Report:    ENHANCED-2026_report.md")
print(f"  • DOCX Report:  ENHANCED-2026_report.docx")
print(f"  • SQLite DB:    ENHANCED-2026_findings.sqlite")
print(f"  • JSON Data:    ENHANCED-2026_findings.json")
