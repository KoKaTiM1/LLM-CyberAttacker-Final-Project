"""
Analyze CVE Statistics from nvd_cves_all.jsonl

This script counts how many CVEs exist for each CWE type we support.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.modules.cve_database import CVEDatabase


def analyze_cve_statistics():
    """Analyze CVE statistics for our supported CWE types"""
    
    print("=" * 80)
    print("  CVE Statistics Analysis")
    print("=" * 80)
    
    # Our supported CWEs mapped to their categories
    cwe_categories = {
        # Command Injection (Top Priority)
        "CWE-77": ("Command Injection", "injection", "🥇 TOP"),
        "CWE-78": ("OS Command Injection", "injection", "🥇 TOP"),
        "CWE-94": ("Code Injection", "injection", "🥇 TOP"),
        
        # Path Traversal (Top Priority - needs to be added)
        "CWE-22": ("Path Traversal", "web_security", "🥇 TOP"),
        
        # Format String (Backup)
        "CWE-134": ("Format String", "injection", "🥈 BACKUP"),
        
        # Memory Corruption
        "CWE-119": ("Buffer Overflow", "memory_corruption", "⚙️ COMPLEX"),
        "CWE-120": ("Buffer Copy without Check", "memory_corruption", "⚙️ COMPLEX"),
        "CWE-121": ("Stack Buffer Overflow", "memory_corruption", "⚙️ COMPLEX"),
        "CWE-122": ("Heap Buffer Overflow", "memory_corruption", "⚙️ COMPLEX"),
        "CWE-125": ("Out-of-bounds Read", "memory_corruption", "⚙️ COMPLEX"),
        "CWE-787": ("Out-of-bounds Write", "memory_corruption", "⚙️ COMPLEX"),
        "CWE-416": ("Use After Free", "memory_corruption", "⚙️ COMPLEX"),
        "CWE-415": ("Double Free", "memory_corruption", "⚙️ COMPLEX"),
        
        # Numeric Errors
        "CWE-190": ("Integer Overflow", "numeric_errors", "⚙️ COMPLEX"),
        "CWE-191": ("Integer Underflow", "numeric_errors", "⚙️ COMPLEX"),
        
        # Web Security
        "CWE-89": ("SQL Injection", "injection", "🔧 MODERATE"),
        "CWE-79": ("XSS", "injection", "🔧 MODERATE"),
        "CWE-352": ("CSRF", "web_security", "🔧 MODERATE"),
        "CWE-918": ("SSRF", "web_security", "🔧 MODERATE"),
    }
    
    print("\n📊 Initializing CVE Database...")
    try:
        db = CVEDatabase()
        stats = db.get_statistics()
        print(f"✅ Database loaded: {stats['total_cves']:,} total CVEs")
        print(f"   File size: {stats['file_size_mb']:.2f} MB\n")
    except Exception as e:
        print(f"❌ Error loading database: {e}")
        return
    
    print("🔍 Counting CVEs for each CWE type...")
    print("   (This may take a few minutes for large databases)\n")
    
    # Count CVEs for each CWE
    results = defaultdict(int)
    
    for cwe_id, (name, category, priority) in cwe_categories.items():
        print(f"   Searching {cwe_id} ({name})...", end=" ", flush=True)
        
        # Search with limit to get count estimate
        cves = db.filter_by_cwe(cwe_id, limit=500)
        count = len(cves)
        
        results[cwe_id] = {
            'name': name,
            'category': category,
            'priority': priority,
            'count': count,
            'sample_cves': [cve.get('id') or cve.get('cve', {}).get('id', 'Unknown') 
                           for cve in cves[:3]]
        }
        
        print(f"Found {count}+")
    
    # Print results by priority
    print("\n" + "=" * 80)
    print("  RESULTS BY PRIORITY")
    print("=" * 80)
    
    # Top Priority (Simple to implement)
    print("\n🥇 TOP PRIORITY - Simplest to Implement:")
    print("-" * 80)
    top_priority = {k: v for k, v in results.items() if v['priority'] == "🥇 TOP"}
    total_top = sum(v['count'] for v in top_priority.values())
    
    for cwe_id, data in sorted(top_priority.items(), key=lambda x: x[1]['count'], reverse=True):
        print(f"\n{data['priority']} {cwe_id}: {data['name']}")
        print(f"   Count: {data['count']}+ CVEs")
        print(f"   Category: {data['category']}")
        if data['sample_cves']:
            print(f"   Samples: {', '.join(data['sample_cves'][:3])}")
    
    print(f"\n   📊 TOTAL TOP PRIORITY: {total_top}+ CVEs")
    
    # Backup options
    print("\n🥈 BACKUP OPTIONS - Still Relatively Simple:")
    print("-" * 80)
    backup = {k: v for k, v in results.items() if v['priority'] == "🥈 BACKUP"}
    total_backup = sum(v['count'] for v in backup.values())
    
    for cwe_id, data in sorted(backup.items(), key=lambda x: x[1]['count'], reverse=True):
        print(f"\n{data['priority']} {cwe_id}: {data['name']}")
        print(f"   Count: {data['count']}+ CVEs")
        print(f"   Category: {data['category']}")
        if data['sample_cves']:
            print(f"   Samples: {', '.join(data['sample_cves'][:3])}")
    
    print(f"\n   📊 TOTAL BACKUP: {total_backup}+ CVEs")
    
    # Moderate complexity
    print("\n🔧 MODERATE COMPLEXITY - Require Infrastructure:")
    print("-" * 80)
    moderate = {k: v for k, v in results.items() if v['priority'] == "🔧 MODERATE"}
    total_moderate = sum(v['count'] for v in moderate.values())
    
    for cwe_id, data in sorted(moderate.items(), key=lambda x: x[1]['count'], reverse=True):
        print(f"\n{data['priority']} {cwe_id}: {data['name']}")
        print(f"   Count: {data['count']}+ CVEs")
        if data['sample_cves']:
            print(f"   Samples: {', '.join(data['sample_cves'][:3])}")
    
    print(f"\n   📊 TOTAL MODERATE: {total_moderate}+ CVEs")
    
    # Complex
    print("\n⚙️ COMPLEX - Memory Corruption & Binary:")
    print("-" * 80)
    complex_types = {k: v for k, v in results.items() if v['priority'] == "⚙️ COMPLEX"}
    total_complex = sum(v['count'] for v in complex_types.values())
    
    for cwe_id, data in sorted(complex_types.items(), key=lambda x: x[1]['count'], reverse=True):
        print(f"\n{data['priority']} {cwe_id}: {data['name']}")
        print(f"   Count: {data['count']}+ CVEs")
        if data['sample_cves']:
            print(f"   Samples: {', '.join(data['sample_cves'][:3])}")
    
    print(f"\n   📊 TOTAL COMPLEX: {total_complex}+ CVEs")
    
    # Grand total
    grand_total = sum(v['count'] for v in results.values())
    print("\n" + "=" * 80)
    print(f"  📊 GRAND TOTAL: {grand_total}+ CVEs across all supported types")
    print("=" * 80)
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    print("-" * 80)
    print(f"✅ Start with TOP PRIORITY: {total_top}+ CVEs available")
    print(f"   - Command Injection (CWE-77, 78, 94)")
    print(f"   - Path Traversal (CWE-22)")
    print(f"\n✅ Add BACKUP if needed: {total_backup}+ CVEs available")
    print(f"   - Format String (CWE-134)")
    print(f"\n⚠️  MODERATE requires DB/Web infrastructure: {total_moderate}+ CVEs")
    print(f"\n⚙️  COMPLEX requires compilation & memory analysis: {total_complex}+ CVEs")
    
    print("\n" + "=" * 80)
    print("  Analysis Complete!")
    print("=" * 80 + "\n")
    
    return results


if __name__ == "__main__":
    try:
        analyze_cve_statistics()
    except KeyboardInterrupt:
        print("\n\n⚠️ Analysis interrupted by user\n")
    except Exception as e:
        print(f"\n\n❌ Error during analysis: {e}\n")
        import traceback
        traceback.print_exc()
