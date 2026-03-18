"""
CVE Database Module

Manages loading and querying CVE data from nvd_cves_all.jsonl file.
Provides filtering capabilities by CVE ID, CWE, vendor, severity, etc.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


logger = logging.getLogger(__name__)


class CVEDatabase:
    """
    Database interface for CVE data stored in JSONL format.
    Provides efficient querying and filtering capabilities.
    """
    
    def __init__(self, jsonl_path: Optional[str] = None):
        """
        Initialize CVE Database
        
        Args:
            jsonl_path: Path to the JSONL file containing CVE data.
                       If None, uses default path: data/nvd_cves_all.jsonl
        """
        if jsonl_path is None:
            # Default path relative to project root
            base_dir = Path(__file__).parent.parent.parent
            jsonl_path = base_dir / "data" / "nvd_cves_all.jsonl"
        
        self.jsonl_path = Path(jsonl_path)
        self._cve_cache = {}  # Optional: cache for loaded CVEs
        self._index_built = False
        
        if not self.jsonl_path.exists():
            logger.error(f"CVE database file not found: {self.jsonl_path}")
            raise FileNotFoundError(f"CVE database not found: {self.jsonl_path}")
        
        logger.info(f"CVE Database initialized with: {self.jsonl_path}")
        logger.info(f"File size: {self.jsonl_path.stat().st_size / (1024*1024):.2f} MB")
    
    def _load_jsonl_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single line from JSONL file
        
        Args:
            line: JSON string line
            
        Returns:
            Parsed dictionary or None if parsing fails
        """
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON line: {e}")
            return None
    
    def get_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CVE data by CVE ID
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
            
        Returns:
            CVE data dictionary or None if not found
        """
        # Normalize CVE ID
        cve_id = cve_id.upper().strip()
        
        # Check cache first
        if cve_id in self._cve_cache:
            logger.debug(f"CVE {cve_id} found in cache")
            return self._cve_cache[cve_id]
        
        # Search in file
        logger.info(f"Searching for CVE: {cve_id}")
        
        try:
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    cve_data = self._load_jsonl_line(line)
                    if not cve_data:
                        continue
                    
                    # Check multiple possible ID locations
                    current_id = (
                        cve_data.get('id') or 
                        cve_data.get('cve', {}).get('id') or
                        cve_data.get('cve_id')
                    )
                    
                    if current_id and current_id.upper() == cve_id:
                        logger.info(f"Found {cve_id} at line {line_num}")
                        # Cache for future use
                        self._cve_cache[cve_id] = cve_data
                        return cve_data
                    
                    # Progress indicator for large files
                    if line_num % 10000 == 0:
                        logger.debug(f"Searched {line_num} entries...")
            
            logger.warning(f"CVE {cve_id} not found in database")
            return None
            
        except Exception as e:
            logger.error(f"Error reading CVE database: {e}")
            return None
    
    def filter_by_cwe(self, cwe_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Filter CVEs by CWE (Common Weakness Enumeration)
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-119" or "119")
            limit: Maximum number of results to return
            
        Returns:
            List of matching CVE dictionaries
        """
        # Normalize CWE ID
        if not cwe_id.upper().startswith('CWE-'):
            cwe_id = f"CWE-{cwe_id}"
        cwe_id = cwe_id.upper()
        
        logger.info(f"Filtering CVEs by CWE: {cwe_id} (limit: {limit})")
        
        results = []
        
        try:
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if len(results) >= limit:
                        break
                    
                    if not line.strip():
                        continue
                    
                    cve_data = self._load_jsonl_line(line)
                    if not cve_data:
                        continue
                    
                    # Check for CWE in various locations
                    if self._has_cwe(cve_data, cwe_id):
                        results.append(cve_data)
                        logger.debug(f"Found match at line {line_num}")
                    
                    if line_num % 10000 == 0:
                        logger.debug(f"Searched {line_num} entries, found {len(results)} matches")
            
            logger.info(f"Found {len(results)} CVEs with {cwe_id}")
            return results
            
        except Exception as e:
            logger.error(f"Error filtering by CWE: {e}")
            return []
    
    def _has_cwe(self, cve_data: Dict, cwe_id: str) -> bool:
        """
        Check if CVE data contains specific CWE
        
        Args:
            cve_data: CVE data dictionary
            cwe_id: CWE identifier to search for
            
        Returns:
            True if CWE is found
        """
        # Check direct cwe field
        if 'cwe' in cve_data:
            cwe_value = cve_data['cwe']
            if not cwe_value.upper().startswith('CWE-'):
                cwe_value = f"CWE-{cwe_value}"
            if cwe_value.upper() == cwe_id:
                return True
        
        # Check weaknesses array (NVD format)
        if 'weaknesses' in cve_data:
            for weakness in cve_data['weaknesses']:
                for desc in weakness.get('description', []):
                    if desc.get('value', '').upper() == cwe_id:
                        return True
        
        # Check nested cve.weaknesses
        if 'cve' in cve_data and 'weaknesses' in cve_data['cve']:
            for weakness in cve_data['cve']['weaknesses']:
                for desc in weakness.get('description', []):
                    if desc.get('value', '').upper() == cwe_id:
                        return True
        
        return False
    
    def filter_by_vendor(self, vendor: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Filter CVEs by vendor/manufacturer name
        
        Args:
            vendor: Vendor name (e.g., "Microsoft", "Apache", "Linux")
            limit: Maximum number of results to return
            
        Returns:
            List of matching CVE dictionaries
        """
        vendor_lower = vendor.lower()
        logger.info(f"Filtering CVEs by vendor: {vendor} (limit: {limit})")
        
        results = []
        
        try:
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if len(results) >= limit:
                        break
                    
                    if not line.strip():
                        continue
                    
                    cve_data = self._load_jsonl_line(line)
                    if not cve_data:
                        continue
                    
                    # Search vendor in description
                    description = self._extract_description(cve_data)
                    if description and vendor_lower in description.lower():
                        results.append(cve_data)
                        logger.debug(f"Found match at line {line_num}")
                    
                    if line_num % 10000 == 0:
                        logger.debug(f"Searched {line_num} entries, found {len(results)} matches")
            
            logger.info(f"Found {len(results)} CVEs for vendor '{vendor}'")
            return results
            
        except Exception as e:
            logger.error(f"Error filtering by vendor: {e}")
            return []
    
    def filter_by_severity(self, min_score: float = 7.0, max_score: float = 10.0, 
                          limit: int = 100) -> List[Dict[str, Any]]:
        """
        Filter CVEs by CVSS score range
        
        Args:
            min_score: Minimum CVSS score (0.0-10.0)
            max_score: Maximum CVSS score (0.0-10.0)
            limit: Maximum number of results to return
            
        Returns:
            List of matching CVE dictionaries
        """
        logger.info(f"Filtering CVEs by severity: {min_score}-{max_score} (limit: {limit})")
        
        results = []
        
        try:
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if len(results) >= limit:
                        break
                    
                    if not line.strip():
                        continue
                    
                    cve_data = self._load_jsonl_line(line)
                    if not cve_data:
                        continue
                    
                    cvss_score = self._extract_cvss_score_numeric(cve_data)
                    if cvss_score is not None and min_score <= cvss_score <= max_score:
                        results.append(cve_data)
                    
                    if line_num % 10000 == 0:
                        logger.debug(f"Searched {line_num} entries, found {len(results)} matches")
            
            logger.info(f"Found {len(results)} CVEs with severity {min_score}-{max_score}")
            return results
            
        except Exception as e:
            logger.error(f"Error filtering by severity: {e}")
            return []
    
    def advanced_filter(self, 
                       cwe_id: Optional[str] = None,
                       vendor: Optional[str] = None,
                       min_severity: float = 0.0,
                       max_severity: float = 10.0,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """
        Advanced filtering with multiple criteria
        
        Args:
            cwe_id: CWE identifier to filter by (optional)
            vendor: Vendor name to filter by (optional)
            min_severity: Minimum CVSS score (default: 0.0)
            max_severity: Maximum CVSS score (default: 10.0)
            limit: Maximum number of results to return
            
        Returns:
            List of matching CVE dictionaries
        """
        logger.info(f"Advanced filter - CWE: {cwe_id}, Vendor: {vendor}, "
                   f"Severity: {min_severity}-{max_severity}, Limit: {limit}")
        
        results = []
        
        # Normalize inputs
        if cwe_id and not cwe_id.upper().startswith('CWE-'):
            cwe_id = f"CWE-{cwe_id}"
        vendor_lower = vendor.lower() if vendor else None
        
        try:
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if len(results) >= limit:
                        break
                    
                    if not line.strip():
                        continue
                    
                    cve_data = self._load_jsonl_line(line)
                    if not cve_data:
                        continue
                    
                    # Apply all filters
                    if cwe_id and not self._has_cwe(cve_data, cwe_id.upper()):
                        continue
                    
                    if vendor_lower:
                        description = self._extract_description(cve_data)
                        if not description or vendor_lower not in description.lower():
                            continue
                    
                    cvss_score = self._extract_cvss_score_numeric(cve_data)
                    if cvss_score is None or not (min_severity <= cvss_score <= max_severity):
                        continue
                    
                    results.append(cve_data)
                    
                    if line_num % 10000 == 0:
                        logger.debug(f"Searched {line_num} entries, found {len(results)} matches")
            
            logger.info(f"Advanced filter found {len(results)} matching CVEs")
            return results
            
        except Exception as e:
            logger.error(f"Error in advanced filter: {e}")
            return []
    
    def _extract_description(self, cve_data: Dict) -> Optional[str]:
        """Extract description from CVE data"""
        if 'descriptions' in cve_data:
            for desc in cve_data['descriptions']:
                if desc.get('lang') == 'en':
                    return desc.get('value')
        
        if 'cve' in cve_data and 'descriptions' in cve_data['cve']:
            for desc in cve_data['cve']['descriptions']:
                if desc.get('lang') == 'en':
                    return desc.get('value')
        
        if 'description' in cve_data:
            return cve_data['description']
        
        return None
    
    def _extract_cvss_score_numeric(self, cve_data: Dict) -> Optional[float]:
        """Extract numeric CVSS score from CVE data"""
        if 'metrics' in cve_data:
            metrics = cve_data['metrics']
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                return metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore')
            # Try CVSS v3.0
            if 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
                return metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore')
            # Try CVSS v2
            if 'cvssMetricV2' in metrics and len(metrics['cvssMetricV2']) > 0:
                return metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore')
        
        if 'cvss_score' in cve_data:
            try:
                return float(cve_data['cvss_score'])
            except (ValueError, TypeError):
                pass
        
        return None
    
    def get_random_sample(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Get random sample of CVEs (useful for testing/demo)
        
        Args:
            count: Number of CVEs to return
            
        Returns:
            List of random CVE dictionaries
        """
        logger.info(f"Getting random sample of {count} CVEs")
        
        results = []
        line_count = 0
        
        try:
            # First pass: count total lines
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        line_count += 1
            
            # Calculate step size
            if line_count < count:
                step = 1
            else:
                step = line_count // count
            
            # Second pass: collect samples
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if len(results) >= count:
                        break
                    
                    if line_num % step == 0 and line.strip():
                        cve_data = self._load_jsonl_line(line)
                        if cve_data:
                            results.append(cve_data)
            
            logger.info(f"Retrieved {len(results)} random CVEs")
            return results
            
        except Exception as e:
            logger.error(f"Error getting random sample: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics
        
        Returns:
            Dictionary with statistics about the CVE database
        """
        logger.info("Calculating database statistics...")
        
        stats = {
            'total_cves': 0,
            'file_size_mb': self.jsonl_path.stat().st_size / (1024 * 1024),
            'sample_cves': []
        }
        
        try:
            with open(self.jsonl_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        stats['total_cves'] += 1
                        
                        # Collect first 3 as samples
                        if len(stats['sample_cves']) < 3:
                            cve_data = self._load_jsonl_line(line)
                            if cve_data:
                                cve_id = cve_data.get('id') or cve_data.get('cve', {}).get('id', 'Unknown')
                                stats['sample_cves'].append(cve_id)
                    
                    if line_num % 10000 == 0:
                        logger.debug(f"Counted {line_num} entries...")
            
            logger.info(f"Database contains {stats['total_cves']} CVEs")
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating statistics: {e}")
            return stats


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 80)
    print("CVE Database Module - Test")
    print("=" * 80)
    
    try:
        # Initialize database
        db = CVEDatabase()
        
        # Get statistics
        print("\n📊 Database Statistics:")
        stats = db.get_statistics()
        print(f"  Total CVEs: {stats['total_cves']}")
        print(f"  File Size: {stats['file_size_mb']:.2f} MB")
        print(f"  Sample CVEs: {', '.join(stats['sample_cves'])}")
        
        # Test get by ID (if you have a known CVE)
        print("\n🔍 Test: Get CVE by ID")
        # Uncomment and replace with actual CVE ID from your database
        # cve = db.get_by_id("CVE-2024-1234")
        # if cve:
        #     print(f"  Found: {cve.get('id')}")
        
        # Test filter by CWE
        print("\n🔍 Test: Filter by CWE-119 (limit 5)")
        cves = db.filter_by_cwe("CWE-119", limit=5)
        print(f"  Found {len(cves)} CVEs")
        for cve in cves[:3]:
            cve_id = cve.get('id') or cve.get('cve', {}).get('id', 'Unknown')
            print(f"    - {cve_id}")
        
        # Test random sample
        print("\n🎲 Test: Random sample (5 CVEs)")
        sample = db.get_random_sample(5)
        print(f"  Retrieved {len(sample)} CVEs")
        
        print("\n✅ All tests completed!")
        
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("   Please ensure nvd_cves_all.jsonl exists in the data/ directory")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
