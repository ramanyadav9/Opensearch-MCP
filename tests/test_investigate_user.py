"""Test script for investigate_user tool

Comprehensive UEBA orchestrator testing.
"""

import asyncio
import sys
from pathlib import Path
import json

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from sentinel_mcp.tools.investigate_user import InvestigateUserTool
from sentinel_mcp.opensearch_client import SentinelOpenSearchClient


async def test_investigate_user():
    """Test investigate_user tool with comprehensive output"""
    
    print("=" * 70)
    print("TESTING InvestigateUserTool - Comprehensive UEBA Orchestrator")
    print("=" * 70)
    
    # Create OpenSearch client
    config = {
        "hosts": ["http://192.168.1.133:9200"],
        "username": "admin",
        "password": "admin",
        "verify_certs": False
    }
    
    print(f"\n📡 OpenSearch Configuration:")
    print(f"   Hosts: {config['hosts']}")
    print(f"   Username: {config['username']}")
    
    try:
        client = SentinelOpenSearchClient(config)
        print("   ✓ Client initialized")
    except Exception as e:
        print(f"   ✗ Client initialization failed: {e}")
        return False
    
    # Create tool
    tool_config = {}
    tool = InvestigateUserTool(client, tool_config)
    
    print(f"\n🔧 Tool Information:")
    print(f"   Name: {tool.name()}")
    print(f"   Description: {tool.description()[:100]}...")
    
    # Test with sample user/agent
    # Using "MDM-189" as suggested in the example, or fallback to a known user if needed
    test_user = "MDM-189" 
    
    print(f"\n" + "=" * 70)
    print(f"EXECUTING INVESTIGATION")
    print("=" * 70)
    print(f"\n🎯 Target User/Agent: {test_user}")
    print(f"   Time Range: 24h")
    print(f"   Baseline Window: 30d")
    
    try:
        print(f"\n⏳ Orchestrating 7 specialized queries...")
        result = await tool.execute(
            username=test_user,
            time_range="24h",
            baseline_window="30d"
        )
        
        print("\n" + "=" * 70)
        print("✅ INVESTIGATION RESULTS")
        print("=" * 70)
        
        # Summary
        print(f"\n📊 SUMMARY")
        print(f"   Entity: {result.get('entity')}")
        print(f"   Risk Score: {result.get('risk_score')}/100")
        print(f"   Risk Level: {result.get('risk_level')}")
        print(f"   Insider Threat Score: {result.get('insider_threat_score')}/100")
        
        # 1. Authentication
        auth = result.get('authentication_activity', {})
        print(f"\n🔐 AUTHENTICATION")
        print(f"   Total: {auth.get('total', 0)}")
        print(f"   Failed: {auth.get('failed', 0)}")
        print(f"   Successful: {auth.get('successful', 0)}")
        print(f"   Source IPs: {auth.get('source_ips', [])}")
        
        # 2. File Modifications
        fim = result.get('file_modifications', {})
        print(f"\n📁 FILE MODIFICATIONS")
        print(f"   Total: {fim.get('total', 0)}")
        print(f"   Modified Files: {len(fim.get('modified_files', []))}")
        
        # 3. Malware
        malware = result.get('malware_events', {})
        print(f"\n🦠 MALWARE & SECURITY")
        print(f"   Total Detections: {malware.get('total', 0)}")
        print(f"   Critical: {malware.get('critical_count', 0)}")
        
        # 4. Network
        network = result.get('network_activity', {})
        print(f"\n🌐 NETWORK ACTIVITY")
        print(f"   Total Connections: {network.get('total', 0)}")
        print(f"   Unique Destinations: {network.get('unique_destinations', 0)}")
        
        # 5. Vulnerabilities
        vuln = result.get('vulnerability_data', {})
        print(f"\n🔓 VULNERABILITIES")
        print(f"   Total: {vuln.get('total', 0)}")
        print(f"   Unique CVEs: {vuln.get('unique_cves', 0)}")
        
        # 6. Compliance
        comp = result.get('compliance_violations', {})
        print(f"\n📋 COMPLIANCE VIOLATIONS")
        print(f"   Total: {comp.get('total', 0)}")
        print(f"   HIPAA: {comp.get('hipaa', 0)}")
        print(f"   GDPR: {comp.get('gdpr', 0)}")
        print(f"   PCI-DSS: {comp.get('pci_dss', 0)}")
        
        # 7. Process Execution
        proc = result.get('process_execution', {})
        print(f"\n⚙️ PROCESS EXECUTION")
        print(f"   Total: {proc.get('total', 0)}")
        print(f"   Unique Processes: {proc.get('unique_processes', 0)}")
        
        # Behavioral Analysis
        print(f"\n📈 BEHAVIORAL ANALYSIS")
        baseline = result.get('baseline', {})
        print(f"   Baseline Period: {baseline.get('period')}")
        print(f"   Avg Logins/Day: {baseline.get('login_count_avg', 0):.1f}")
        print(f"   Avg File Mods/Day: {baseline.get('file_modification_avg', 0):.1f}")
        
        # Anomalies
        anomalies = result.get('anomalies', [])
        if anomalies:
            print(f"\n⚠️  ANOMALIES DETECTED ({len(anomalies)})")
            for anomaly in anomalies:
                print(f"   • [{anomaly.get('severity', 'unknown').upper()}] {anomaly.get('description')}")
        else:
            print(f"\n✅ No behavioral anomalies detected")
            
        # Recommendations
        recs = result.get('recommendations', [])
        if recs:
            print(f"\n💡 RECOMMENDATIONS")
            for i, rec in enumerate(recs, 1):
                print(f"   {i}. {rec}")
                
        print("\n" + "=" * 70)
        print("✅ TEST COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED")
        print(f"   Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\n")
    success = asyncio.run(test_investigate_user())
    print("\n")
    sys.exit(0 if success else 1)
