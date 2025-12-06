"""Test script for investigate_ip tool

Enhanced validation with comprehensive IP field testing.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from sentinel_mcp.tools.investigate_ip import InvestigateIPTool
from sentinel_mcp.opensearch_client import SentinelOpenSearchClient


async def test_investigate_ip():
    """Test investigate_ip tool with comprehensive output"""
    
    print("=" * 70)
    print("TESTING InvestigateIPTool - Comprehensive IP Investigation")
    print("=" * 70)
    
    # Create OpenSearch client
    config = {
        "hosts": ["http://192.168.1.133:9200"],  # Must be 'hosts' (plural) and include http://
        "username": "admin",
        "password": "admin",
        "verify_certs": False
    }
    
    print(f"\n📡 OpenSearch Configuration:")
    print(f"   Hosts: {config['hosts']}")
    print(f"   Username: {config['username']}")
    print(f"   SSL Verification: {config['verify_certs']}")
    
    try:
        client = SentinelOpenSearchClient(config)
        print("   ✓ Client initialized")
    except Exception as e:
        print(f"   ✗ Client initialization failed: {e}")
        return False
    
    # Create tool
    tool_config = {}
    tool = InvestigateIPTool(client, tool_config)
    
    print(f"\n🔧 Tool Information:")
    print(f"   Name: {tool.name()}")
    print(f"   Description: {tool.description()[:100]}...")
    
    # Show IP fields being searched
    print(f"\n🔍 IP Fields Searched (7 total):")
    print(f"   1. network.srcIp (standard network source)")
    print(f"   2. network.destIp (standard network destination)")
    print(f"   3. data.srcip (firewall/threat hunting source)")
    print(f"   4. data.dstip (firewall/threat hunting destination)")
    print(f"   5. data.dest_ip (alternative destination)")
    print(f"   6. agent.ip (agent identification)")
    print(f"   7. data.win.eventdata.destinationIp (Windows events)")
    
    # Test with sample IP
    test_ip = "192.168.1.192"  # Change to an IP from your logs
    
    print(f"\n" + "=" * 70)
    print(f"EXECUTING INVESTIGATION")
    print("=" * 70)
    print(f"\n🎯 Target IP: {test_ip}")
    print(f"   Time Range: 12h")
    print(f"   Include Graph: False (faster test)")
    
    try:
        print(f"\n⏳ Querying OpenSearch...")
        result = await tool.execute(
            ip=test_ip,
            time_range="12h",
            include_graph=False
        )
        
        print("\n" + "=" * 70)
        print("✅ INVESTIGATION RESULTS")
        print("=" * 70)
        
        # Summary Section
        print(f"\n📊 SUMMARY")
        print(f"   Total Events: {result.get('total_events', 0)}")
        print(f"   Critical Alerts (level ≥12): {result.get('critical_alerts', 0)}")
        print(f"   Affected Systems: {len(result.get('affected_agents', []))}")
        print(f"   Affected Users: {len(result.get('affected_users', []))}")
        print(f"   Affected IPs: {len(result.get('affected_ips', []))}")
        
        # Risk Assessment
        print(f"\n🎯 RISK ASSESSMENT")
        print(f"   Risk Score: {result.get('risk_score', 0)}/100")
        print(f"   Risk Level: {result.get('risk_level', 'Unknown')}")
        print(f"   Verdict: {result.get('verdict', 'Unknown')}")
        
        # Risk Factors
        risk_factors = result.get('risk_factors', [])
        if risk_factors:
            print(f"\n⚠️  RISK FACTORS ({len(risk_factors)} total)")
            for factor in risk_factors:
                print(f"   • {factor.get('description')} (+{factor.get('points')} points)")
        
        # MITRE ATT&CK Mapping
        mitre_techniques = result.get('mitre_techniques', [])
        if mitre_techniques:
            print(f"\n🎭 MITRE ATT&CK TECHNIQUES ({len(mitre_techniques)} total)")
            for tech in mitre_techniques[:5]:  # Show first 5
                print(f"   • {tech.get('id')}: {tech.get('technique')}")
                if tech.get('tactic'):
                    print(f"     Tactic: {tech.get('tactic')}")
        
        # Affected Systems
        affected_agents = result.get('affected_agents', [])
        if affected_agents:
            print(f"\n💻 AFFECTED SYSTEMS ({len(affected_agents)} total)")
            for agent in affected_agents[:5]:  # Show first 5
                print(f"   • {agent}")
        
        # Affected Users
        affected_users = result.get('affected_users', [])
        if affected_users:
            print(f"\n👥 AFFECTED USERS ({len(affected_users)} total)")
            for user in affected_users[:5]:  # Show first 5
                print(f"   • {user}")
        
        # Timeline
        timeline = result.get('timeline', [])
        if timeline:
            print(f"\n📅 TIMELINE ({len(timeline)} events)")
            for event in timeline[:5]:  # Show first 5
                print(f"   • {event.get('timestamp')} - {event.get('type')}: {event.get('description')[:60]}...")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS")
        recommendations = result.get('recommendations', [])
        if recommendations:
            for i, rec in enumerate(recommendations[:5], 1):  # Show first 5
                print(f"   {i}. {rec}")
        else:
            print(f"   • No specific recommendations")
        
        # Metadata
        metadata = result.get('metadata', {})
        print(f"\n📋 METADATA")
        print(f"   Queries Executed: {metadata.get('query_count', 0)}")
        print(f"   Correlation Time: {metadata.get('correlation_timestamp', 'N/A')}")
        
        print("\n" + "=" * 70)
        print("✅ TEST COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        
        return True
        
    except ConnectionError as e:
        print(f"\n❌ CONNECTION ERROR")
        print(f"   {str(e)}")
        print(f"\n💡 TROUBLESHOOTING:")
        print(f"   1. Verify OpenSearch is running on {config['host']}")
        print(f"   2. Check network connectivity")
        print(f"   3. If OpenSearch is on WSL, try running from WSL:")
        print(f"      cd /mnt/e/CyberSentinal\\ All/Sentinel-AI/mcp-server")
        print(f"      python3 tests/test_investigate_ip.py")
        return False
        
    except Exception as e:
        print(f"\n❌ TEST FAILED")
        print(f"   Error: {str(e)}")
        print(f"\n📋 Full Traceback:")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\n")
    success = asyncio.run(test_investigate_ip())
    print("\n")
    sys.exit(0 if success else 1)
