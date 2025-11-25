"""Threat hunting tool for suspicious activity detection"""

import logging
from typing import Dict, Any, List
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class ThreatHuntingTool(BaseTool):
    """Proactive threat hunting and suspicious activity detection"""
    
    def name(self) -> str:
        return "threat_hunt"
    
    def description(self) -> str:
        return (
            "Hunt for suspicious activities including brute force attempts, "
            "privilege escalation, lateral movement, and data exfiltration indicators."
        )
    
    async def execute(self,
                     hunt_type: str = "all",
                     time_range: str = "24h",
                     limit: int = 100) -> Dict[str, Any]:
        """Execute threat hunt
        
        Args:
            hunt_type: Type of hunt (all, brute_force, lateral_movement, persistence, exfiltration)
            time_range: Time range for analysis
            limit: Maximum results per category
            
        Returns:
            Threat hunting findings
        """
        try:
            # Parse time range
            time_filter = TimeRangeParser.parse(time_range)
            
            # Define hunt queries
            hunts = {
                'brute_force': {
                    'bool': {
                        'should': [
                            {'match': {'rule.mitre.id': 'T1110'}},  # Brute Force
                            {'match': {'rule.groups': 'authentication_failed'}},
                            {'match': {'rule.description': 'authentication failure'}}
                        ],
                        'minimum_should_match': 1
                    }
                },
                'lateral_movement': {
                    'bool': {
                        'should': [
                            {'match': {'rule.mitre.tactic': 'Lateral Movement'}},
                            {'match': {'rule.mitre.id': 'T1021'}},  # Remote Services
                            {'match': {'rule.mitre.id': 'T1091'}}   # Replication Through Removable Media
                        ],
                        'minimum_should_match': 1
                    }
                },
                'persistence': {
                    'bool': {
                        'should': [
                            {'match': {'rule.mitre.tactic': 'Persistence'}},
                            {'match': {'rule.mitre.id': 'T1053'}},  # Scheduled Task/Job
                            {'match': {'rule.mitre.id': 'T1547'}}   # Boot or Logon Autostart Execution
                        ],
                        'minimum_should_match': 1
                    }
                },
                'exfiltration': {
                    'bool': {
                        'should': [
                            {'match': {'rule.mitre.tactic': 'Exfiltration'}},
                            {'match': {'rule.mitre.id': 'T1048'}},  # Exfiltration Over Alternative Protocol
                            {'match': {'rule.mitre.id': 'T1041'}}   # Exfiltration Over C2 Channel
                        ],
                        'minimum_should_match': 1
                    }
                },
                'privilege_escalation': {
                    'bool': {
                        'should': [
                            {'match': {'rule.mitre.tactic': 'Privilege Escalation'}},
                            {'match': {'rule.mitre.id': 'T1068'}},  # Exploitation for Privilege Escalation
                            {'match': {'rule.groups': 'elevation_of_privilege'}}
                        ],
                        'minimum_should_match': 1
                    }
                }
            }
            
            results = {}
            
            # Determine which hunts to run
            hunts_to_run = hunts.keys() if hunt_type == 'all' else [hunt_type]
            
            for hunt in hunts_to_run:
                if hunt not in hunts:
                    continue
                    
                # Build query
                query_body = {
                    'bool': {
                        'must': [
                            time_filter,
                            hunts[hunt]
                        ]
                    }
                }
                
                # Add false positive filter
                query_body = self.add_false_positive_filter(query_body)
                
                # Get indices
                indices = await self.discover_indices()
                if not indices:
                    results[hunt] = {'count': 0, 'findings': []}
                    continue
                
                # Execute search
                response = await self.client.search(
                    index=','.join(indices),
                    body={
                        'query': query_body,
                        'size': limit,
                        'sort': [{'@timestamp': {'order': 'desc'}}],
                        '_source': {
                            'includes': [
                                '@timestamp', 'rule.level', 'rule.description',
                                'rule.mitre', 'agent.name', 'data.srcip', 'data.dstip',
                                'data.user'
                            ]
                        }
                    }
                )
                
                findings = []
                for hit in response['hits']['hits']:
                    findings.append({
                        **hit['_source'],
                        'id': hit['_id']
                    })
                
                results[hunt] = {
                    'count': response['hits']['total']['value'],
                    'findings': findings
                }
            
            return {
                'time_range': time_range,
                'hunt_type': hunt_type,
                'results': results
            }
            
        except Exception as e:
            logger.error(f"Threat hunt error: {e}")
            return {
                'error': str(e),
                'time_range': time_range,
                'results': {}
            }
