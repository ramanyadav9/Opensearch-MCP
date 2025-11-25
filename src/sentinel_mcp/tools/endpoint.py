"""Endpoint analytics tool"""

import logging
from typing import Dict, Any
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class EndpointAnalyticsTool(BaseTool):
    """Analyze endpoint behavior and statistics"""
    
    def name(self) -> str:
        return "get_endpoint_analytics"
    
    def description(self) -> str:
        return (
            "Analyze behavior for a specific endpoint/agent. "
            "Provides summary of activity, top rules triggered, and network connections."
        )
    
    async def execute(self,
                     agent_name: str,
                     time_range: str = "24h") -> Dict[str, Any]:
        """Get endpoint analytics
        
        Args:
            agent_name: Agent name to analyze
            time_range: Time range for analysis
            
        Returns:
            Endpoint analytics summary
        """
        try:
            # Parse time range
            time_filter = TimeRangeParser.parse(time_range)
            
            # Build query
            query_body = {
                'bool': {
                    'must': [
                        time_filter,
                        {'term': {'agent.name': agent_name}}
                    ]
                }
            }
            
            # Add false positive filter
            query_body = self.add_false_positive_filter(query_body)
            
            # Get indices
            indices = await self.discover_indices()
            if not indices:
                return self._empty_result(agent_name, time_range)
            
            # Execute aggregation query
            response = await self.client.search(
                index=','.join(indices),
                body={
                    'size': 0,
                    'query': query_body,
                    'aggs': {
                        'severity_stats': {
                            'stats': {'field': 'rule.level'}
                        },
                        'top_rules': {
                            'terms': {'field': 'rule.description.keyword', 'size': 10}
                        },
                        'rule_groups': {
                            'terms': {'field': 'rule.groups', 'size': 10}
                        },
                        'mitre_tactics': {
                            'terms': {'field': 'rule.mitre.tactic', 'size': 5}
                        },
                        'dest_ips': {
                            'terms': {'field': 'network.destIp', 'size': 10}
                        },
                        'users': {
                            'terms': {'field': 'data.dstuser', 'size': 5}
                        }
                    }
                }
            )
            
            aggs = response['aggregations']
            
            return {
                'agent': agent_name,
                'time_range': time_range,
                'total_events': response['hits']['total']['value'],
                'severity': {
                    'avg': aggs['severity_stats'].get('avg', 0),
                    'max': aggs['severity_stats'].get('max', 0)
                },
                'top_rules': [
                    {'rule': b['key'], 'count': b['doc_count']}
                    for b in aggs['top_rules']['buckets']
                ],
                'activity_types': [
                    {'group': b['key'], 'count': b['doc_count']}
                    for b in aggs['rule_groups']['buckets']
                ],
                'mitre_tactics': [
                    {'tactic': b['key'], 'count': b['doc_count']}
                    for b in aggs['mitre_tactics']['buckets']
                ],
                'top_destinations': [
                    {'ip': b['key'], 'count': b['doc_count']}
                    for b in aggs['dest_ips']['buckets']
                ],
                'active_users': [
                    {'user': b['key'], 'count': b['doc_count']}
                    for b in aggs['users']['buckets']
                ]
            }
            
        except Exception as e:
            logger.error(f"Endpoint analytics error: {e}")
            return {
                'error': str(e),
                **self._empty_result(agent_name, time_range)
            }
    
    def _empty_result(self, agent: str, time_range: str) -> Dict[str, Any]:
        return {
            'agent': agent,
            'time_range': time_range,
            'total_events': 0,
            'severity': {'avg': 0, 'max': 0},
            'top_rules': [],
            'activity_types': [],
            'mitre_tactics': [],
            'top_destinations': [],
            'active_users': []
        }
