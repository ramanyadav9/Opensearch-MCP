"""MITRE ATT&CK analysis tool"""

import logging
from typing import Dict, Any
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class MITREAttackTool(BaseTool):
    """Analyze MITRE ATT&CK tactics and techniques"""
    
    def name(self) -> str:
        return "get_mitre_attacks"
    
    def description(self) -> str:
        return (
            "Get MITRE ATT&CK mapped events. Use for: 'Show attack techniques', 'What tactics are in use?', "
            "'Filter by T-ID' (e.g. T1110). Returns tactic counts, technique breakdown, severity distribution. "
            "Filter by tactic, technique, or id."
        )
    
    async def execute(self,
                     time_range: str = "24h",
                     tactic: str = None,
                     technique: str = None,
                     id: str = None,
                     min_level: int = 0,
                     limit: int = 100) -> Dict[str, Any]:
        """Get MITRE ATT&CK analysis
        
        Args:
            time_range: Time range for analysis
            tactic: Filter by tactic (e.g., "Initial Access")
            technique: Filter by technique
            id: Filter by technique ID (e.g., "T1110")
            min_level: Minimum rule level
            limit: Maximum results
            
        Returns:
            MITRE ATT&CK analysis
        """
        try:
            # Parse time range
            time_filter = TimeRangeParser.parse(time_range)
            
            # Build query
            query_body = {
                'bool': {
                    'must': [
                        time_filter,
                        {'exists': {'field': 'rule.mitre.id'}}
                    ]
                }
            }
            
            # Add filters
            if tactic:
                query_body['bool']['must'].append({'match': {'rule.mitre.tactic': tactic}})
            if technique:
                query_body['bool']['must'].append({'match': {'rule.mitre.technique': technique}})
            if id:
                query_body['bool']['must'].append({'match': {'rule.mitre.id': id}})
            if min_level > 0:
                query_body['bool']['must'].append({'range': {'rule.level': {'gte': min_level}}})
            
            # Add false positive filter
            query_body = self.add_false_positive_filter(query_body)
            
            # Get indices
            indices = await self.discover_indices()
            if not indices:
                return self._empty_result(time_range)
            
            # Execute aggregation query
            response = await self.client.search(
                index=','.join(indices),
                body={
                    'size': 0,
                    'query': query_body,
                    'aggs': {
                        'tactics': {
                            'terms': {'field': 'rule.mitre.tactic', 'size': 20}
                        },
                        'techniques': {
                            'terms': {'field': 'rule.mitre.technique', 'size': 20}
                        },
                        'ids': {
                            'terms': {'field': 'rule.mitre.id', 'size': 20}
                        },
                        'agents': {
                            'terms': {'field': 'agent.name', 'size': 10}
                        },
                        'levels': {
                            'terms': {'field': 'rule.level', 'size': 10}
                        }
                    }
                }
            )
            
            # Get sample logs if specific filter applied
            samples = []
            if tactic or technique or id:
                sample_response = await self.client.search(
                    index=','.join(indices),
                    body={
                        'query': query_body,
                        'size': 10,
                        'sort': [{'@timestamp': {'order': 'desc'}}],
                        '_source': {
                            'includes': [
                                '@timestamp', 'rule.level', 'rule.description',
                                'rule.mitre', 'agent.name'
                            ]
                        }
                    }
                )
                samples = [hit['_source'] for hit in sample_response['hits']['hits']]
            
            # Process aggregations
            aggs = response['aggregations']
            
            return {
                'time_range': time_range,
                'total_events': response['hits']['total']['value'],
                'tactics': [
                    {'name': b['key'], 'count': b['doc_count']}
                    for b in aggs['tactics']['buckets']
                ],
                'techniques': [
                    {'name': b['key'], 'count': b['doc_count']}
                    for b in aggs['techniques']['buckets']
                ],
                'ids': [
                    {'id': b['key'], 'count': b['doc_count']}
                    for b in aggs['ids']['buckets']
                ],
                'top_agents': [
                    {'name': b['key'], 'count': b['doc_count']}
                    for b in aggs['agents']['buckets']
                ],
                'severity_distribution': [
                    {'level': b['key'], 'count': b['doc_count']}
                    for b in aggs['levels']['buckets']
                ],
                'samples': samples
            }
            
        except Exception as e:
            logger.error(f"MITRE analysis error: {e}")
            return {
                'error': str(e),
                **self._empty_result(time_range)
            }
    
    def _empty_result(self, time_range: str) -> Dict[str, Any]:
        return {
            'time_range': time_range,
            'total_events': 0,
            'tactics': [],
            'techniques': [],
            'ids': [],
            'top_agents': [],
            'severity_distribution': [],
            'samples': []
        }
