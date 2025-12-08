"""Advanced analytics summary tool"""

import logging
from typing import Dict, Any, List
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class AdvancedAnalyticsTool(BaseTool):
    """Get high-level security analytics summary"""
    
    def name(self) -> str:
        return "advanced_analytics_summary"
    
    def description(self) -> str:
        return (
            "USE THIS FIRST for security posture overview. Returns dashboard-level stats: "
            "total event counts (critical/warning/normal), top 10 agents by activity, "
            "top protocols, services, triggered rules, network flows (source->destination), "
            "and event timeline. Best for: 'What is the current security status?', "
            "'Show me an overview', 'Which agents have most alerts?'"
        )
    
    async def execute(self, time_range: str = "24h") -> Dict[str, Any]:
        """Execute advanced analytics summary
        
        Args:
            time_range: Time range for analysis
            
        Returns:
            Analytics summary data
        """
        try:
            # Parse time range
            time_filter = TimeRangeParser.parse(time_range)
            
            # Get indices
            indices = await self.discover_indices()
            if not indices:
                return self._empty_stats()
            
            # Build base query
            query = {
                'bool': {
                    'must': [time_filter]
                }
            }
            
            # Add false positive filter
            query = self.add_false_positive_filter(query)
            
            # Execute search with aggregations
            response = await self.client.search(
                index=','.join(indices),
                body={
                    'size': 0,
                    'query': query,
                    'aggs': {
                        # Event levels
                        'by_level': {
                            'terms': {'field': 'rule.level', 'size': 20}
                        },
                        # Top agents
                        'by_agent': {
                            'terms': {'field': 'agent.name', 'size': 10}
                        },
                        # Top protocols (Network)
                        'by_network_protocol': {
                            'terms': {'field': 'network.protocol', 'size': 10}
                        },
                        # Top protocols (Data)
                        'by_data_protocol': {
                            'terms': {'field': 'data.protocol', 'size': 10}
                        },
                        # Top services
                        'by_service': {
                            'terms': {'field': 'data.service', 'size': 10}
                        },
                        # Rule descriptions
                        'by_description': {
                            'terms': {'field': 'rule.description', 'size': 20}
                        },
                        # Network flows (Sankey)
                        'network_flows': {
                            'composite': {
                                'sources': [
                                    {'source': {'terms': {'field': 'network.srcIp'}}},
                                    {'target': {'terms': {'field': 'network.destIp'}}}
                                ],
                                'size': 20
                            }
                        },
                        # Timeline
                        'events_over_time': {
                            'date_histogram': {
                                'field': '@timestamp',
                                'calendar_interval': self._get_interval(time_range),
                                'min_doc_count': 0
                            }
                        }
                    }
                }
            )
            
            # Process aggregations
            aggs = response['aggregations']
            total = response['hits']['total']['value']
            
            # Calculate severity counts
            # Critical >= 12, Warning >= 8, Normal < 8
            critical = 0
            warning = 0
            normal = 0
            
            for bucket in aggs['by_level']['buckets']:
                level = int(bucket['key'])
                count = bucket['doc_count']
                if level >= 12:
                    critical += count
                elif level >= 7:
                    warning += count
                else:
                    normal += count
            
            # Format flows
            network_flows = []
            for bucket in aggs.get('network_flows', {}).get('buckets', []):
                src = bucket['key'].get('source', 'unknown')
                dst = bucket['key'].get('target', 'unknown')
                if src != 'unknown' and dst != 'unknown':
                    network_flows.append({
                        'source': src,
                        'target': dst,
                        'value': bucket['doc_count']
                    })
            
            # Merge protocols
            protocols = {}
            for b in aggs['by_network_protocol']['buckets']:
                p = str(b['key']).lower()
                protocols[p] = protocols.get(p, 0) + b['doc_count']
            for b in aggs['by_data_protocol']['buckets']:
                p = str(b['key']).lower()
                protocols[p] = protocols.get(p, 0) + b['doc_count']
                
            sorted_protocols = sorted(
                [{'name': k, 'count': v} for k, v in protocols.items()],
                key=lambda x: x['count'],
                reverse=True
            )[:10]
            
            return {
                'summary': {
                    'total_events': total,
                    'critical_events': critical,
                    'warning_events': warning,
                    'normal_events': normal
                },
                'top_agents': [
                    {'name': b['key'], 'count': b['doc_count']}
                    for b in aggs['by_agent']['buckets']
                ],
                'top_protocols': sorted_protocols,
                'top_services': [
                    {'name': b['key'], 'count': b['doc_count']}
                    for b in aggs['by_service']['buckets']
                ],
                'top_rules': [
                    {'description': b['key'], 'count': b['doc_count']}
                    for b in aggs['by_description']['buckets']
                ],
                'network_flows': network_flows,
                'timeline': [
                    {'time': b['key_as_string'], 'count': b['doc_count']}
                    for b in aggs['events_over_time']['buckets']
                ]
            }
            
        except Exception as e:
            logger.error(f"Advanced analytics error: {e}")
            return {'error': str(e)}
            
    def _get_interval(self, time_range: str) -> str:
        """Get appropriate histogram interval for time range"""
        if time_range in ['1h', '4h']:
            return 'minute'
        elif time_range in ['12h', '24h']:
            return 'hour'
        elif time_range in ['3d', '7d']:
            return 'day'
        return 'day'

    def _empty_stats(self) -> Dict[str, Any]:
        return {
            'summary': {'total': 0, 'critical': 0, 'warning': 0, 'normal': 0},
            'top_agents': [],
            'top_protocols': [],
            'top_services': [],
            'top_rules': [],
            'network_flows': [],
            'timeline': []
        }
