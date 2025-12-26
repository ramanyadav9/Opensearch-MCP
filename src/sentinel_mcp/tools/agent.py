"""Agent-specific logs query tool with optional analytics"""

import logging
from typing import Dict, Any
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class AgentLogsTool(BaseTool):
    """Query logs for a specific agent by name with optional analytics"""
    
    def name(self) -> str:
        return "get_agent_logs"
    
    def description(self) -> str:
        return (
            "PRIMARY TOOL for any agent/endpoint/hostname/server/workstation queries. "
            "ALWAYS use this when user mentions a machine name like 'raman', 'server01', 'MDM-189'. "
            "Use for: 'Show logs for raman', 'What happened on server01?', 'Check workstation-5'. "
            "Set include_analytics=true for MITRE tactics, network destinations, and severity stats."
        )
    
    async def execute(self,
                     agent_name: str,
                     time_range: str = "24h",
                     page: int = 1,
                     size: int = 100,
                     search: str = "",
                     sort_order: str = "desc",
                     include_analytics: bool = False) -> Dict[str, Any]:
        """Get logs for specific agent
        
        Args:
            agent_name: Agent name to query (e.g., "SOC_GPU_SRV", "MDM-189")
            time_range: Time range (15m, 1h, 24h, 7d, 30d, custom:start:end)
            page: Page number (1-indexed)
            size: Results per page
            search: Optional search filter within agent logs
            sort_order: Sort order (asc/desc)
            include_analytics: Include extended analytics (MITRE, destinations, severity)
            
        Returns:
            Agent logs with pagination, statistics, and optional analytics
        """
        try:
            # Cap page size
            size = self.cap_page_size(size)
            
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
            
            # Add search filter if provided
            if search and search.strip():
                query_body['bool']['must'].append({
                    'multi_match': {
                        'query': search,
                        'fields': [
                            'rule.description^3',
                            'rule.groups^2',
                            'network.srcIp^2',
                            'network.destIp^2',
                            'data.srcip^2',
                            'data.dstip^2',
                            'raw_log.message'
                        ],
                        'type': 'best_fields'
                    }
                })
            
            # Add false positive filter
            query_body = self.add_false_positive_filter(query_body)
            
            # Get indices
            indices = await self.discover_indices()
            if not indices:
                return {
                    'agent': agent_name,
                    'logs': [],
                    'pagination': self.format_pagination(page, size, 0),
                    'stats': self._empty_stats()
                }
            
            # Calculate offset
            from_val = (page - 1) * size
            
            # Get logs
            logs_response = await self.client.search(
                index=','.join(indices),
                body={
                    'query': query_body,
                    'sort': [{'@timestamp': {'order': sort_order}}],
                    '_source': {
                        'excludes': ['raw_log.command', 'raw_log.script']
                    }
                },
                size=size,
                from_=from_val
            )
            
            # Build aggregations
            aggs_body = {
                'level_distribution': {
                    'terms': {'field': 'rule.level', 'size': 10}
                },
                'rule_groups': {
                    'terms': {'field': 'rule.groups', 'size': 20}
                },
                'time_trend': {
                    'date_histogram': {
                        'field': '@timestamp',
                        'calendar_interval': 'hour'
                    }
                },
                'top_rules': {
                    'terms': {'field': 'rule.description.keyword', 'size': 10}
                }
            }
            
            # Add extended analytics aggregations if requested
            if include_analytics:
                aggs_body.update({
                    'severity_stats': {
                        'stats': {'field': 'rule.level'}
                    },
                    'mitre_tactics': {
                        'terms': {'field': 'rule.mitre.tactic', 'size': 10}
                    },
                    'mitre_techniques': {
                        'terms': {'field': 'rule.mitre.technique', 'size': 10}
                    },
                    'dest_ips': {
                        'terms': {'field': 'network.destIp', 'size': 10}
                    },
                    'src_ips': {
                        'terms': {'field': 'network.srcIp', 'size': 10}
                    },
                    'users': {
                        'terms': {'field': 'data.dstuser', 'size': 10}
                    }
                })
            
            # Get statistics
            stats_response = await self.client.search(
                index=','.join(indices),
                body={
                    'size': 0,
                    'query': query_body,
                    'aggs': aggs_body
                }
            )
            
            # Format logs
            logs = []
            for hit in logs_response['hits']['hits']:
                log_entry = {
                    **hit['_source'],
                    'id': hit['_id'],
                    '_score': hit.get('_score', 0)
                }
                logs.append(log_entry)
            
            # Format stats
            aggs = stats_response['aggregations']
            stats = {
                'total_events': logs_response['hits']['total']['value'],
                'level_distribution': [
                    {'level': b['key'], 'count': b['doc_count']}
                    for b in aggs['level_distribution']['buckets']
                ],
                'rule_groups': [
                    {'group': b['key'], 'count': b['doc_count']}
                    for b in aggs['rule_groups']['buckets']
                ],
                'top_rules': [
                    {'rule': b['key'], 'count': b['doc_count']}
                    for b in aggs['top_rules']['buckets']
                ],
                'time_trend': [
                    {'timestamp': b['key_as_string'], 'count': b['doc_count']}
                    for b in aggs['time_trend']['buckets']
                ]
            }
            
            # Add extended analytics if requested
            if include_analytics:
                stats['analytics'] = {
                    'severity': {
                        'avg': aggs['severity_stats'].get('avg', 0),
                        'max': aggs['severity_stats'].get('max', 0),
                        'min': aggs['severity_stats'].get('min', 0)
                    },
                    'mitre_tactics': [
                        {'tactic': b['key'], 'count': b['doc_count']}
                        for b in aggs['mitre_tactics']['buckets']
                    ],
                    'mitre_techniques': [
                        {'technique': b['key'], 'count': b['doc_count']}
                        for b in aggs['mitre_techniques']['buckets']
                    ],
                    'top_destinations': [
                        {'ip': b['key'], 'count': b['doc_count']}
                        for b in aggs['dest_ips']['buckets']
                    ],
                    'top_sources': [
                        {'ip': b['key'], 'count': b['doc_count']}
                        for b in aggs['src_ips']['buckets']
                    ],
                    'active_users': [
                        {'user': b['key'], 'count': b['doc_count']}
                        for b in aggs['users']['buckets']
                    ]
                }
            
            total = logs_response['hits']['total']['value']
            
            return {
                'agent': agent_name,
                'logs': logs,
                'pagination': self.format_pagination(page, size, total),
                'stats': stats,
                'query_info': {
                    'time_range': time_range,
                    'search_filter': search if search else None,
                    'include_analytics': include_analytics
                }
            }
            
        except Exception as e:
            logger.error(f"Agent logs error: {e}")
            return {
                'error': str(e),
                'agent': agent_name,
                'logs': [],
                'pagination': self.format_pagination(page, size, 0),
                'stats': self._empty_stats()
            }
    
    def _empty_stats(self) -> Dict[str, Any]:
        """Return empty stats structure"""
        return {
            'total_events': 0,
            'level_distribution': [],
            'rule_groups': [],
            'top_rules': [],
            'time_trend': []
        }

