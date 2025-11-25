"""Agent-specific logs query tool"""

import logging
from typing import Dict, Any
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class AgentLogsTool(BaseTool):
    """Query logs for a specific agent by name"""
    
    def name(self) -> str:
        return "get_agent_logs"
    
    def description(self) -> str:
        return (
            "Get logs for a specific agent by name. Supports time range filtering and pagination. "
            "Useful for investigating specific endpoints or servers."
        )
    
    async def execute(self,
                     agent_name: str,
                     time_range: str = "24h",
                     page: int = 1,
                     size: int = 100,
                     search: str = "",
                     sort_order: str = "desc") -> Dict[str, Any]:
        """Get logs for specific agent
        
        Args:
            agent_name: Agent name to query (e.g., "SOC_GPU_SRV", "MDM-189")
            time_range: Time range (15m, 1h, 24h, 7d, 30d, custom:start:end)
            page: Page number (1-indexed)
            size: Results per page
            search: Optional search filter within agent logs
            sort_order: Sort order (asc/desc)
            
        Returns:
            Agent logs with pagination and statistics
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
            
            # Get statistics
            stats_response = await self.client.search(
                index=','.join(indices),
                body={
                    'size': 0,
                    'query': query_body,
                    'aggs': {
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
            
            total = logs_response['hits']['total']['value']
            
            return {
                'agent': agent_name,
                'logs': logs,
                'pagination': self.format_pagination(page, size, total),
                'stats': stats,
                'query_info': {
                    'time_range': time_range,
                    'search_filter': search if search else None
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
        """Return empty stats structure
        
        Returns:
            Empty statistics dictionary
        """
        return {
            'total_events': 0,
            'level_distribution': [],
            'rule_groups': [],
            'top_rules': [],
            'time_trend': []
        }
