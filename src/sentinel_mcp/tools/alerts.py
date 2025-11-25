"""Major alerts tool for critical security events"""

import logging
import math
from typing import Dict, Any
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class MajorAlertsTool(BaseTool):
    """Retrieve critical security alerts with rule level >= 12"""
    
    def name(self) -> str:
        return "get_major_alerts"
    
    def description(self) -> str:
        return (
            "Get major/critical security alerts (rule level >= 12). "
            "Includes comprehensive statistics on alert distribution, MITRE ATT&CK mappings, and affected agents."
        )
    
    async def execute(self,
                     time_range: str = "24h",
                     page: int = 1,
                     size: int = 100,
                     search: str = "",
                     sort_by: str = "@timestamp",
                     sort_order: str = "desc",
                     min_level: int = 12) -> Dict[str, Any]:
        """Get major alerts
        
        Args:
            time_range: Time range (15m, 1h, 24h, 7d, 30d, custom:start:end)
            page: Page number (1-indexed)
            size: Results per page
            search: Optional search filter
            sort_by: Field to sort by
            sort_order: Sort order (asc/desc)
            min_level: Minimum rule level (default 12 for critical)
            
        Returns:
            Major alerts with comprehensive statistics
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
                        {'range': {'rule.level': {'gte': min_level}}}
                    ]
                }
            }
            
            # Add search filter if provided
            if search and search.strip():
                query_body['bool']['must'].append({
                    'match': {
                        'raw_log.message': {
                            'query': search,
                            'operator': 'or'
                        }
                    }
                })
            
            # Add false positive filter
            query_body = self.add_false_positive_filter(query_body)
            
            # Get indices
            indices = await self.discover_indices()
            if not indices:
                return {
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
                    'sort': [{sort_by: {'order': sort_order}}]
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
                        'agent_distribution': {
                            'terms': {'field': 'agent.name', 'size': 20}
                        },
                        'time_trend': {
                            'date_histogram': {
                                'field': '@timestamp',
                                'calendar_interval': 'day'
                            }
                        },
                        'mitre_tactics': {
                            'terms': {'field': 'rule.mitre.tactic', 'size': 20}
                        },
                        'mitre_techniques': {
                            'terms': {'field': 'rule.mitre.technique', 'size': 20}
                        },
                        'mitre_ids': {
                            'terms': {'field': 'rule.mitre.id', 'size': 20}
                        },
                        'rule_groups': {
                            'terms': {'field': 'rule.groups', 'size': 20}
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
            
            # Format statistics
            aggs = stats_response['aggregations']
            stats = {
                'total': logs_response['hits']['total']['value'],
                'byLevel': [
                    {'level': b['key'], 'count': b['doc_count']}
                    for b in aggs['level_distribution']['buckets']
                ],
                'byAgent': [
                    {'name': b['key'], 'count': b['doc_count']}
                    for b in aggs['agent_distribution']['buckets']
                ],
                'byTimeInterval': [
                    {'timestamp': b['key_as_string'], 'count': b['doc_count']}
                    for b in aggs['time_trend']['buckets']
                ],
                'mitreCategories': {
                    'tactics': [
                        {'key': b['key'], 'count': b['doc_count']}
                        for b in aggs['mitre_tactics']['buckets']
                    ],
                    'techniques': [
                        {'key': b['key'], 'count': b['doc_count']}
                        for b in aggs['mitre_techniques']['buckets']
                    ],
                    'ids': [
                        {'key': b['key'], 'count': b['doc_count']}
                        for b in aggs['mitre_ids']['buckets']
                    ]
                },
                'ruleGroups': [
                    {'name': b['key'], 'count': b['doc_count']}
                    for b in aggs['rule_groups']['buckets']
                ]
            }
            
            total = logs_response['hits']['total']['value']
            
            return {
                'logs': logs,
                'pagination': self.format_pagination(page, size, total),
                'stats': stats,
                'query_info': {
                    'time_range': time_range,
                    'min_level': min_level,
                    'search_filter': search if search else None
                }
            }
            
        except Exception as e:
            logger.error(f"Major alerts error: {e}")
            return {
                'error': str(e),
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
            'total': 0,
            'byLevel': [],
            'byAgent': [],
            'byTimeInterval': [],
            'mitreCategories': {
                'tactics': [],
                'techniques': [],
                'ids': []
            },
            'ruleGroups': []
        }
