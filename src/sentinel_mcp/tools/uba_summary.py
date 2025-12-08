"""User Behavior Analytics (UBA) summary tool"""

import logging
from typing import Dict, Any
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class UBASummaryTool(BaseTool):
    """Get User Behavior Analytics summary"""
    
    def name(self) -> str:
        return "uba_summary"
    
    def description(self) -> str:
        return (
            "Get INSIDER THREAT / RISKY USER summary. Use for: 'Which users are suspicious?', "
            "'Insider threats', 'Brute force suspects', 'Lateral movement'. "
            "Returns: risky users (high alerts), multi-agent users (lateral movement), failed logins."
        )
    
    async def execute(self, time_range: str = "24h", limit: int = 10) -> Dict[str, Any]:
        """Execute UBA summary
        
        Args:
            time_range: Time range for analysis
            limit: Max risky users to return
            
        Returns:
            UBA summary data
        """
        try:
            time_filter = TimeRangeParser.parse(time_range)
            indices = await self.discover_indices()
            if not indices:
                return self._empty_result(time_range)
            
            # Base query: events with user data
            query = {
                'bool': {
                    'must': [
                        time_filter,
                        {'exists': {'field': 'data.srcuser'}}
                    ]
                }
            }
            query = self.add_false_positive_filter(query)
            
            # Aggregations to find anomalies
            aggs = {
                # Top users by event count
                'top_users': {'terms': {'field': 'data.srcuser', 'size': limit * 2}},
                
                # Users with high severity alerts
                'risky_users': {
                    'filter': {'range': {'rule.level': {'gte': 10}}},
                    'aggs': {
                        'users': {'terms': {'field': 'data.srcuser', 'size': limit}}
                    }
                },
                
                # Users appearing on multiple agents
                'multi_agent_users': {
                    'terms': {'field': 'data.srcuser', 'size': limit, 'min_doc_count': 5},
                    'aggs': {
                        'agent_count': {'cardinality': {'field': 'agent.name'}}
                    }
                },
                
                # Login failures
                'login_failures': {
                    'filter': {'match': {'rule.groups': 'authentication_failed'}},
                    'aggs': {
                        'users': {'terms': {'field': 'data.srcuser', 'size': limit}}
                    }
                }
            }
            
            response = await self.client.search(
                index=','.join(indices),
                body={'size': 0, 'query': query, 'aggs': aggs}
            )
            
            aggs_res = response['aggregations']
            
            # Process results
            risky_users = [
                {'user': b['key'], 'critical_alerts': b['doc_count']}
                for b in aggs_res['risky_users']['users']['buckets']
            ]
            
            multi_agent_users = []
            for b in aggs_res['multi_agent_users']['buckets']:
                if b['agent_count']['value'] > 1:
                    multi_agent_users.append({
                        'user': b['key'],
                        'agent_count': b['agent_count']['value']
                    })
            
            login_failures = [
                {'user': b['key'], 'failures': b['doc_count']}
                for b in aggs_res['login_failures']['users']['buckets']
            ]
            
            return {
                'time_range': time_range,
                'risky_users': risky_users,
                'lateral_movement_candidates': multi_agent_users[:limit],
                'brute_force_candidates': login_failures,
                'summary': {
                    'total_users_analyzed': len(aggs_res['top_users']['buckets'])
                }
            }
            
        except Exception as e:
            logger.error(f"UBA summary error: {e}")
            return {'error': str(e), **self._empty_result(time_range)}
    
    def _empty_result(self, time_range) -> Dict[str, Any]:
        return {
            'time_range': time_range,
            'risky_users': [],
            'lateral_movement_candidates': [],
            'brute_force_candidates': [],
            'summary': {'total_users_analyzed': 0}
        }
