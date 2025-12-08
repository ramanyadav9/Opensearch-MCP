"""Category-specific log tools"""

import logging
from typing import Dict, Any, List, Optional
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class CategoryBaseTool(BaseTool):
    """Base class for category tools providing standard aggregations"""
    
    async def _execute_category_search(self, 
                                     query: Dict[str, Any], 
                                     time_range: str,
                                     page: int,
                                     size: int,
                                     aggs: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute standardized category search"""
        try:
            indices = await self.discover_indices()
            if not indices:
                return {'logs': [], 'pagination': self.format_pagination(page, size, 0)}
            
            # Add false positive filter
            query = self.add_false_positive_filter(query)
            
            from_val = (page - 1) * size
            
            # Main search
            search_body = {
                'query': query,
                'sort': [{'@timestamp': {'order': 'desc'}}],
                '_source': {'excludes': ['raw_log.command']}
            }
            
            response = await self.client.search(
                index=','.join(indices),
                body=search_body,
                size=size,
                from_=from_val
            )
            
            # Aggregations if requested
            stats = {}
            if aggs:
                agg_response = await self.client.search(
                    index=','.join(indices),
                    body={'size': 0, 'query': query, 'aggs': aggs}
                )
                stats = agg_response['aggregations']
            
            logs = []
            for hit in response['hits']['hits']:
                logs.append({**hit['_source'], 'id': hit['_id']})
                
            total = response['hits']['total']['value']
            
            return {
                'logs': logs,
                'pagination': self.format_pagination(page, size, total),
                'stats': stats
            }
        except Exception as e:
            logger.error(f"Category search error: {e}")
            return {'error': str(e), 'logs': []}


class FIMEventsTool(CategoryBaseTool):
    def name(self) -> str: return "get_fim_events"
    def description(self) -> str: return "Get FILE CHANGES (created/modified/deleted). Use for: 'Were any files modified?', 'Check for unauthorized file changes', 'Who changed config files?'. Returns syscheck events with file paths, actions, and affected agents."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        time_filter = TimeRangeParser.parse(time_range)
        query = {
            'bool': {
                'must': [
                    time_filter,
                    {'exists': {'field': 'syscheck.path'}}
                ]
            }
        }
        aggs = {
            'by_action': {'terms': {'field': 'syscheck.event', 'size': 5}},
            'top_files': {'terms': {'field': 'syscheck.path', 'size': 10}},
            'by_agent': {'terms': {'field': 'agent.name', 'size': 10}}
        }
        return await self._execute_category_search(query, time_range, page, int(size), aggs)


class SCAEventsTool(CategoryBaseTool):
    def name(self) -> str: return "get_sca_events"
    def description(self) -> str: return "Get SECURITY COMPLIANCE CHECKS (passed/failed). Use for: 'Are systems properly configured?', 'Show failed security checks', 'CIS benchmark results'. Returns SCA policy results by agent."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        time_filter = TimeRangeParser.parse(time_range)
        query = {
            'bool': {
                'must': [
                    time_filter,
                    {'match': {'rule.groups': 'sca'}}
                ]
            }
        }
        aggs = {
            'by_result': {'terms': {'field': 'data.sca.check.result', 'size': 5}},
            'by_policy': {'terms': {'field': 'data.sca.policy', 'size': 10}},
            'by_agent': {'terms': {'field': 'agent.name', 'size': 10}}
        }
        return await self._execute_category_search(query, time_range, page, int(size), aggs)


class SessionEventsTool(CategoryBaseTool):
    def name(self) -> str: return "get_session_events"
    def description(self) -> str: return "Get LOGIN/AUTHENTICATION events (success/failure). Use for: 'Who logged in?', 'Failed login attempts', 'SSH access', 'Brute force detection'. Returns user logins with source IPs."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        time_filter = TimeRangeParser.parse(time_range)
        query = {
            'bool': {
                'must': [time_filter],
                'should': [
                    {'match': {'rule.groups': 'authentication_success'}},
                    {'match': {'rule.groups': 'authentication_failed'}},
                    {'match': {'rule.groups': 'login_denied'}},
                    {'match': {'rule.groups': 'sshd'}}
                ],
                'minimum_should_match': 1
            }
        }
        aggs = {
            'top_users': {'terms': {'field': 'data.dstuser', 'size': 10}},
            'source_ips': {'terms': {'field': 'data.srcip', 'size': 10}},
            'success_vs_fail': {'terms': {'field': 'rule.groups', 'size': 10}}
        }
        return await self._execute_category_search(query, time_range, page, int(size), aggs)


class MalwareEventsTool(CategoryBaseTool):
    def name(self) -> str: return "get_malware_events"
    def description(self) -> str: return "Get MALWARE/VIRUS detections. Use for: 'Any malware detected?', 'Virus alerts', 'Infected files', 'Rootkit checks'. Returns virus names, file paths, and affected agents."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        time_filter = TimeRangeParser.parse(time_range)
        query = {
            'bool': {
                'must': [time_filter],
                'should': [
                    {'match': {'rule.groups': 'virus'}},
                    {'match': {'rule.groups': 'malware'}},
                    {'match': {'rule.groups': 'rootcheck'}},
                    {'exists': {'field': 'data.virus.name'}}
                ],
                'minimum_should_match': 1
            }
        }
        aggs = {
            'virus_names': {'terms': {'field': 'data.virus.name', 'size': 10}},
            'file_paths': {'terms': {'field': 'data.file', 'size': 10}},
            'agents': {'terms': {'field': 'agent.name', 'size': 10}}
        }
        return await self._execute_category_search(query, time_range, page, int(size), aggs)


class AIAnnotatedLogsTool(CategoryBaseTool):
    def name(self) -> str: return "get_ai_annotated_logs"
    def description(self) -> str: return "Get logs PREVIOUSLY ANALYZED by Sentinel-AI's internal AI. Use to review past AI analysis results. Returns logs that have AI_response field populated."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        time_filter = TimeRangeParser.parse(time_range)
        query = {
            'bool': {
                'must': [
                    time_filter,
                    {'exists': {'field': 'data.AI_response'}}
                ]
            }
        }
        return await self._execute_category_search(query, time_range, page, int(size))


class MLAnomaliesTool(CategoryBaseTool):
    def name(self) -> str: return "get_ml_anomalies"
    def description(self) -> str: return "Get ML-DETECTED ANOMALIES with anomaly scores. Use for: 'Show unusual behavior', 'ML outliers', 'Anomaly detection results'. Returns events flagged by ML models."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        time_filter = TimeRangeParser.parse(time_range)
        query = {
            'bool': {
                'must': [
                    time_filter,
                    {'exists': {'field': 'data.ML_logs.anomaly_score'}}
                ]
            }
        }
        return await self._execute_category_search(query, time_range, page, int(size))


class VulnerabilitiesTool(CategoryBaseTool):
    def name(self) -> str: return "get_vulnerabilities"
    def description(self) -> str: return "Get VULNERABILITY/CVE detections. Use for: 'Vulnerable packages', 'CVE alerts', 'Critical vulnerabilities'. Filter by min_score (0-10). Returns CVE IDs, package names, severity levels."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100, min_score: float = 0.0) -> Dict[str, Any]:
        time_filter = TimeRangeParser.parse(time_range)
        query = {
            'bool': {
                'must': [
                    time_filter,
                    {'exists': {'field': 'data.vulnerability.cve'}}
                ]
            }
        }
        if min_score > 0:
            query['bool']['must'].append({'range': {'data.vulnerability.score': {'gte': min_score}}})
            
        aggs = {
            'top_cves': {'terms': {'field': 'data.vulnerability.cve', 'size': 10}},
            'packages': {'terms': {'field': 'data.vulnerability.package.name', 'size': 10}},
            'severity': {'terms': {'field': 'data.vulnerability.severity', 'size': 5}}
        }
        return await self._execute_category_search(query, time_range, page, int(size), aggs)
