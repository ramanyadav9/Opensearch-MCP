"""Advanced SIEM search tool with DQL detection and field boosting"""

import logging
import math
from typing import Dict, Any, List, Optional
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser
from ..utils.validators import DQLDetector

logger = logging.getLogger(__name__)


class AdvancedSIEMSearchTool(BaseTool):
    """Advanced search tool with DQL detection, field boosting, and multi-strategy search"""
    
    # Search fields with boost values
    SEARCH_FIELDS = [
        # Core fields
        "@timestamp", "id", "location",
        # Agent fields (high boost)
        "agent.name^3", "agent.id^2", "agent.ip^2",
        # Rule fields (high boost)
        "rule.id^3", "rule.level^2", "rule.description^3", "rule.groups^2",
        # MITRE ATT&CK fields
        "rule.mitre.id^2", "rule.mitre.tactic^2", "rule.mitre.technique^2",
        # Compliance frameworks
        "rule.gdpr", "rule.hipaa", "rule.nist", "rule.pci_dss", "rule.tsc",
        # Network fields
        "network.srcIp^3", "network.destIp^3", "network.protocol^2",
        "network.srcPort", "network.destPort",
        # Data fields
        "data.srcip^3", "data.dstip^3", "data.srcuser^2", "data.dstuser^2",
        "data.user^2", "data.hostname^2", "data.app^2", "data.msg^2",
        "data.action^2", "data.protocol", "data.srcport", "data.dstport",
        "data.srccountry", "data.dstcountry",
        # Windows-specific
        "data.win.eventdata.targetUserName^2",
        "data.win.eventdata.processName^2",
        "data.win.eventdata.commandLine",
        # Syscheck
        "syscheck.path^3", "syscheck.event^2", "syscheck.mode", "syscheck.diff",
        # AI/ML
        "data.AI_response^2", "data.ML_logs.anomaly_score", "data.ML_logs.severity^2",
        # Vulnerability
        "data.vulnerability.cve^3", "data.vulnerability.title^2",
        "data.vulnerability.severity^2", "data.vulnerability.package.name^2",
        # SCA
        "data.sca.policy^2", "data.sca.check.result^2",
        # Raw log message (fallback)
        "raw_log.message"
    ]
    
    def name(self) -> str:
        return "search_logs"
    
    def description(self) -> str:
        return (
            "FALLBACK ONLY - General log search. DO NOT use if user mentions a specific "
            "agent/hostname/endpoint/server/workstation name (use get_agent_logs instead) or "
            "if user asks to 'investigate' a user/person (use investigate_user instead). "
            "Use this ONLY for: general queries without specific entity names, DQL syntax searches, "
            "or filtering by log_type (firewall, ids, windows, linux)."
        )
    
    async def execute(self, 
                     query: str = "",
                     time_range: str = "24h",
                     page: int = 1,
                     size: int = 100,
                     sort_by: str = "@timestamp",
                     sort_order: str = "desc",
                     log_type: str = "all",
                     rule_level: str = "all") -> Dict[str, Any]:
        """Execute advanced SIEM search
        
        Args:
            query: Search query (supports DQL like field:value)
            time_range: Time range (15m, 1h, 24h, 7d, 30d, custom:start:end)
            page: Page number (1-indexed)
            size: Results per page
            sort_by: Field to sort by
            sort_order: Sort order (asc/desc)
            log_type: Filter by log type (all, firewall, ids, windows, linux)
            rule_level: Minimum rule level (all, or number like 5, 10, 12)
            
        Returns:
            Search results with logs and pagination
        """
        try:
            # Cap page size
            size = self.cap_page_size(size)
            
            # Parse time range
            time_filter = TimeRangeParser.parse(time_range)
            
            # Build base query
            query_body = {
                'bool': {
                    'must': [time_filter]
                }
            }
            
            # Add search query if provided
            if query and query.strip():
                search_query = await self._build_search_query(query)
                query_body['bool']['must'].append(search_query)
            
            # Add log type filter
            if log_type != "all":
                log_type_filter = self._build_log_type_filter(log_type)
                query_body['bool']['must'].append(log_type_filter)
            
            # Add rule level filter
            if rule_level != "all":
                level_filter = self._build_rule_level_filter(rule_level)
                query_body['bool']['must'].append(level_filter)
            
            # Add false positive filter
            query_body = self.add_false_positive_filter(query_body)
            
            # Get indices
            indices = await self.discover_indices()
            if not indices:
                return {
                    'logs': [],
                    'pagination': self.format_pagination(page, size, 0)
                }
            
            # Calculate offset
            from_val = (page - 1) * size
            
            # Build search body
            search_body = {
                'query': query_body,
                'sort': [{sort_by: {'order': sort_order}}],
                '_source': {
                    'excludes': ['raw_log.command', 'raw_log.script']
                }
            }
            
            # Add highlighting if query provided
            if query and query.strip():
                search_body['highlight'] = {
                    'fields': {
                        'raw_log.message': {},
                        'rule.description': {},
                        'agent.name': {},
                        'network.srcIp': {},
                        'network.destIp': {},
                        'data.srcip': {},
                        'data.dstip': {},
                        'rule.id': {},
                        'data.app': {}
                    },
                    'pre_tags': ['<strong>'],
                    'post_tags': ['</strong>']
                }
            
            # Execute search
            response = await self.client.search(
                index=','.join(indices),
                body=search_body,
                size=size,
                from_=from_val
            )
            
            # Format results
            logs = []
            for hit in response['hits']['hits']:
                log_entry = {
                    **hit['_source'],
                    'id': hit['_id'],
                    '_score': hit.get('_score', 0)
                }
                if 'highlight' in hit:
                    log_entry['_highlights'] = hit['highlight']
                logs.append(log_entry)
            
            total = response['hits']['total']['value']
            
            return {
                'logs': logs,
                'pagination': self.format_pagination(page, size, total),
                'query_info': {
                    'search_query': query,
                    'time_range': time_range,
                    'log_type': log_type,
                    'rule_level': rule_level
                }
            }
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return {
                'error': str(e),
                'logs': [],
                'pagination': self.format_pagination(page, size, 0)
            }
    
    async def _build_search_query(self, query_text: str) -> Dict[str, Any]:
        """Build search query with DQL detection and fallback strategies
        
        Args:
            query_text: Search query string
            
        Returns:
            OpenSearch query clause
        """
        # Detect DQL
        is_dql = DQLDetector.is_dql_query(query_text)
        
        if is_dql:
            # Use query_string for DQL queries
            return {
                'query_string': {
                    'query': query_text,
                    'fields': self.SEARCH_FIELDS,
                    'default_operator': 'AND',
                    'allow_leading_wildcard': True,
                    'analyze_wildcard': True,
                    'lenient': True
                }
            }
        
        # Use multi-match strategy for regular text
        return {
            'bool': {
                'should': [
                    {
                        'query_string': {
                            'query': f'*{query_text}*',
                            'fields': ['raw_log.message^3'],
                            'analyze_wildcard': True,
                            'lenient': True
                        }
                    },
                    {
                        'query_string': {
                            'query': f'*{query_text}*',
                            'fields': ['rule.description^2'],
                            'analyze_wildcard': True,
                            'lenient': True
                        }
                    },
                    {
                        'multi_match': {
                            'query': query_text,
                            'fields': [
                                'agent.name^3',
                                'network.srcIp^2',
                                'network.destIp^2',
                                'data.srcip^2',
                                'data.dstip^2',
                                'data.app^2',
                                'data.msg^1',
                                'rule.id^2',
                                'id^1'
                            ],
                            'type': 'best_fields',
                            'fuzziness': 'AUTO'
                        }
                    }
                ],
                'minimum_should_match': 1
            }
        }
    
    def _build_log_type_filter(self, log_type: str) -> Dict[str, Any]:
        """Build filter for specific log types
        
        Args:
            log_type: Log type filter
            
        Returns:
            OpenSearch filter clause
        """
        if log_type == "firewall":
            return {
                'bool': {
                    'should': [{'match': {'rule.groups': 'Firewall'}}],
                    'minimum_should_match': 1
                }
            }
        elif log_type == "ids":
            return {
                'bool': {
                    'should': [
                        {'match': {'rule.groups': 'ids'}},
                        {'match': {'rule.groups': 'ips'}},
                        {'match': {'rule.groups': 'IDS/IPS'}}
                    ],
                    'minimum_should_match': 1
                }
            }
        elif log_type == "windows":
            return {
                'bool': {
                    'should': [
                        {'match': {'rule.groups': 'windows'}},
                        {'match': {'agent.name': 'windows'}}
                    ],
                    'minimum_should_match': 1
                }
            }
        elif log_type == "linux":
            return {
                'bool': {
                    'should': [
                        {'match': {'rule.groups': 'linux'}},
                        {'match': {'rule.groups': 'linuxkernel'}}
                    ],
                    'minimum_should_match': 1
                }
            }
        return {'match_all': {}}
    
    def _build_rule_level_filter(self, rule_level: str) -> Dict[str, Any]:
        """Build filter for rule level
        
        Args:
            rule_level: Minimum rule level
            
        Returns:
            OpenSearch filter clause
        """
        try:
            level_num = int(rule_level)
            return {
                'range': {
                    'rule.level': {'gte': level_num}
                }
            }
        except ValueError:
            return {'match_all': {}}
