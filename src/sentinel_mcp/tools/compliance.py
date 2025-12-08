"""Compliance-specific log tools"""

import logging
from typing import Dict, Any, List
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser

logger = logging.getLogger(__name__)


class ComplianceBaseTool(BaseTool):
    """Base class for compliance tools"""
    
    async def _execute_compliance_search(self,
                                       compliance_field: str,
                                       time_range: str,
                                       page: int,
                                       size: int,
                                       extra_aggs: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute standardized compliance search"""
        try:
            indices = await self.discover_indices()
            if not indices:
                return {'logs': [], 'pagination': self.format_pagination(page, size, 0)}
            
            time_filter = TimeRangeParser.parse(time_range)
            
            # Build query
            query = {
                'bool': {
                    'must': [
                        time_filter,
                        {'exists': {'field': compliance_field}}
                    ]
                }
            }
            
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
            
            # Aggregations
            aggs = {
                'controls': {'terms': {'field': compliance_field, 'size': 20}},
                'agents': {'terms': {'field': 'agent.name', 'size': 10}},
                'levels': {'terms': {'field': 'rule.level', 'size': 10}}
            }
            if extra_aggs:
                aggs.update(extra_aggs)
                
            stats_response = await self.client.search(
                index=','.join(indices),
                body={'size': 0, 'query': query, 'aggs': aggs}
            )
            stats = stats_response['aggregations']
            
            logs = []
            for hit in response['hits']['hits']:
                logs.append({**hit['_source'], 'id': hit['_id']})
                
            total = response['hits']['total']['value']
            
            return {
                'logs': logs,
                'pagination': self.format_pagination(page, size, total),
                'stats': {
                    'controls': [{'key': b['key'], 'count': b['doc_count']} for b in stats['controls']['buckets']],
                    'top_agents': [{'name': b['key'], 'count': b['doc_count']} for b in stats['agents']['buckets']],
                    'severity': [{'level': b['key'], 'count': b['doc_count']} for b in stats['levels']['buckets']],
                    **{k: [{'key': b['key'], 'count': b['doc_count']} for b in stats[k]['buckets']] for k in extra_aggs or {}}
                }
            }
        except Exception as e:
            logger.error(f"Compliance search error ({compliance_field}): {e}")
            return {'error': str(e), 'logs': []}


class HIPAAEventsTool(ComplianceBaseTool):
    def name(self) -> str: return "get_hipaa_events"
    def description(self) -> str: return "Get HIPAA COMPLIANCE events (healthcare data protection). Use for: 'HIPAA violations', 'PHI access', 'Healthcare compliance status'. Returns events mapped to HIPAA controls with severity levels."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        return await self._execute_compliance_search("rule.hipaa", time_range, page, int(size))


class GDPREventsTool(ComplianceBaseTool):
    def name(self) -> str: return "get_gdpr_events"
    def description(self) -> str: return "Get GDPR COMPLIANCE events (EU data protection). Use for: 'GDPR violations', 'EU data transfers', 'Privacy compliance'. Returns events with source/destination country breakdown."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        extra_aggs = {
            'src_countries': {'terms': {'field': 'data.srccountry', 'size': 10}},
            'dst_countries': {'terms': {'field': 'data.dstcountry', 'size': 10}}
        }
        return await self._execute_compliance_search("rule.gdpr", time_range, page, int(size), extra_aggs)


class NISTEventsTool(ComplianceBaseTool):
    def name(self) -> str: return "get_nist_events"
    def description(self) -> str: return "Get NIST COMPLIANCE events (US gov/enterprise security framework). Use for: 'NIST controls', 'Framework compliance'. Returns events mapped to NIST 800-53 controls."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        return await self._execute_compliance_search("rule.nist", time_range, page, int(size))


class PCIDSSEventsTool(ComplianceBaseTool):
    def name(self) -> str: return "get_pci_dss_events"
    def description(self) -> str: return "Get PCI DSS COMPLIANCE events (payment card security). Use for: 'Credit card security', 'PCI audit', 'Payment compliance'. Returns events mapped to PCI DSS requirements."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        return await self._execute_compliance_search("rule.pci_dss", time_range, page, int(size))


class TSCEventsTool(ComplianceBaseTool):
    def name(self) -> str: return "get_tsc_events"
    def description(self) -> str: return "Get TSC (SOC 2) COMPLIANCE events (Trust Services Criteria). Use for: 'SOC 2 audit', 'Service organization controls'. Returns events mapped to TSC categories."
    
    async def execute(self, time_range: str = "24h", page: int = 1, size: int = 100) -> Dict[str, Any]:
        return await self._execute_compliance_search("rule.tsc", time_range, page, int(size))
