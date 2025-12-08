"""Network analytics tool for flow analysis"""

import logging
from typing import Dict, Any, List
from .base import BaseTool
from ..utils.time_parser import TimeRangeParser
from ..utils.validators import IPValidator, ProtocolNormalizer

logger = logging.getLogger(__name__)


class NetworkAnalyticsTool(BaseTool):
    """Analyze network traffic flows and patterns"""
    
    def name(self) -> str:
        return "get_network_flows"
    
    def description(self) -> str:
        return (
            "Get AGGREGATED NETWORK FLOWS (source->destination IP pairs). Use for: "
            "'Show traffic patterns', 'Data exfiltration', 'Unusual connections', 'Top talkers'. "
            "Returns connection counts, protocols, ports. Use get_connection_details for raw logs."
        )
    
    async def execute(self,
                     time_range: str = "12h",
                     min_bytes: int = 0,
                     src_ip: str = None,
                     dest_ip: str = None,
                     limit: int = 100) -> Dict[str, Any]:
        """Get network flows
        
        Args:
            time_range: Time range for analysis
            min_bytes: Minimum bytes to include (if available)
            src_ip: Filter by source IP
            dest_ip: Filter by destination IP
            limit: Maximum number of flows to return
            
        Returns:
            Network flow analysis
        """
        try:
            # Parse time range
            time_filter = TimeRangeParser.parse(time_range)
            
            # Calculate dynamic flow limit based on time range
            # For longer time ranges, we might need a larger aggregation size
            # but we'll cap it to avoid memory issues
            flow_limit = min(limit * 2, self.config.get('limits', {}).get('max_flow_limit', 5000))
            
            # Build query
            query_body = {
                'bool': {
                    'must': [time_filter]
                }
            }
            
            # Add IP filters if provided
            if src_ip:
                query_body['bool']['must'].append({'term': {'network.srcIp': src_ip}})
            if dest_ip:
                query_body['bool']['must'].append({'term': {'network.destIp': dest_ip}})
            
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
                        'protocols': {
                            'terms': {
                                'field': 'network.protocol',
                                'size': 20,
                                'missing': 'unknown'
                            }
                        },
                        'network_flows': {
                            'composite': {
                                'size': flow_limit,
                                'sources': [
                                    {'srcIp': {'terms': {'field': 'network.srcIp', 'missing_bucket': True}}},
                                    {'destIp': {'terms': {'field': 'network.destIp', 'missing_bucket': True}}},
                                    {'protocol': {'terms': {'field': 'network.protocol', 'missing_bucket': True}}}
                                ]
                            },
                            'aggs': {
                                'flow_count': {'value_count': {'field': 'network.srcIp'}},
                                'src_ports': {'terms': {'field': 'network.srcPort', 'size': 5}},
                                'dest_ports': {'terms': {'field': 'network.destPort', 'size': 5}},
                                'latest_timestamp': {'max': {'field': '@timestamp'}},
                                'earliest_timestamp': {'min': {'field': '@timestamp'}}
                            }
                        }
                    }
                }
            )
            
            # Process results
            aggs = response['aggregations']
            
            # Process protocols
            protocols = [
                {
                    'protocol': ProtocolNormalizer.normalize(b['key']),
                    'count': b['doc_count']
                }
                for b in aggs['protocols']['buckets']
            ]
            
            # Process flows
            flows = []
            flow_buckets = aggs['network_flows']['buckets']
            
            for bucket in flow_buckets:
                src = bucket['key']['srcIp']
                dst = bucket['key']['destIp']
                raw_proto = bucket['key']['protocol']
                
                # Validate IPs
                if not IPValidator.is_valid_ip(src) or not IPValidator.is_valid_ip(dst):
                    continue
                if src == dst:  # Skip self-loops
                    continue
                
                # Normalize protocol
                protocol = ProtocolNormalizer.normalize(raw_proto)
                
                # Get ports
                src_ports = [b['key'] for b in bucket['src_ports']['buckets']]
                dest_ports = [b['key'] for b in bucket['dest_ports']['buckets']]
                
                # Calculate metrics
                # Note: In a real scenario, we'd sum actual bytes if available
                # Here we estimate based on flow count or use available fields
                count = bucket['doc_count']
                
                flows.append({
                    'source': src,
                    'target': dst,
                    'protocol': protocol,
                    'count': count,
                    'src_ports': src_ports,
                    'dest_ports': dest_ports,
                    'last_seen': bucket['latest_timestamp'].get('value_as_string'),
                    'first_seen': bucket['earliest_timestamp'].get('value_as_string')
                })
            
            # Sort by count descending and apply limit
            flows.sort(key=lambda x: x['count'], reverse=True)
            flows = flows[:limit]
            
            return {
                'time_range': time_range,
                'total_flows': len(flows),
                'top_protocols': protocols,
                'flows': flows
            }
            
        except Exception as e:
            logger.error(f"Network analytics error: {e}")
            return {
                'error': str(e),
                **self._empty_result(time_range)
            }
    
    def _empty_result(self, time_range: str) -> Dict[str, Any]:
        return {
            'time_range': time_range,
            'total_flows': 0,
            'top_protocols': [],
            'flows': []
        }


class ConnectionDetailsTool(BaseTool):
    """Get detailed connection logs with pagination"""
    
    def name(self) -> str:
        return "get_connection_details"
    
    def description(self) -> str:
        return (
            "Get INDIVIDUAL CONNECTION LOGS (not aggregated). Use AFTER get_network_flows to drill down. "
            "Filter by src_ip, dest_ip, country, direction (incoming/outgoing). "
            "Returns paginated raw connection events with timestamps."
        )
    
    async def execute(self,
                     time_range: str = "24h",
                     page: int = 1,
                     size: int = 100,
                     src_ip: str = None,
                     dest_ip: str = None,
                     country: str = None,
                     connection_type: str = "all") -> Dict[str, Any]:
        """Get connection details
        
        Args:
            time_range: Time range
            page: Page number
            size: Results per page
            src_ip: Source IP filter
            dest_ip: Destination IP filter
            country: Filter by country code (ISO 2)
            connection_type: 'all', 'incoming', 'outgoing', 'internal'
            
        Returns:
            Paginated connection logs
        """
        try:
            # Cap page size
            size = self.cap_page_size(size)
            
            # Parse time range
            time_filter = TimeRangeParser.parse(time_range)
            
            # Build query
            query_body = {
                'bool': {
                    'must': [time_filter]
                }
            }
            
            # Add IP filters
            if src_ip:
                query_body['bool']['must'].append({'term': {'network.srcIp': src_ip}})
            if dest_ip:
                query_body['bool']['must'].append({'term': {'network.destIp': dest_ip}})
                
            # Add Country filter
            if country:
                query_body['bool']['must'].append({
                    'bool': {
                        'should': [
                            {'term': {'data.srccountry': country}},
                            {'term': {'data.dstcountry': country}}
                        ],
                        'minimum_should_match': 1
                    }
                })
            
            # Add Connection Type filter
            # This logic mirrors common SIEM logic for directionality
            if connection_type == 'incoming':
                # External source, internal dest (simplified)
                query_body['bool']['must_not'] = [{'term': {'network.srcIp': '10.0.0.0/8'}}] # Example
                # In reality, rely on `data.direction` if available or `rule.groups`
                query_body['bool']['must'].append({'term': {'data.direction': 'inbound'}})
            elif connection_type == 'outgoing':
                query_body['bool']['must'].append({'term': {'data.direction': 'outbound'}})
            
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
            
            # Search
            response = await self.client.search(
                index=','.join(indices),
                body={
                    'query': query_body,
                    'sort': [{'@timestamp': {'order': 'desc'}}],
                    '_source': {
                        'includes': [
                            '@timestamp', 'network.srcIp', 'network.destIp',
                            'network.srcPort', 'network.destPort', 'network.protocol',
                            'data.srccountry', 'data.dstcountry', 'rule.description',
                            'agent.name'
                        ]
                    }
                },
                size=size,
                from_=from_val
            )
            
            # Format logs
            logs = []
            for hit in response['hits']['hits']:
                log_entry = {
                    **hit['_source'],
                    'id': hit['_id']
                }
                logs.append(log_entry)
            
            total = response['hits']['total']['value']
            
            return {
                'logs': logs,
                'pagination': self.format_pagination(page, size, total),
                'query_info': {
                    'time_range': time_range,
                    'connection_type': connection_type,
                    'src_ip': src_ip,
                    'dest_ip': dest_ip
                }
            }
            
        except Exception as e:
            logger.error(f"Connection details error: {e}")
            return {
                'error': str(e),
                'logs': []
            }
