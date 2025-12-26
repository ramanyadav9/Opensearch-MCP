"""Correlation Engine for cross-entity event correlation"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from .models import CorrelationResult, Entity, Relationship, EntityGraph
from ..opensearch_client import SentinelOpenSearchClient

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Engine for correlating security events across entities and time"""
    
    # Performance constraints (sensible defaults)
    MAX_CORRELATION_WINDOW_HOURS = 12
    MAX_RESULTS_PER_QUERY = 10000
    DEFAULT_CORRELATION_WINDOW = timedelta(hours=12)
    
    # Risk scoring weights
    RISK_WEIGHTS = {
        'critical_alert': 30,
        'mitre_technique': 15,
        'ueba_anomaly': 20,
        'rare_external': 15,
        'lateral_movement': 25,
        'privilege_escalation': 20,
        'file_tampering': 10,
        'vulnerability_exploit': 20,
        'failed_login_spike': 10,
        'tor_proxy_usage': 15,
    }
    
    def __init__(self, client: SentinelOpenSearchClient):
        """Initialize correlation engine
        
        Args:
            client: OpenSearch client instance
        """
        self.client = client
    
    async def correlate_by_ip(
        self, 
        ip: str, 
        time_window: Optional[timedelta] = None
    ) -> CorrelationResult:
        """Correlate all events involving an IP address
        
        Searches across ALL IP-related fields in OpenSearch logs:
        - network.srcIp / network.destIp (standard network events)
        - data.srcip / data.dstip (firewall/threat hunting logs)
        - data.dest_ip (alternative destination IP field)
        - agent.ip (agent identification)
        - data.win.eventdata.destinationIp (Windows event logs)
        
        Args:
            ip: IP address to investigate (IPv4 or IPv6)
            time_window: Time window for correlation (default: 12h)
            
        Returns:
            Complete correlation result with alerts, entity graph, and risk score
        """
        if time_window is None:
            time_window = self.DEFAULT_CORRELATION_WINDOW
        
        logger.info(f"Correlating IP: {ip} over {time_window}")
        
        # Initialize result
        result = CorrelationResult(
            entity_type="ip",
            entity_value=ip,
            time_window=str(time_window)
        )
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        # Build time range string for queries
        time_range = f"custom:{start_time.isoformat()}:{end_time.isoformat()}"
        
        # Query 1: Get alerts involving this IP
        logger.debug(f"Querying alerts for IP: {ip}")
        
        # Build comprehensive IP search across ALL possible IP fields
        # Based on backend analysis: network.srcIp, network.destIp, data.srcip, data.dstip,
        # agent.ip, data.dest_ip, data.win.eventdata.destinationIp
        alerts_query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }
                    },
                    {
                        "bool": {
                            "should": [
                                # Network fields (standard fields)
                                {"term": {"network.srcIp": ip}},
                                {"term": {"network.destIp": ip}},
                                
                                # Data fields (firewall/threat hunting logs)
                                {"term": {"data.srcip": ip}},
                                {"term": {"data.dstip": ip}},
                                {"term": {"data.dest_ip": ip}},
                                
                                # Agent IP (for agent identification)
                                {"term": {"agent.ip": ip}},
                                
                                # Windows event data (for Windows logs)
                                {"term": {"data.win.eventdata.destinationIp": ip}},
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
        
        try:
            alerts_response = await self.client.search(
                index="logs-*",
                body={
                    "query": alerts_query,
                    "size": 1000,
                    "sort": [{"@timestamp": {"order": "desc"}}]
                }
            )
            
            result.query_count += 1
            
            if alerts_response and 'hits' in alerts_response:
                hits = alerts_response['hits']['hits']
                result.alerts = [hit['_source'] for hit in hits]
                result.total_events += len(hits)
                
                # Extract affected entities
                for hit in hits:
                    source = hit['_source']
                    
                    # Count critical alerts
                    if source.get('rule', {}).get('level', 0) >= 12:
                        result.critical_alerts += 1
                    
                    # Extract affected agents
                    agent_name = source.get('agent', {}).get('name')
                    if agent_name and agent_name not in result.affected_agents:
                        result.affected_agents.append(agent_name)
                    
                    # Extract users
                    for user_field in ['data.srcuser', 'data.dstuser', 'data.user']:
                        user = self._get_nested_value(source, user_field)
                        if user and user not in result.affected_users:
                            result.affected_users.append(user)
                    
                    # Extract MITRE techniques
                    mitre = source.get('rule', {}).get('mitre', {})
                    if mitre:
                        technique_ids = mitre.get('id', [])
                        if isinstance(technique_ids, str):
                            technique_ids = [technique_ids]
                        
                        for tech_id in technique_ids:
                            if not any(t['id'] == tech_id for t in result.mitre_techniques):
                                result.mitre_techniques.append({
                                    'id': tech_id,
                                    'technique': mitre.get('technique', ''),
                                    'tactic': mitre.get('tactic', '')
                                })
                        
                        # Extract tactics
                        tactics = mitre.get('tactic', [])
                        if isinstance(tactics, str):
                            tactics = [tactics]
                        for tactic in tactics:
                            if tactic and tactic not in result.mitre_tactics:
                                result.mitre_tactics.append(tactic)
                    
                    # Add to timeline
                    result.timeline.append({
                        'timestamp': source.get('@timestamp'),
                        'type': 'alert',
                        'description': source.get('rule', {}).get('description', ''),
                        'level': source.get('rule', {}).get('level'),
                        'agent': agent_name
                    })
                
                logger.info(f"Found {len(hits)} alerts for IP {ip}")
        
        except Exception as e:
            logger.error(f"Error querying alerts for IP {ip}: {e}")
        
        # Query 2: Get network flows
        logger.debug(f"Network flow analysis for IP: {ip}")
        try:
            network_query = {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {"term": {"network.srcIp": ip}},
                                    {"term": {"network.destIp": ip}},
                                    {"term": {"data.srcip": ip}},
                                    {"term": {"data.dstip": ip}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            }

            network_response = await self.client.search(
                index="logs-*",
                body={
                    "query": network_query,
                    "size": 500,
                    "sort": [{"@timestamp": {"order": "desc"}}]
                }
            )

            result.query_count += 1

            if network_response and 'hits' in network_response:
                hits = network_response['hits']['hits']
                result.total_events += len(hits)
                
                for hit in hits:
                    source = hit['_source']
                    
                    # Extract unique destinations/sources for graph
                    src_ip = source.get('network', {}).get('srcIp') or source.get('data', {}).get('srcip')
                    dest_ip = source.get('network', {}).get('destIp') or source.get('data', {}).get('dstip')
                    
                    # Add simple network events to timeline if they are significant (e.g., large transfer or specific ports)
                    # For now, we add a summary if it looks interesting
                    if src_ip and dest_ip:
                        other_ip = dest_ip if src_ip == ip else src_ip
                        # We don't want to flood the timeline, so maybe just track connections in the future
                        # For now, let's look for high ports or known protocols
                        pass

        except Exception as e:
            logger.error(f"Error querying network flows for IP {ip}: {e}")
        
        # Query 3: Get authentication sessions
        # 3a. Auth sessions where source IP is the investigated IP
        logger.debug(f"Querying auth sessions for source IP: {ip}")
        try:
            auth_ip_query = {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {"term": {"network.srcIp": ip}},
                                    {"term": {"data.srcip": ip}},
                                    {"term": {"source.ip": ip}}
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {"match": {"rule.groups": "authentication_success"}},
                                    {"match": {"rule.groups": "authentication_failed"}},
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            }
            
            auth_response = await self.client.search(
                index="logs-*",
                body={"query": auth_ip_query, "size": 100}
            )
            
            result.query_count += 1
            
            if auth_response and 'hits' in auth_response:
                hits = auth_response['hits']['hits']
                result.total_events += len(hits)
                
                for hit in hits:
                    source = hit['_source']
                    is_failed = 'failed' in str(source.get('rule', {}).get('groups', '')).lower()
                    user = source.get('data', {}).get('srcuser') or source.get('data', {}).get('user')
                    
                    if user and user not in result.affected_users:
                        result.affected_users.append(user)
                    
                    result.timeline.append({
                        'timestamp': source.get('@timestamp'),
                        'type': 'login_failed' if is_failed else 'login_success',
                        'description': f"Login {'failed' if is_failed else 'success'} for user {user or 'unknown'}",
                        'level': source.get('rule', {}).get('level'),
                        'user': user
                    })

                    # Add risk for failed logins from this IP
                    if is_failed:
                        # Check if we already have a failed login risk factor
                        existing = next((r for r in result.risk_factors if r['type'] == 'failed_login_spike'), None)
                        if existing:
                            existing['count'] += 1
                            existing['points'] = min(existing['count'] * 2, 20)
                            existing['description'] = f"{existing['count']} failed login attempts from IP"
                        else:
                             result.risk_factors.append({
                                'type': 'failed_login_spike',
                                'count': 1,
                                'points': 2,
                                'description': "Failed login attempts from IP"
                            })

        except Exception as e:
            logger.error(f"Error querying auth sessions for IP {ip}: {e}")

        # 3b. Auth sessions for affected agents (if any)
        if result.affected_agents:
            logger.debug(f"Querying auth sessions for {len(result.affected_agents)} agents")
            try:
                # Limit to first 5 agents to avoid massive queries
                target_agents = result.affected_agents[:5]
                agent_auth_query = {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat()
                                    }
                                }
                            },
                             {
                                "bool": {
                                    "should": [
                                        {"match": {"rule.groups": "authentication_success"}},
                                        {"match": {"rule.groups": "authentication_failed"}},
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "terms": {"agent.name": target_agents}
                            }
                        ]
                    }
                }
                
                agent_auth_response = await self.client.search(
                    index="logs-*",
                    body={"query": agent_auth_query, "size": 100}
                )
                
                result.query_count += 1
                
                if agent_auth_response and 'hits' in agent_auth_response:
                    hits = agent_auth_response['hits']['hits']
                    # We don't add to total_events here to avoid double counting if they overlap, 
                    # and because these are secondary correlations
                    
                    for hit in hits:
                        source = hit['_source']
                        # Just extract users we might have missed
                        user = source.get('data', {}).get('user') or source.get('data', {}).get('srcuser')
                        if user and user not in result.affected_users:
                            result.affected_users.append(user)
                            
            except Exception as e:
                logger.error(f"Error querying agent auth sessions: {e}")
        
        # Build entity graph
        result.entity_graph = self._build_entity_graph(result)
        
        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result)
        result.risk_level = self._get_risk_level(result.risk_score)
        
        # Generate verdict and recommendations
        result.verdict = self._generate_verdict(result)
        result.recommendations = self._generate_recommendations(result)
        
        logger.info(f"Correlation complete for IP {ip}: {result.total_events} events, risk={result.risk_score}")
        
        return result
    
    def _build_entity_graph(self, result: CorrelationResult) -> EntityGraph:
        """Build entity relationship graph from correlation data
        
        Args:
            result: Correlation result with correlated data
            
        Returns:
            Entity graph
        """
        graph = EntityGraph()
        
        # Add root entity (IP)
        root_entity = Entity(
            id=f"ip:{result.entity_value}",
            type="ip",
            label=result.entity_value,
            event_count=result.total_events
        )
        graph.add_node(root_entity)
        
        # Add agent nodes
        for agent in result.affected_agents:
            agent_entity = Entity(
                id=f"host:{agent}",
                type="host",
                label=agent,
                event_count=sum(1 for a in result.alerts if a.get('agent', {}).get('name') == agent)
            )
            graph.add_node(agent_entity)
            
            # Add relationship
            graph.add_edge(Relationship(
                source=root_entity.id,
                target=agent_entity.id,
                type="contacted",
                weight=agent_entity.event_count
            ))
        
        # Add user nodes
        for user in result.affected_users:
            user_entity = Entity(
                id=f"user:{user}",
                type="user",
                label=user,
                event_count=1
            )
            graph.add_node(user_entity)
            
            # Link to IP
            graph.add_edge(Relationship(
                source=user_entity.id,
                target=root_entity.id,
                type="used",
                weight=1
            ))
        
        # Add alert nodes
        for idx, alert in enumerate(result.alerts[:10]):  # Limit to top 10 for graph clarity
            alert_id = alert.get('id', f"alert-{idx}")
            alert_entity = Entity(
                id=f"alert:{alert_id}",
                type="alert",
                label=alert.get('rule', {}).get('description', 'Alert')[:50],
                properties={
                    'level': alert.get('rule', {}).get('level'),
                    'rule_id': alert.get('rule', {}).get('id')
                }
            )
            graph.add_node(alert_entity)
            
            # Link to IP
            graph.add_edge(Relationship(
                source=root_entity.id,
                target=alert_entity.id,
                type="triggered",
                weight=1,
                timestamp=self._parse_timestamp(alert.get('@timestamp'))
            ))
        
        return graph
    
    def _calculate_risk_score(self, result: CorrelationResult) -> int:
        """Calculate overall risk score
        
        Args:
            result: Correlation result
            
        Returns:
            Risk score (0-100)
        """
        score = 0
        
        # Critical alerts
        if result.critical_alerts > 0:
            weight = self.RISK_WEIGHTS['critical_alert']
            multiplier = 2 if result.critical_alerts > 1 else 1
            score += weight * multiplier
            result.risk_factors.append({
                'type': 'critical_alerts',
                'count': result.critical_alerts,
                'points': weight * multiplier,
                'description': f"{result.critical_alerts} critical alert(s) detected"
            })
        
        # MITRE techniques
        if result.mitre_techniques:
            weight = self.RISK_WEIGHTS['mitre_technique']
            count = len(result.mitre_techniques)
            points = weight * min(count, 3)  # Cap at 3 techniques
            score += points
            result.risk_factors.append({
                'type': 'mitre_techniques',
                'count': count,
                'points': points,
                'description': f"{count} MITRE ATT&CK technique(s) identified"
            })
        
        # Lateral movement detection
        if 'Lateral Movement' in result.mitre_tactics:
            weight = self.RISK_WEIGHTS['lateral_movement']
            score += weight
            result.risk_factors.append({
                'type': 'lateral_movement',
                'count': 1,
                'points': weight,
                'description': "Lateral movement indicators detected"
            })
        
        # Privilege escalation
        if 'Privilege Escalation' in result.mitre_tactics:
            weight = self.RISK_WEIGHTS['privilege_escalation']
            score += weight
            result.risk_factors.append({
                'type': 'privilege_escalation',
                'count': 1,
                'points': weight,
                'description': "Privilege escalation indicators detected"
            })
        
        # Multiple affected systems
        if len(result.affected_agents) > 3:
            points = 15
            score += points
            result.risk_factors.append({
                'type': 'multiple_systems',
                'count': len(result.affected_agents),
                'points': points,
                'description': f"{len(result.affected_agents)} systems affected"
            })
        
        # Cap at 100
        return min(score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            Risk level string
        """
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Informational"
    
    def _generate_verdict(self, result: CorrelationResult) -> str:
        """Generate overall verdict
        
        Args:
            result: Correlation result
            
        Returns:
            Verdict string
        """
        if result.risk_score >= 70:
            return "Malicious"
        elif result.risk_score >= 40:
            return "Suspicious"
        elif result.risk_score >= 20:
            return "Potentially Suspicious"
        else:
            return "Clean"
    
    def _generate_recommendations(self, result: CorrelationResult) -> List[str]:
        """Generate actionable recommendations
        
        Args:
            result: Correlation result
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if result.critical_alerts > 0:
            recommendations.append(
                f"URGENT: Investigate {result.critical_alerts} critical alert(s) immediately"
            )
        
        if result.affected_agents:
            recommendations.append(
                f"Review activity on {len(result.affected_agents)} affected system(s): {', '.join(result.affected_agents[:3])}"
            )
        
        if 'Lateral Movement' in result.mitre_tactics:
            recommendations.append(
                "CRITICAL: Lateral movement detected - isolate affected systems and review access logs"
            )
        
        if result.mitre_techniques:
            recommendations.append(
                f"Review MITRE ATT&CK techniques: {', '.join([t['id'] for t in result.mitre_techniques[:3]])}"
            )
        
        if result.affected_users:
            recommendations.append(
                f"Investigate user accounts: {', '.join(result.affected_users[:3])}"
            )
        
        if result.risk_score >= 60:
            recommendations.append(
                "Consider temporary network isolation for affected IP"
            )
        
        if not recommendations:
            recommendations.append("No immediate action required - continue monitoring")
        
        return recommendations
    
    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get nested dictionary value by dot notation path
        
        Args:
            obj: Dictionary object
            path: Dot notation path (e.g., 'data.srcuser')
            
        Returns:
            Value or None
        """
        keys = path.split('.')
        value = obj
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    def _parse_timestamp(self, timestamp: Any) -> Optional[datetime]:
        """Parse timestamp string to datetime
        
        Args:
            timestamp: Timestamp string or object
            
        Returns:
            datetime object or None
        """
        if not timestamp:
            return None
        
        if isinstance(timestamp, datetime):
            return timestamp
        
        try:
            if isinstance(timestamp, str):
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp)
        except Exception as e:
            logger.warning(f"Failed to parse timestamp {timestamp}: {e}")
        
        return None
