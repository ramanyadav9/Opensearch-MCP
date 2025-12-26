"""User Investigation Tool

Comprehensive UEBA orchestrator that treats user==agent and correlates all activity.
Uses multiple specialized tools to build complete behavioral profile.
"""

import logging
from typing import Dict, Any, List
from datetime import timedelta, datetime

from .base import BaseTool

logger = logging.getLogger(__name__)


class InvestigateUserTool(BaseTool):
    """Comprehensive UEBA orchestrator - investigates user/agent with full activity correlation"""
    
    def __init__(self, client, config: Dict[str, Any]):
        """Initialize tool
        
        Args:
            client: OpenSearch client
            config: Tool configuration
        """
        super().__init__(client, config)
    
    def name(self) -> str:
        """Tool name"""
        return "investigate_user"
    
    def description(self) -> str:
        """Tool description"""
        return (
            "USE THIS when user asks to 'investigate' a user or agent/person name. "
            "Performs deep UEBA analysis: authentication sessions, file modifications, malware events, "
            "network activity, compliance violations, insider threat scoring. "
            "Example queries: 'Investigate user raman', 'Is john a threat?', 'Analyze admin behavior'. "
            "NOT for simple log lookups - use get_agent_logs for those."
        )
    
    async def execute(
        self,
        username: str,
        time_range: str = "24h",
        baseline_window: str = "30d",
        **kwargs
    ) -> Dict[str, Any]:
        """Execute comprehensive user/agent investigation
        
        Args:
            username: Username or agent name to investigate
            time_range: Investigation time window (default: 24h)
                       For current activity analysis
            baseline_window: Historical baseline window (default: 30d)
                            For behavioral baseline comparison
            
        Returns:
            Comprehensive UEBA report with all correlated activity
        """
        logger.info(f"UEBA Investigation: {username}, current={time_range}, baseline={baseline_window}")
        
        # Initialize result structure
        result = {
            'entity': username,
            'entity_type': 'user_agent',  # User == Agent
            'investigation_window': time_range,
            'baseline_window': baseline_window,
            'timestamp': datetime.utcnow().isoformat(),
            
            # Activity data (populated by orchestration)
            'authentication_activity': {},
            'file_modifications': {},
            'malware_events': {},
            'network_activity': {},
            'vulnerability_data': {},
            'compliance_violations': {},
            'process_execution': {},
            
            # Behavioral analysis
            'baseline': {},
            'anomalies': [],
            'behavioral_changes': [],
            
            # Risk scoring
            'risk_score': 0,
            'risk_level': 'Informational',
            'insider_threat_score': 0,
            'risk_factors': [],
            
            # Recommendations
            'recommendations': [],
            'alerts': []
        }
        
        # STEP 1: Gather all activity using specialized queries
        logger.info(f"Step 1: Gathering comprehensive activity for {username}")
        
        # 1.1 Authentication Sessions
        result['authentication_activity'] = await self._get_auth_sessions(username, time_range)
        
        # 1.2 File Modifications (FIM)
        result['file_modifications'] = await self._get_fim_events(username, time_range)
        
        # 1.3 Malware/Security Events
        result['malware_events'] = await self._get_malware_events(username, time_range)
        
        # 1.4 Network Activity
        result['network_activity'] = await self._get_network_activity(username, time_range)
        
        # 1.5 Vulnerability Events
        result['vulnerability_data'] = await self._get_vulnerability_events(username, time_range)
        
        # 1.6 Compliance Violations
        result['compliance_violations'] = await self._get_compliance_violations(username, time_range)
        
        # 1.7 Process Execution (Windows)
        result['process_execution'] = await self._get_process_execution(username, time_range)
        
        # STEP 2: Build behavioral baseline from historical data
        logger.info(f"Step 2: Building behavioral baseline ({baseline_window})")
        result['baseline'] = await self._build_behavioral_baseline(username, baseline_window)
        
        # STEP 3: Detect anomalies by comparing current vs baseline
        logger.info(f"Step 3: Detecting anomalies")
        result['anomalies'] = self._detect_anomalies(result)
        
        # STEP 4: Internal Behavioral Analysis
        logger.info(f"Step 4: Performing internal behavioral analysis")
        # (Already done in Step 3 via _detect_anomalies which now uses enhanced baseline)
        
        # STEP 5: Calculate risk scores
        logger.info(f"Step 5: Calculating risk scores")
        result['risk_score'] = self._calculate_comprehensive_risk(result)
        result['risk_level'] = self._get_risk_level(result['risk_score'])
        result['insider_threat_score'] = self._calculate_insider_threat(result)
        
        # STEP 6: Generate recommendations
        logger.info(f"Step 6: Generating recommendations")
        result['recommendations'] = self._generate_recommendations(result)
        
        logger.info(
            f"UEBA complete: {username} | "
            f"Events: auth={result['authentication_activity'].get('total', 0)}, "
            f"fim={result['file_modifications'].get('total', 0)}, "
            f"malware={result['malware_events'].get('total', 0)} | "
            f"Risk={result['risk_score']}, Insider={result['insider_threat_score']}"
        )
        
        return result
    
    async def _get_auth_sessions(self, username: str, time_range: str) -> Dict[str, Any]:
        """Get authentication sessions for user/agent"""
        time_window = self._parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
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
                        "bool": {
                            "should": [
                                {"term": {"agent.name": username}},
                                {"term": {"data.user": username}},
                                {"term": {"data.srcuser": username}},
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
        
        try:
            response = await self.client.search(index="logs-*", body={"query": query, "size": 1000})
            hits = response['hits']['hits']
            logs = [hit['_source'] for hit in hits]
            
            successful = sum(1 for log in logs if 'success' in str(log.get('rule', {}).get('groups', '')).lower())
            failed = sum(1 for log in logs if 'failed' in str(log.get('rule', {}).get('groups', '')).lower())
            
            # Extract unique source IPs
            source_ips = list(set(
                log.get('network', {}).get('srcIp') or log.get('data', {}).get('srcip')
                for log in logs
                if log.get('network', {}).get('srcIp') or log.get('data', {}).get('srcip')
            ))
            
            return {
                'total': len(logs),
                'successful': successful,
                'failed': failed,
                'source_ips': source_ips,
                'sessions': logs[:100]  # Limit for response size
            }
        except Exception as e:
            logger.error(f"Error getting auth sessions: {e}")
            return {'total': 0, 'error': str(e)}
    
    async def _get_fim_events(self, username: str, time_range: str) -> Dict[str, Any]:
        """Get file integrity monitoring events"""
        time_window = self._parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    {"exists": {"field": "syscheck.event"}},
                    {"term": {"agent.name": username}}
                ]
            }
        }
        
        try:
            response = await self.client.search(index="logs-*", body={"query": query, "size": 1000})
            hits = response['hits']['hits']
            logs = [hit['_source'] for hit in hits]
            
            by_event = {}
            for log in logs:
                event_type = log.get('syscheck', {}).get('event', 'unknown')
                by_event[event_type] = by_event.get(event_type, 0) + 1
            
            return {
                'total': len(logs),
                'by_event_type': by_event,
                'modified_files': [log.get('syscheck', {}).get('path') for log in logs if log.get('syscheck', {}).get('event') == 'modified'][:50],
                'events': logs[:100]
            }
        except Exception as e:
            logger.error(f"Error getting FIM events: {e}")
            return {'total': 0, 'error': str(e)}
    
    async def _get_malware_events(self, username: str, time_range: str) -> Dict[str, Any]:
        """Get malware and security scanner events"""
        time_window = self._parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    {
                        "bool": {
                            "should": [
                                {"match": {"rule.groups": "VirusScanner"}},
                                {"match": {"rule.groups": "SentinelAI"}},
                                {"match": {"rule.groups": "rootcheck"}},
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    {"term": {"agent.name": username}}
                ]
            }
        }
        
        try:
            response = await self.client.search(index="logs-*", body={"query": query, "size": 1000})
            hits = response['hits']['hits']
            logs = [hit['_source'] for hit in hits]
            
            return {
                'total': len(logs),
                'detections': logs[:50],
                'critical_count': sum(1 for log in logs if log.get('rule', {}).get('level', 0) >= 12)
            }
        except Exception as e:
            logger.error(f"Error getting malware events: {e}")
            return {'total': 0, 'error': str(e)}
    
    async def _get_network_activity(self, username: str, time_range: str) -> Dict[str, Any]:
        """Get network activity for agent"""
        time_window = self._parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    {"term": {"agent.name": username}},
                    {
                        "bool": {
                            "should": [
                                {"exists": {"field": "network.srcIp"}},
                                {"exists": {"field": "network.destIp"}},
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
        
        try:
            response = await self.client.search(index="logs-*", body={"query": query, "size": 1000})
            hits = response['hits']['hits']
            logs = [hit['_source'] for hit in hits]
            
            # Extract destinations
            destinations = list(set(
                log.get('network', {}).get('destIp') or log.get('data', {}).get('dstip')
                for log in logs
                if log.get('network', {}).get('destIp') or log.get('data', {}).get('dstip')
            ))
            
            return {
                'total': len(logs),
                'unique_destinations': len(destinations),
                'destination_ips': destinations[:100],
                'connections': logs[:100]
            }
        except Exception as e:
            logger.error(f"Error getting network activity: {e}")
            return {'total': 0, 'error': str(e)}
    
    async def _get_vulnerability_events(self, username: str, time_range: str) -> Dict[str, Any]:
        """Get vulnerability scan results"""
        time_window = self._parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    {"exists": {"field": "data.vulnerability.cve"}},
                    {"term": {"agent.name": username}}
                ]
            }
        }
        
        try:
            response = await self.client.search(index="logs-*", body={"query": query, "size": 1000})
            hits = response['hits']['hits']
            logs = [hit['_source'] for hit in hits]
            
            cves = list(set(log.get('data', {}).get('vulnerability', {}).get('cve') for log in logs if log.get('data', {}).get('vulnerability', {}).get('cve')))
            
            return {
                'total': len(logs),
                'unique_cves': len(cves),
                'cves': cves[:50],
                'vulnerabilities': logs[:50]
            }
        except Exception as e:
            logger.error(f"Error getting vulnerability events: {e}")
            return {'total': 0, 'error': str(e)}
    
    async def _get_compliance_violations(self, username: str, time_range: str) -> Dict[str, Any]:
        """Get compliance violation events"""
        time_window = self._parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    {"term": {"agent.name": username}},
                    {
                        "bool": {
                            "should": [
                                {"exists": {"field": "rule.hipaa"}},
                                {"exists": {"field": "rule.gdpr"}},
                                {"exists": {"field": "rule.pci_dss"}},
                                {"exists": {"field": "rule.nist"}},
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
        
        try:
            response = await self.client.search(index="logs-*", body={"query": query, "size": 1000})
            hits = response['hits']['hits']
            logs = [hit['_source'] for hit in hits]
            
            return {
                'total': len(logs),
                'hipaa': sum(1 for log in logs if log.get('rule', {}).get('hipaa')),
                'gdpr': sum(1 for log in logs if log.get('rule', {}).get('gdpr')),
                'pci_dss': sum(1 for log in logs if log.get('rule', {}).get('pci_dss')),
                'violations': logs[:50]
            }
        except Exception as e:
            logger.error(f"Error getting compliance violations: {e}")
            return {'total': 0, 'error': str(e)}
    
    async def _get_process_execution(self, username: str, time_range: str) -> Dict[str, Any]:
        """Get process execution events (Windows)"""
        time_window = self._parse_time_range(time_range)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    {"exists": {"field": "data.win.eventdata.processName"}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"agent.name": username}},
                                {"term": {"data.win.eventdata.targetUserName": username}},
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
        
        try:
            response = await self.client.search(index="logs-*", body={"query": query, "size": 1000})
            hits = response['hits']['hits']
            logs = [hit['_source'] for hit in hits]
            
            processes = list(set(log.get('data', {}).get('win', {}).get('eventdata', {}).get('processName') for log in logs if log.get('data', {}).get('win', {}).get('eventdata', {}).get('processName')))
            
            return {
                'total': len(logs),
                'unique_processes': len(processes),
                'processes': processes[:100],
                'executions': logs[:100]
            }
        except Exception as e:
            logger.error(f"Error getting process execution: {e}")
            return {'total': 0, 'error': str(e)}
    
    async def _build_behavioral_baseline(self, username: str, baseline_window: str) -> Dict[str, Any]:
        """Build behavioral baseline from historical data"""
        time_window = self._parse_time_range(baseline_window)
        end_time = datetime.utcnow()
        start_time = end_time - time_window
        
        logger.info(f"Building baseline for {username} from {start_time} to {end_time}")
        
        # Get historical logins
        hist_auth = await self._get_auth_sessions(username, baseline_window)
        
        # Get historical FIM
        hist_fim = await self._get_fim_events(username, baseline_window)
        
        # Get historical network
        hist_network = await self._get_network_activity(username, baseline_window)
        
        # Calculate hourly distribution
        hour_counts = {}
        for session in hist_auth.get('sessions', []):
            try:
                dt = datetime.fromisoformat(session['timestamp'].replace('Z', '+00:00'))
                hour = dt.hour
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
            except:
                pass
        
        # Calculate process frequency
        process_counts = {}
        hist_proc = await self._get_process_execution(username, baseline_window)
        for proc in hist_proc.get('processes', []):
            process_counts[proc] = 1 # Just tracking existence for now
            
        baseline = {
            'period': baseline_window,
            'login_count_avg': hist_auth.get('total', 0) / 30,  # Avg per day
            'failed_login_ratio': hist_auth.get('failed', 0) / max(hist_auth.get('total', 1), 1),
            'typical_source_ips': hist_auth.get('source_ips', [])[:20],
            'file_modification_avg': hist_fim.get('total', 0) / 30,
            'network_destinations_avg': hist_network.get('unique_destinations', 0) / 30,
            'hourly_activity': hour_counts,
            'known_processes': list(process_counts.keys())
        }
        
        return baseline
    
    def _detect_anomalies(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies by comparing current activity to baseline"""
        anomalies = []
        baseline = result.get('baseline', {})
        
        # Anomaly 1: Unusual login failures
        current_failed = result['authentication_activity'].get('failed', 0)
        baseline_failed_ratio = baseline.get('failed_login_ratio', 0)
        current_total = result['authentication_activity'].get('total', 1)
        current_failed_ratio = current_failed / max(current_total, 1)
        
        if current_failed_ratio > baseline_failed_ratio * 3 and current_failed > 5:
            anomalies.append({
                'type': 'unusual_failed_logins',
                'severity': 'high',
                'description': f"Failed login ratio ({current_failed_ratio:.2%}) is 3x higher than baseline ({baseline_failed_ratio:.2%})",
                'count': current_failed
            })
        
        # Anomaly 2: Excessive file modifications
        current_fim = result['file_modifications'].get('total', 0)
        baseline_fim = baseline.get('file_modification_avg', 0)
        
        if current_fim > baseline_fim * 5 and current_fim > 20:
            anomalies.append({
                'type': 'excessive_file_modifications',
                'severity': 'medium',
                'description': f"File modifications ({current_fim}) significantly higher than baseline ({baseline_fim:.1f})",
                'count': current_fim
            })
        
        # Anomaly 3: New/unusual network destinations
        current_dests = set(result['network_activity'].get('destination_ips', []))
        baseline_dests = set(baseline.get('typical_source_ips', []))
        new_destinations = current_dests - baseline_dests
        
        if len(new_destinations) > 10:
            anomalies.append({
                'type': 'unusual_network_destinations',
                'severity': 'medium',
                'description': f"{len(new_destinations)} new network destinations not seen in baseline",
                'count': len(new_destinations)
            })
        
        # Anomaly 4: Off-hours Activity
        hourly_baseline = baseline.get('hourly_activity', {})
        current_sessions = result['authentication_activity'].get('sessions', [])
        for session in current_sessions:
            try:
                dt = datetime.fromisoformat(session['timestamp'].replace('Z', '+00:00'))
                hour = dt.hour
                # If hour has < 5% of total historical activity (or 0 if no history), flag it
                total_hist = sum(hourly_baseline.values())
                if total_hist > 10: # Only if we have enough history
                    hour_count = hourly_baseline.get(hour, 0)
                    if hour_count / total_hist < 0.05:
                        anomalies.append({
                            'type': 'off_hours_activity',
                            'severity': 'medium',
                            'description': f"Activity during unusual hour ({hour}:00)",
                            'count': 1
                        })
                        break # Flag once per investigation
            except:
                pass

        # Anomaly 5: Rare Process Execution
        known_processes = set(baseline.get('known_processes', []))
        current_processes = result['process_execution'].get('processes', [])
        new_processes = [p for p in current_processes if p not in known_processes]
        
        if new_processes and len(known_processes) > 5: # Only if we have a baseline
            anomalies.append({
                'type': 'rare_process_execution',
                'severity': 'high',
                'description': f"Execution of {len(new_processes)} rare/new processes: {', '.join(new_processes[:3])}",
                'count': len(new_processes)
            })

        return anomalies
    
    def _calculate_comprehensive_risk(self, result: Dict[str, Any]) -> int:
        """Calculate comprehensive risk score"""
        score = 0
        
        # Failed logins
        failed = result['authentication_activity'].get('failed', 0)
        if failed > 10:
            points = min(failed * 3, 40)
            score += points
            result['risk_factors'].append({
                'type': 'failed_logins',
                'points': points,
                'description': f"{failed} failed login attempts"
            })
        
        # Malware detections
        malware = result['malware_events'].get('critical_count', 0)
        if malware > 0:
            points = 50
            score += points
            result['risk_factors'].append({
                'type': 'malware',
                'points': points,
                'description': f"{malware} critical malware detection(s)"
            })
        
        # Anomalies
        anomalies = len(result.get('anomalies', []))
        if anomalies > 0:
            points = anomalies * 15
            score += points
            result['risk_factors'].append({
                'type': 'anomalies',
                'points': points,
                'description': f"{anomalies} behavioral anomaly(ies) detected"
            })
        
        # Compliance violations
        compliance_total = result['compliance_violations'].get('total', 0)
        if compliance_total > 5:
            points = 20
            score += points
            result['risk_factors'].append({
                'type': 'compliance',
                'points': points,
                'description': f"{compliance_total} compliance violation(s)"
            })
        
        return min(score, 100)
    
    def _calculate_insider_threat(self, result: Dict[str, Any]) -> int:
        """Calculate insider threat specific score"""
        score = 0
        
        # Excessive file modifications (data exfiltration indicator)
        if result['file_modifications'].get('total', 0) > 50:
            score += 30
        
        # Anomalies (behavioral changes)
        score += len(result.get('anomalies', [])) * 20
        
        # New network destinations (potential data exfiltration)
        new_dests = 0
        for anomaly in result.get('anomalies', []):
            if anomaly.get('type') == 'unusual_network_destinations':
                new_dests = anomaly.get('count', 0)
        if new_dests > 5:
            score += 25
        
        # Failed logins (reconnaissance)
        if result['authentication_activity'].get('failed', 0) > 20:
            score += 15
        
        return min(score, 100)
    
    def _generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # High failed logins
        if result['authentication_activity'].get('failed', 0) > 10:
            recommendations.append(
                f"URGENT: Investigate {result['authentication_activity']['failed']} failed login attempts"
            )
        
        # Malware
        if result['malware_events'].get('critical_count', 0) > 0:
            recommendations.append(
                "CRITICAL: Malware detected - isolate system and perform forensics"
            )
        
        # Anomalies
        for anomaly in result.get('anomalies', []):
            if anomaly.get('severity') == 'high':
                recommendations.append(f"HIGH: {anomaly.get('description')}")
        
        # Insider threat
        if result.get('insider_threat_score', 0) > 60:
            recommendations.append(
                "WARNING: High insider threat score - review all user activity and access logs"
            )
        
        if not recommendations:
            recommendations.append("Continue normal monitoring")
        
        return recommendations
    
    def _parse_time_range(self, time_range: str) -> timedelta:
        """Parse time range string to timedelta"""
        unit = time_range[-1]
        value = int(time_range[:-1])
        
        if unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        else:
            logger.warning(f"Invalid time range: {time_range}, defaulting to 24h")
            return timedelta(hours=24)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level"""
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

