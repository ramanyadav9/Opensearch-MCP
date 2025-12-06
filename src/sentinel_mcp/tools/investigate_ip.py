"""IP Investigation Tool

Provides comprehensive IP address investigation with correlation analysis.
"""

import logging
from typing import Dict, Any
from datetime import timedelta

from .base import BaseTool
from ..correlation.engine import CorrelationEngine

logger = logging.getLogger(__name__)


class InvestigateIPTool(BaseTool):
    """Investigate IP address with full correlation analysis"""
    
    def __init__(self, client, config: Dict[str, Any]):
        """Initialize tool
        
        Args:
            client: OpenSearch client
            config: Tool configuration
        """
        super().__init__(client, config)
        self.correlation_engine = CorrelationEngine(client)
    
    def name(self) -> str:
        """Tool name"""
        return "investigate_ip"
    
    def description(self) -> str:
        """Tool description"""
        return (
            "Comprehensive IP address investigation with correlation analysis. "
            "Correlates alerts, network flows, authentication sessions, file modifications, "
            "and UEBA data. Builds entity relationship graph and calculates risk score. "
            "Provides verdict and actionable recommendations."
        )
    
    async def execute(
        self,
        ip: str,
        time_range: str = "12h",
        include_graph: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute IP investigation
        
        Args:
            ip: IP address to investigate
            time_range: Time range for correlation (default: 12h)
                       Supported: 1h, 6h, 12h, 24h, 3d, 7d
            include_graph: Include entity relationship graph (default: True)
            
        Returns:
            Comprehensive investigation report
        """
        logger.info(f"Investigating IP: {ip} with time_range={time_range}")
        
        # Parse time range to timedelta
        time_window = self._parse_time_range(time_range)
        
        # Run correlation
        result = await self.correlation_engine.correlate_by_ip(ip, time_window)
        
        # Convert to dict
        report = result.model_dump(mode='json')
        
        # Optionally exclude graph for smaller response
        if not include_graph:
            report.pop('entity_graph', None)
        
        # Add metadata
        report['metadata'] = {
            'tool': self.name(),
            'ip_address': ip,
            'time_range': time_range,
            'query_count': result.query_count,
            'correlation_timestamp': result.correlation_timestamp.isoformat()
        }
        
        logger.info(
            f"IP investigation complete: {result.total_events} events, "
            f"risk={result.risk_score} ({result.risk_level}), "
            f"verdict={result.verdict}"
        )
        
        return report
    
    def _parse_time_range(self, time_range: str) -> timedelta:
        """Parse time range string to timedelta
        
        Args:
            time_range: Time range string (e.g., '12h', '3d')
            
        Returns:
            timedelta object
        """
        unit = time_range[-1]
        value = int(time_range[:-1])
        
        if unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        else:
            # Default to 12 hours
            logger.warning(f"Invalid time range: {time_range}, defaulting to 12h")
            return timedelta(hours=12)
