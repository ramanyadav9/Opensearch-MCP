"""Time range parsing utilities"""

from datetime import datetime, timedelta
from typing import Tuple, Dict, Any
import re


class TimeRangeParser:
    """Parse time range strings into OpenSearch range filters"""
    
    @staticmethod
    def parse(time_range: str) -> Dict[str, Any]:
        """Parse time range string into OpenSearch range filter
        
        Supported formats:
        - Relative: 15m, 1h, 4h, 12h, 24h, 3d, 7d, 15d, 30d, 90d
        - Custom: custom:2025-11-20T00:00:00Z:2025-11-23T23:59:59Z
        
        Args:
            time_range: Time range string
            
        Returns:
            OpenSearch range filter for @timestamp field
        """
        now = datetime.utcnow()
        
        # Handle custom time range
        if time_range.startswith('custom:'):
            parts = time_range.split(':')
            if len(parts) == 3:
                try:
                    start_date = datetime.fromisoformat(parts[1].replace('Z', '+00:00'))
                    end_date = datetime.fromisoformat(parts[2].replace('Z', '+00:00'))
                    return {
                        'range': {
                            '@timestamp': {
                                'gte': start_date.isoformat() + 'Z',
                                'lte': end_date.isoformat() + 'Z'
                            }
                        }
                    }
                except (ValueError, IndexError) as e:
                    # Fall back to default if parsing fails
                    time_range = '24h'
        
        # Handle relative time ranges
        time_deltas = {
            '15m': timedelta(minutes=15),
            '1h': timedelta(hours=1),
            '4h': timedelta(hours=4),
            '12h': timedelta(hours=12),
            '24h': timedelta(hours=24),
            '3d': timedelta(days=3),
            '7d': timedelta(days=7),
            '15d': timedelta(days=15),
            '30d': timedelta(days=30),
            '90d': timedelta(days=90),
        }
        
        delta = time_deltas.get(time_range, timedelta(hours=24))
        start_date = now - delta
        
        return {
            'range': {
                '@timestamp': {
                    'gte': start_date.isoformat() + 'Z',
                    'lte': now.isoformat() + 'Z'
                }
            }
        }
    
    @staticmethod
    def calculate_time_diff_hours(time_range: str) -> int:
        """Calculate time difference in hours from time range string
        
        Args:
            time_range: Time range string
            
        Returns:
            Time difference in hours
        """
        time_map = {
            '15m': 0.25,
            '1h': 1,
            '4h': 4,
            '12h': 12,
            '24h': 24,
            '3d': 72,
            '7d': 168,
            '15d': 360,
            '30d': 720,
            '90d': 2160,
        }
        
        return time_map.get(time_range, 24)
