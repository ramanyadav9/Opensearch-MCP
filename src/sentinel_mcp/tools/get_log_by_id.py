"""Tool for retrieving logs by timestamp"""

import logging
from typing import Dict, Any
from datetime import datetime, timedelta
from .base import BaseTool

logger = logging.getLogger(__name__)


class GetLogsByTimestampTool(BaseTool):
    """Retrieve logs around a specific timestamp"""
    
    def name(self) -> str:
        return "get_logs_by_timestamp"
    
    def description(self) -> str:
        return (
            "Get logs around a SPECIFIC TIMESTAMP. Use for: 'Show me logs from 10:45 AM', "
            "'What happened at 2024-12-08T14:30:00?'. Provide timestamp (ISO format) and "
            "optional window_minutes (default ±5 min). Returns logs in that time window."
        )
    
    async def execute(self, 
                     timestamp: str,
                     window_minutes: int = 5,
                     size: int = 100,
                     agent_name: str = None) -> Dict[str, Any]:
        """Get logs around a timestamp
        
        Args:
            timestamp: ISO format timestamp (e.g., "2024-12-08T14:30:00")
            window_minutes: Minutes before and after timestamp to include
            size: Maximum number of logs to return
            agent_name: Optional filter by agent name
            
        Returns:
            Logs within the time window
        """
        try:
            # Parse timestamp
            try:
                center_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                # Try common formats
                for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                    try:
                        center_time = datetime.strptime(timestamp, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return {'error': f'Invalid timestamp format: {timestamp}. Use ISO format like 2024-12-08T14:30:00'}
            
            # Calculate window
            start_time = center_time - timedelta(minutes=window_minutes)
            end_time = center_time + timedelta(minutes=window_minutes)
            
            # Build query
            query_body = {
                'bool': {
                    'must': [
                        {
                            'range': {
                                '@timestamp': {
                                    'gte': start_time.isoformat(),
                                    'lte': end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            }
            
            # Add agent filter if provided
            if agent_name:
                query_body['bool']['must'].append({'term': {'agent.name': agent_name}})
            
            # Add false positive filter
            query_body = self.add_false_positive_filter(query_body)
            
            # Cap size
            size = self.cap_page_size(size)
            
            # Get indices
            indices = await self.discover_indices()
            if not indices:
                return {
                    'logs': [],
                    'query_info': {
                        'timestamp': timestamp,
                        'window': f'±{window_minutes} minutes',
                        'start': start_time.isoformat(),
                        'end': end_time.isoformat()
                    }
                }
            
            # Search
            response = await self.client.search(
                index=','.join(indices),
                body={
                    'query': query_body,
                    'sort': [{'@timestamp': {'order': 'asc'}}],
                    '_source': {
                        'excludes': ['raw_log.command', 'raw_log.script']
                    }
                },
                size=size
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
                'total': total,
                'returned': len(logs),
                'query_info': {
                    'center_timestamp': timestamp,
                    'window': f'±{window_minutes} minutes',
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'agent_filter': agent_name
                }
            }
            
        except Exception as e:
            logger.error(f"Error retrieving logs by timestamp: {e}")
            return {
                'error': str(e),
                'timestamp': timestamp
            }
