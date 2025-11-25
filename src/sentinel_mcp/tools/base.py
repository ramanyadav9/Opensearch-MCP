"""Base class for MCP tools"""

import logging
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseTool(ABC):
    """Base class for all MCP tools"""
    
    def __init__(self, opensearch_client, config: Dict[str, Any]):
        """Initialize tool
        
        Args:
            opensearch_client: OpenSearch client instance
            config: Tool configuration
        """
        self.client = opensearch_client
        self.config = config
        self.index_pattern = "logs-*"
        
        # Get limits from config
        self.max_page_size = config.get('limits', {}).get('max_page_size', 1000)
        self.default_page_size = config.get('limits', {}).get('default_page_size', 100)
        self.search_timeout = config.get('limits', {}).get('search_timeout', 30)
        
    @abstractmethod
    def name(self) -> str:
        """Get tool name
        
        Returns:
            Tool name for MCP registration
        """
        pass
    
    @abstractmethod
    def description(self) -> str:
        """Get tool description
        
        Returns:
            Human-readable tool description
        """
        pass
    
    @abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute tool with given parameters
        
        Args:
            **kwargs: Tool-specific parameters
            
        Returns:
            Tool execution result
        """
        pass
    
    async def discover_indices(self) -> List[str]:
        """Discover available log indices
        
        Returns:
            List of log index names
        """
        return await self.client.discover_indices(self.index_pattern)
    
    def add_false_positive_filter(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Add false positive exclusion filter to query
        
        Args:
            query: OpenSearch query
            
        Returns:
            Query with false positive filter added
        """
        if 'bool' not in query:
            query['bool'] = {'must': []}
        if 'must' not in query['bool']:
            query['bool']['must'] = []
        
        # Add false positive filter
        query['bool']['must'].append({
            'bool': {
                'should': [
                    {'term': {'is_false_positive': False}},
                    {'bool': {'must_not': {'exists': {'field': 'is_false_positive'}}}}
                ],
                'minimum_should_match': 1
            }
        })
        
        return query
    
    def cap_page_size(self, size: int) -> int:
        """Cap page size to maximum allowed
        
        Args:
            size: Requested page size
            
        Returns:
            Capped page size
        """
        return min(size, self.max_page_size)
    
    def format_pagination(self, page: int, size: int, total: int) -> Dict[str, Any]:
        """Format pagination metadata
        
        Args:
            page: Current page number
            size: Page size
            total: Total results
            
        Returns:
            Pagination metadata
        """
        import math
        
        return {
            'page': page,
            'limit': size,
            'total': total,
            'pages': math.ceil(total / size) if size > 0 else 0
        }
