"""OpenSearch client wrapper for Sentinel-AI MCP Server"""

import logging
from typing import Dict, List, Any, Optional
from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import OpenSearchException

logger = logging.getLogger(__name__)


class SentinelOpenSearchClient:
    """Wrapper for OpenSearch client with SIEM-specific functionality"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize OpenSearch client
        
        Args:
            config: OpenSearch configuration dict
        """
        self.config = config
        self.client = self._create_client()
        self.index_pattern = "logs-*"
        
    def _create_client(self) -> OpenSearch:
        """Create and configure OpenSearch client
        
        Returns:
            Configured OpenSearch client
        """
        # Parse hosts
        hosts = self.config.get('hosts', 'http://localhost:9200')
        if isinstance(hosts, str):
            hosts = [hosts]
        
        # Build client configuration
        client_config = {
            'hosts': hosts,
            'http_auth': (
                self.config.get('username', 'admin'),
                self.config.get('password', 'admin')
            ),
            'use_ssl': self.config.get('use_ssl', False),
            'verify_certs': self.config.get('verify_certs', False),
            'ssl_show_warn': False,
            'connection_class': RequestsHttpConnection,
            'timeout': self.config.get('timeout', 30),
        }
        
        try:
            client = OpenSearch(**client_config)
            # Test connection
            client.info()
            logger.info("Successfully connected to OpenSearch")
            return client
        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            raise
    
    async def discover_indices(self, pattern: str = None) -> List[str]:
        """Discover available indices matching pattern
        
        Args:
            pattern: Index pattern (default: logs-*)
            
        Returns:
            List of index names
        """
        if pattern is None:
            pattern = self.index_pattern
            
        try:
            response = self.client.cat.indices(
                index=pattern,
                format='json',
                h='index'
            )
            indices = [idx['index'] for idx in response]
            logger.debug(f"Discovered {len(indices)} indices matching {pattern}")
            return indices
        except OpenSearchException as e:
            logger.error(f"Error discovering indices: {e}")
            return []
    
    async def search(self, 
                    index: str, 
                    body: Dict[str, Any],
                    size: int = 100,
                    from_: int = 0,
                    sort: Optional[List[Dict]] = None,
                    _source: Optional[Dict] = None) -> Dict[str, Any]:
        """Execute search query
        
        Args:
            index: Index or index pattern to search
            body: Query body
            size: Number of results
            from_: Starting offset
            sort: Sort criteria
            _source: Source filtering
            
        Returns:
            Search response
        """
        try:
            search_params = {
                'index': index,
                'body': body,
                'size': size,
                'from_': from_
            }
            
            if sort:
                search_params['sort'] = sort
            if _source:
                search_params['_source'] = _source
            
            response = self.client.search(**search_params)
            return response
        except OpenSearchException as e:
            logger.error(f"Search error: {e}")
            raise
    
    async def count(self, index: str, body: Dict[str, Any]) -> int:
        """Count documents matching query
        
        Args:
            index: Index or index pattern
            body: Query body
            
        Returns:
            Document count
        """
        try:
            response = self.client.count(index=index, body=body)
            return response['count']
        except OpenSearchException as e:
            logger.error(f"Count error: {e}")
            return 0
    
    async def get_mapping(self, index: str) -> Dict[str, Any]:
        """Get index mapping
        
        Args:
            index: Index name
            
        Returns:
            Index mapping
        """
        try:
            response = self.client.indices.get_mapping(index=index)
            return response
        except OpenSearchException as e:
            logger.error(f"Get mapping error: {e}")
            return {}
    
    async def validate_connection(self) -> bool:
        """Validate OpenSearch connection
        
        Returns:
            True if connection is valid
        """
        try:
            info = self.client.info()
            logger.info(f"Connected to OpenSearch {info['version']['number']}")
            return True
        except Exception as e:
            logger.error(f"Connection validation failed: {e}")
            return False
    
    def close(self):
        """Close OpenSearch connection"""
        try:
            self.client.close()
            logger.info("OpenSearch connection closed")
        except Exception as e:
            logger.error(f"Error closing connection: {e}")
