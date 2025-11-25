"""Index management tools"""

import logging
from typing import Dict, Any, List
from .base import BaseTool

logger = logging.getLogger(__name__)


class ListIndicesTool(BaseTool):
    """List available log indices"""
    
    def name(self) -> str:
        return "list_indices"
    
    def description(self) -> str:
        return "List all available log indices in the OpenSearch cluster with statistics."
    
    async def execute(self) -> Dict[str, Any]:
        """List log indices
        
        Returns:
            List of indices with metadata
        """
        try:
            # Get indices
            indices = await self.discover_indices()
            
            if not indices:
                return {
                    'indices': [],
                    'count': 0
                }
            
            # Get detailed info about each index
            try:
                response = self.client.client.cat.indices(
                    index=','.join(indices),
                    format='json',
                    h='index,docs.count,store.size,health,status'
                )
                
                indices_info = []
                for idx in response:
                    indices_info.append({
                        'name': idx['index'],
                        'doc_count': int(idx.get('docs.count', 0)),
                        'size': idx.get('store.size', '0b'),
                        'health': idx.get('health', 'unknown'),
                        'status': idx.get('status', 'unknown')
                    })
                
                # Sort by name (reverse for most recent first)
                indices_info.sort(key=lambda x: x['name'], reverse=True)
                
                return {
                    'indices': indices_info,
                    'count': len(indices_info),
                    'pattern': self.index_pattern
                }
                
            except Exception as e:
                logger.warning(f"Could not get detailed index info: {e}")
                # Fallback to simple list
                return {
                    'indices': [{'name': idx, 'doc_count': None} for idx in sorted(indices, reverse=True)],
                    'count': len(indices),
                    'pattern': self.index_pattern
                }
            
        except Exception as e:
            logger.error(f"List indices error: {e}")
            return{
                'error': str(e),
                'indices': [],
                'count': 0
            }


class IndexMappingTool(BaseTool):
    """Get field mappings for indices"""
    
    def name(self) -> str:
        return "get_index_mapping"
    
    def description(self) -> str:
        return (
            "Get field mappings and structure for log indices. "
            "Shows all available fields that can be queried."
        )
    
    async def execute(self, index: str = "logs-*") -> Dict[str, Any]:
        """Get index mapping
        
        Args:
            index: Index name or pattern (default: logs-*)
            
        Returns:
            Index mapping information
        """
        try:
            # Get mapping
            mapping = await self.client.get_mapping(index)
            
            if not mapping:
                return {
                    'error': 'No mapping found',
                    'index': index,
                    'fields': []
                }
            
            # Extract field names from mapping
            fields = []
            for idx_name, idx_data in mapping.items():
                if 'mappings' in idx_data:
                    mappings = idx_data['mappings']
                    if 'properties' in mappings:
                        fields.extend(self._extract_fields(mappings['properties']))
            
            # Remove duplicates and sort
            unique_fields = sorted(list(set(fields)))
            
            return {
                'index': index,
                'fields': unique_fields,
                'field_count': len(unique_fields),
                'raw_mapping': mapping if len(mapping) == 1 else None
            }
            
        except Exception as e:
            logger.error(f"Get mapping error: {e}")
            return {
                'error': str(e),
                'index': index,
                'fields': []
            }
    
    def _extract_fields(self, properties: Dict[str, Any], prefix: str = "") -> List[str]:
        """Recursively extract field names from mapping properties
        
        Args:
            properties: Mapping properties
            prefix: Field name prefix for nested fields
            
        Returns:
            List of field names
        """
        fields = []
        
        for field_name, field_props in properties.items():
            full_name = f"{prefix}.{field_name}" if prefix else field_name
            fields.append(full_name)
            
            # Check for nested properties
            if isinstance(field_props, dict):
                if 'properties' in field_props:
                    fields.extend(self._extract_fields(field_props['properties'], full_name))
                # Check for fields subfield (for text fields with keyword)
                if 'fields' in field_props:
                    for sub_field in field_props['fields'].keys():
                        fields.append(f"{full_name}.{sub_field}")
        
        return fields
