"""Validation utilities for IPs, protocols, and data"""

import ipaddress
import re
from typing import Optional


class IPValidator:
    """IP address validation utilities"""
    
    # Invalid IP patterns to filter out
    INVALID_IPS = {
        '0.0.0.0',
        '255.255.255.255',
        '127.0.0.1',
    }
    
    @staticmethod
    def is_valid_ip(ip_str: Optional[str]) -> bool:
        """Validate if IP address is valid and not in exclusion list
        
        Args:
            ip_str: IP address string
            
        Returns:
            True if valid and not excluded
        """
        if not ip_str or ip_str == '-' or ip_str == 'unknown':
            return False
        
        # Check if in invalid list
        if ip_str in IPValidator.INVALID_IPS:
            return False
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Filter out loopback
            if ip.is_loopback:
                return False
            
            # Filter out multicast
            if ip.is_multicast:
                return False
            
            # Filter out reserved
            if ip.is_reserved:
                return False
            
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is private
        
        Args:
            ip_str: IP address string
            
        Returns:
            True if private IP
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False


class ProtocolNormalizer:
    """Protocol normalization utilities"""
    
    # Protocol number to name mapping
    PROTOCOL_MAP = {
        '6': 'tcp',
        '17': 'udp',
        '1': 'icmp',
        '58': 'icmpv6',
        '47': 'gre',
        '50': 'esp',
        '51': 'ah',
        '89': 'ospf',
        '88': 'eigrp',
        '132': 'sctp',
        '4': 'ipip',
        '41': 'ipv6',
        '2': 'igmp',
        '103': 'pim',
        '112': 'vrrp',
    }
    
    @staticmethod
    def normalize(protocol: Optional[str]) -> str:
        """Normalize protocol to standard name
        
        Args:
            protocol: Protocol number or name
            
        Returns:
            Normalized protocol name
        """
        if not protocol:
            return 'unknown'
        
        protocol_str = str(protocol).strip().lower()
        
        # If it's a number, map it
        if protocol_str.isdigit():
            return ProtocolNormalizer.PROTOCOL_MAP.get(protocol_str, protocol_str)
        
        # Return as-is if already a name
        return protocol_str


class DQLDetector:
    """Domain Query Language detection"""
    
    # Pattern for field:value queries
    DQL_PATTERN = re.compile(r'\w+[\.\w]*\s*:\s*\S+')
    
    @staticmethod
    def is_dql_query(query: str) -> bool:
        """Detect if query uses DQL syntax (field:value)
        
        Args:
            query: Search query string
            
        Returns:
            True if DQL query detected
        """
        if not query or not query.strip():
            return False
        
        # Check for field:value pattern and no spaces (single term)
        has_pattern = bool(DQLDetector.DQL_PATTERN.search(query))
        has_spaces = ' ' in query.strip()
        
        return has_pattern and not has_spaces
