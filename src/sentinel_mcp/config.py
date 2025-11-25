"""Configuration management for Sentinel-AI MCP Server"""

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class OpenSearchConfig(BaseModel):
    """OpenSearch connection configuration"""
    hosts: str
    username: str
    password: str
    verify_certs: bool = False
    use_ssl: bool = False
    timeout: int = 30


class SecurityConfig(BaseModel):
    """Security configuration"""
    field_level_security: Dict[str, List[str]] = Field(default_factory=dict)


class ToolLimits(BaseModel):
    """Tool execution limits"""
    max_page_size: int = 1000
    default_page_size: int = 100
    max_flow_limit: int = 5000
    search_timeout: int = 30


class ToolsConfig(BaseModel):
    """Tools configuration"""
    limits: ToolLimits = Field(default_factory=ToolLimits)
    enabled: List[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    """Main configuration"""
    opensearch: OpenSearchConfig
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def load_config(config_path: str) -> Config:
    """Load configuration from YAML file
    
    Args:
        config_path: Path to config.yaml file
        
    Returns:
        Parsed configuration object
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(path, 'r') as f:
        config_dict = yaml.safe_load(f)
    
    return Config(**config_dict)
