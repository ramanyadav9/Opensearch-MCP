"""MCP Server for Sentinel-AI SIEM

Main server file that registers all tools and handles MCP protocol communication.
"""

import logging
import asyncio
import argparse
from typing import Dict, Any
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("ERROR: MCP package not installed. Please run: pip install mcp")
    exit(1)

from .config import load_config
from .opensearch_client import SentinelOpenSearchClient
from .tools.search import AdvancedSIEMSearchTool
from .tools.agent import AgentLogsTool
from .tools.alerts import MajorAlertsTool
from .tools.indices import ListIndicesTool, IndexMappingTool
from .tools.network import NetworkAnalyticsTool, ConnectionDetailsTool
from .tools.mitre import MITREAttackTool
from .tools.threat_hunt import ThreatHuntingTool
from .tools.investigate_ip import InvestigateIPTool
from .tools.investigate_user import InvestigateUserTool
from .tools.get_log_by_id import GetLogsByTimestampTool
from .tools.advanced_analytics import AdvancedAnalyticsTool
from .tools.category import (
    FIMEventsTool, SCAEventsTool, SessionEventsTool, MalwareEventsTool,
    AIAnnotatedLogsTool, MLAnomaliesTool, VulnerabilitiesTool
)
from .tools.compliance import (
    HIPAAEventsTool, GDPREventsTool, NISTEventsTool, 
    PCIDSSEventsTool, TSCEventsTool
)
from .tools.uba_summary import UBASummaryTool

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SentinelMCPServer:
    """Sentinel-AI MCP Server"""
    
    def __init__(self, config_path: str):
        """Initialize server
        
        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        
        # Update logging level
        logging.getLogger().setLevel(self.config.logging.level)
        
        # Initialize OpenSearch client
        logger.info("Connecting to OpenSearch...")
        self.os_client = SentinelOpenSearchClient(
            self.config.opensearch.model_dump()
        )
        
        # Initialize MCP server
        self.server = Server("sentinel-ai-mcp")
        
        # Initialize tools
        self.tools = self._initialize_tools()
        
        # Register handlers
        self._register_handlers()
        
        logger.info(f"Initialized {len(self.tools)} tools")
    
    def _initialize_tools(self) -> Dict[str, Any]:
        """Initialize all MCP tools
        
        Returns:
            Dictionary of tool instances
        """
        tools_config = self.config.tools.model_dump()
        enabled_tools = self.config.tools.enabled
        
        all_tools = {
            'AdvancedSIEMSearchTool': AdvancedSIEMSearchTool(self.os_client, tools_config),
            'AgentLogsTool': AgentLogsTool(self.os_client, tools_config),
            'MajorAlertsTool': MajorAlertsTool(self.os_client, tools_config),
            'ListIndicesTool': ListIndicesTool(self.os_client, tools_config),
            'IndexMappingTool': IndexMappingTool(self.os_client, tools_config),
            'NetworkAnalyticsTool': NetworkAnalyticsTool(self.os_client, tools_config),
            'ConnectionDetailsTool': ConnectionDetailsTool(self.os_client, tools_config),
            'AdvancedAnalyticsTool': AdvancedAnalyticsTool(self.os_client, tools_config),
            'FIMEventsTool': FIMEventsTool(self.os_client, tools_config),
            'SCAEventsTool': SCAEventsTool(self.os_client, tools_config),
            'SessionEventsTool': SessionEventsTool(self.os_client, tools_config),
            'MalwareEventsTool': MalwareEventsTool(self.os_client, tools_config),
            'AIAnnotatedLogsTool': AIAnnotatedLogsTool(self.os_client, tools_config),
            'MLAnomaliesTool': MLAnomaliesTool(self.os_client, tools_config),
            'VulnerabilitiesTool': VulnerabilitiesTool(self.os_client, tools_config),
            'HIPAAEventsTool': HIPAAEventsTool(self.os_client, tools_config),
            'GDPREventsTool': GDPREventsTool(self.os_client, tools_config),
            'NISTEventsTool': NISTEventsTool(self.os_client, tools_config),
            'PCIDSSEventsTool': PCIDSSEventsTool(self.os_client, tools_config),
            'TSCEventsTool': TSCEventsTool(self.os_client, tools_config),
            'MITREAttackTool': MITREAttackTool(self.os_client, tools_config),
            'ThreatHuntingTool': ThreatHuntingTool(self.os_client, tools_config),
            'InvestigateIPTool': InvestigateIPTool(self.os_client, tools_config),
            'InvestigateUserTool': InvestigateUserTool(self.os_client, tools_config),
            'GetLogsByTimestampTool': GetLogsByTimestampTool(self.os_client, tools_config),
            'UBASummaryTool': UBASummaryTool(self.os_client, tools_config),
        }
        
        # Filter to enabled tools only
        if enabled_tools:
            tools = {
                k: v for k, v in all_tools.items()
                if k in enabled_tools or v.name() in [et.replace('Tool', '').lower() for et in enabled_tools]
            }
        else:
            tools = all_tools
        
        return tools
    
    def _register_handlers(self):
        """Register MCP protocol handlers"""
        
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available tools"""
            tool_list = []
            for tool in self.tools.values():
                tool_list.append(Tool(
                    name=tool.name(),
                    description=tool.description(),
                    inputSchema={
                        "type": "object",
                        "properties": self._get_tool_schema(tool),
                        "required": []
                    }
                ))
            return tool_list
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            """Execute a tool
            
            Args:
                name: Tool name
                arguments: Tool arguments
                
            Returns:
                Tool execution result
            """
            logger.info(f"Calling tool: {name} with args: {arguments}")
            
            # Find tool
            tool_instance = None
            for tool in self.tools.values():
                if tool.name() == name:
                    tool_instance = tool
                    break
            
            if not tool_instance:
                error_msg = f"Tool not found: {name}"
                logger.error(error_msg)
                return [TextContent(
                    type="text",
                    text=f"Error: {error_msg}"
                )]
            
            try:
                # Execute tool
                result = await tool_instance.execute(**arguments)
                
                # Format result as JSON text
                import json
                result_text = json.dumps(result, indent=2, default=str)
                
                return [TextContent(
                    type="text",
                    text=result_text
                )]
                
            except Exception as e:
                error_msg = f"Tool execution error: {str(e)}"
                logger.error(error_msg, exc_info=True)
                return [TextContent(
                    type="text",
                    text=f"Error: {error_msg}"
                )]
    
    def _get_tool_schema(self, tool) -> Dict[str, Any]:
        """Get JSON schema for tool parameters
        
        Args:
            tool: Tool instance
            
        Returns:
            Parameter schema
        """
        # Default schemas for common parameters
        common_schemas = {
            "query": {
                "type": "string",
                "description": "Search query (supports DQL like field:value)"
            },
            "agent_name": {
                "type": "string",
                "description": "Agent name (e.g., 'SOC_GPU_SRV', 'MDM-189')"
            },
            "time_range": {
                "type": "string",
                "description": "Time range: 15m, 1h, 4h, 12h, 24h, 3d, 7d, 15d, 30d, 90d, or custom:start:end",
                "default": "24h"
            },
            "page": {
                "type": "integer",
                "description": "Page number (1-indexed)",
                "default": 1
            },
            "size": {
                "type": "integer",
                "description": "Results per page",
                "default": 100
            },
            "search": {
                "type": "string",
                "description": "Optional search filter"
            },
            "sort_by": {
                "type": "string",
                "description": "Field to sort by",
                "default": "@timestamp"
            },
            "sort_order": {
                "type": "string",
                "description": "Sort order",
                "enum": ["asc", "desc"],
                "default": "desc"
            },
            "log_type": {
                "type": "string",
                "description": "Log type filter",
                "enum": ["all", "firewall", "ids", "windows", "linux"],
                "default": "all"
            },
            "rule_level": {
                "type": "string",
                "description": "Minimum rule level (all or number)",
                "default": "all"
            },
            "min_level": {
                "type": "integer",
                "description": "Minimum rule level for alerts",
                "default": 12
            },
            "index": {
                "type": "string",
                "description": "Index name or pattern",
                "default": "logs-*"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum results",
                "default": 100
            },
            "src_ip": {
                "type": "string",
                "description": "Source IP address"
            },
            "dest_ip": {
                "type": "string",
                "description": "Destination IP address"
            },
            "tactic": {
                "type": "string",
                "description": "MITRE tactic (e.g., 'Initial Access')"
            },
            "technique": {
                "type": "string",
                "description": "MITRE technique"
            },
            "id": {
                "type": "string",
                "description": "MITRE technique ID (e.g., 'T1110')"
            },
            "hunt_type": {
                "type": "string",
                "description": "Type of hunt (all, brute_force, lateral_movement, persistence, exfiltration)",
                "default": "all"
            }
        }
        
        # Map tool types to their schemas
        tool_name = tool.name()
        
        if tool_name == "search_logs":
            return {
                "query": common_schemas["query"],
                "time_range": common_schemas["time_range"],
                "page": common_schemas["page"],
                "size": common_schemas["size"],
                "sort_by": common_schemas["sort_by"],
                "sort_order": common_schemas["sort_order"],
                "log_type": common_schemas["log_type"],
                "rule_level": common_schemas["rule_level"]
            }
        elif tool_name == "get_agent_logs":
            return {
                "agent_name": common_schemas["agent_name"],
                "time_range": common_schemas["time_range"],
                "page": common_schemas["page"],
                "size": common_schemas["size"],
                "search": common_schemas["search"],
                "sort_order": common_schemas["sort_order"]
            }
        elif tool_name == "get_major_alerts":
            return {
                "time_range": common_schemas["time_range"],
                "page": common_schemas["page"],
                "size": common_schemas["size"],
                "search": common_schemas["search"],
                "sort_by": common_schemas["sort_by"],
                "sort_order": common_schemas["sort_order"],
                "min_level": common_schemas["min_level"]
            }
        elif tool_name == "list_indices":
            return {}
        elif tool_name == "get_index_mapping":
            return {
                "index": common_schemas["index"]
            }
        elif tool_name == "get_network_flows":
            return {
                "time_range": common_schemas["time_range"],
                "limit": common_schemas["limit"],
                "src_ip": common_schemas["src_ip"],
                "dest_ip": common_schemas["dest_ip"]
            }
        elif tool_name == "get_connection_details":
            return {
                "time_range": common_schemas["time_range"],
                "page": common_schemas["page"],
                "size": common_schemas["size"],
                "src_ip": common_schemas["src_ip"],
                "dest_ip": common_schemas["dest_ip"],
                "country": {
                    "type": "string",
                    "description": "Country code (e.g. US, CN)"
                },
                "connection_type": {
                    "type": "string",
                    "description": "Connection type: all, incoming, outgoing",
                    "enum": ["all", "incoming", "outgoing"],
                    "default": "all"
                }
            }
        elif tool_name == "advanced_analytics_summary":
            return {
                "time_range": common_schemas["time_range"]
            }
        elif tool_name in ["get_fim_events", "get_sca_events", "get_session_events", 
                          "get_malware_events", "get_ai_annotated_logs", "get_ml_anomalies"]:
            return {
                "time_range": common_schemas["time_range"],
                "page": common_schemas["page"],
                "size": common_schemas["size"]
            }
        elif tool_name == "get_vulnerabilities":
            return {
                "time_range": common_schemas["time_range"],
                "page": common_schemas["page"],
                "size": common_schemas["size"],
                "min_score": {
                    "type": "number",
                    "description": "Minimum vulnerability score (0-10)",
                    "default": 0.0
                }
            }
        elif tool_name in ["get_hipaa_events", "get_gdpr_events", "get_nist_events", 
                          "get_pci_dss_events", "get_tsc_events"]:
            return {
                "time_range": common_schemas["time_range"],
                "page": common_schemas["page"],
                "size": common_schemas["size"]
            }
        elif tool_name == "get_mitre_attacks":
            return {
                "time_range": common_schemas["time_range"],
                "tactic": common_schemas["tactic"],
                "technique": common_schemas["technique"],
                "id": common_schemas["id"],
                "min_level": common_schemas["min_level"],
                "limit": common_schemas["limit"]
            }
        elif tool_name == "threat_hunt":
            return {
                "hunt_type": common_schemas["hunt_type"],
                "time_range": common_schemas["time_range"],
                "limit": common_schemas["limit"]
            }
        elif tool_name == "investigate_ip":
            return {
                "ip": {
                    "type": "string",
                    "description": "IP address to investigate (IPv4 or IPv6)"
                },
                "time_range": {
                    "type": "string",
                    "description": "Correlation time window: 1h, 6h, 12h, 24h, 3d, 7d",
                    "default": "12h"
                },
                "include_graph": {
                    "type": "boolean",
                    "description": "Include entity relationship graph in response",
                    "default": True
                }
            }
        elif tool_name == "investigate_user":
            return {
                "username": {
                    "type": "string",
                    "description": "Username or agent name to investigate (user==agent)"
                },
                "time_range": {
                    "type": "string",
                    "description": "Current activity window: 1h, 6h, 12h, 24h, 3d, 7d",
                    "default": "24h"
                },
                "baseline_window": {
                    "type": "string",
                    "description": "Historical baseline window: 7d, 14d, 30d, 60d, 90d",
                    "default": "30d"
                }
            }
        elif tool_name == "get_log_by_id":
            return {
                "id": {
                    "type": "string",
                    "description": "Log document ID"
                }
            }
        elif tool_name == "get_logs_by_timestamp":
            return {
                "timestamp": {
                    "type": "string",
                    "description": "ISO format timestamp (e.g., 2024-12-08T14:30:00)"
                },
                "window_minutes": {
                    "type": "integer",
                    "description": "Minutes before and after timestamp to include",
                    "default": 5
                },
                "size": common_schemas["size"],
                "agent_name": {
                    "type": "string",
                    "description": "Optional filter by agent name"
                }
            }
        elif tool_name == "uba_summary":
            return {
                "time_range": common_schemas["time_range"],
                "limit": common_schemas["limit"]
            }
        
        return {}
    
    async def run(self):
        """Run the MCP server"""
        logger.info("Starting Sentinel-AI MCP Server...")
        
        # Validate OpenSearch connection
        if not await self.os_client.validate_connection():
            logger.error("Failed to connect to OpenSearch")
            return
        
        # Run server with stdio transport
        async with stdio_server() as (read_stream, write_stream):
            logger.info("MCP Server running with stdio transport")
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Sentinel-AI MCP Server')
    parser.add_argument(
        '--config',
        type=str,
        required=True,
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    # Check if config exists
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: Configuration file not found: {args.config}")
        print("Please create a config.yaml file. See config.yaml.example for template.")
        exit(1)
    
    try:
        # Create and run server
        server = SentinelMCPServer(args.config)
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        exit(1)


if __name__ == "__main__":
    main()
