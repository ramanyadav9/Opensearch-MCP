"""Data models for correlation results"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class Entity(BaseModel):
    """Represents an entity in the correlation graph"""
    id: str
    type: str  # ip, user, host, domain, alert, process, file
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_count: int = 0


class Relationship(BaseModel):
    """Represents a relationship between entities"""
    source: str  # Entity ID
    target: str  # Entity ID
    type: str  # login-from, connects-to, triggered, executed, contacted, modified
    weight: int = 1
    timestamp: Optional[datetime] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class EntityGraph(BaseModel):
    """Graph representation of correlated entities"""
    nodes: List[Entity] = Field(default_factory=list)
    edges: List[Relationship] = Field(default_factory=list)
    
    def add_node(self, entity: Entity) -> None:
        """Add a node to the graph"""
        # Check if node already exists
        for node in self.nodes:
            if node.id == entity.id:
                # Update event count
                node.event_count += entity.event_count
                if entity.last_seen and (not node.last_seen or entity.last_seen > node.last_seen):
                    node.last_seen = entity.last_seen
                if entity.first_seen and (not node.first_seen or entity.first_seen < node.first_seen):
                    node.first_seen = entity.first_seen
                return
        self.nodes.append(entity)
    
    def add_edge(self, relationship: Relationship) -> None:
        """Add an edge to the graph"""
        # Check if similar edge exists
        for edge in self.edges:
            if (edge.source == relationship.source and 
                edge.target == relationship.target and 
                edge.type == relationship.type):
                # Update weight
                edge.weight += relationship.weight
                return
        self.edges.append(relationship)


class CorrelationResult(BaseModel):
    """Complete correlation analysis result"""
    entity_type: str  # ip, user, host, alert
    entity_value: str
    time_window: str
    
    # Summary statistics
    total_events: int = 0
    critical_alerts: int = 0
    affected_agents: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    affected_ips: List[str] = Field(default_factory=list)
    
    # Detailed data
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    network_flows: List[Dict[str, Any]] = Field(default_factory=list)
    auth_sessions: List[Dict[str, Any]] = Field(default_factory=list)
    fim_events: List[Dict[str, Any]] = Field(default_factory=list)
    processes: List[Dict[str, Any]] = Field(default_factory=list)
    
    # UEBA data
    ueba_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    baseline_data: Optional[Dict[str, Any]] = None
    
    # MITRE mapping
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    
    # Entity graph
    entity_graph: EntityGraph = Field(default_factory=EntityGraph)
    
    # Risk assessment
    risk_score: int = 0
    risk_level: str = "Informational"  # Informational, Low, Medium, High, Critical
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Recommendations
    verdict: str = "Unknown"  # Clean, Suspicious, Malicious, Unknown
    recommendations: List[str] = Field(default_factory=list)
    
    # Timeline
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metadata
    correlation_timestamp: datetime = Field(default_factory=datetime.utcnow)
    query_count: int = 0
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
