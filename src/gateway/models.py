"""
Data models for MCP Security Gateway
"""
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

class ThreatType(str, Enum):
    BENIGN = "benign"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"  
    AGENT_HIJACKING = "agent_hijacking"
    RESOURCE_DOS = "resource_dos"
    TOOL_ABUSE = "tool_abuse"
    CONTEXT_POISONING = "context_poisoning"

class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CONFIRM = "CONFIRM"

class MCPRequest(BaseModel):
    """MCP request for security analysis"""
    prompt: str = Field(..., description="User prompt text")
    tool_call: Optional[str] = Field(None, description="Tool call parameters")
    context: Optional[str] = Field(None, description="Request context")
    client_id: str = Field(..., description="Client identifier")
    timestamp: datetime = Field(default_factory=datetime.now)

class SecurityDecision(BaseModel):
    """Security decision response"""
    decision: DecisionType
    risk_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    threat_type: ThreatType
    trace_id: str
    explanation: Dict[str, Any]
    processing_time_ms: float

class RequestTrace(BaseModel):
    """Complete request trace for audit and explainability"""
    trace_id: str
    request: MCPRequest
    features: Dict[str, float]
    model_predictions: List[Dict]
    decision: SecurityDecision
    timestamp: datetime
    shap_values: Optional[Dict[str, float]] = None
