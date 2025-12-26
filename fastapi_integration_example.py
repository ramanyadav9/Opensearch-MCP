
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os

# 1. Import Sentinel MCP Client and Tools
# Ensure 'sentinel_mcp' is installed or in your PYTHONPATH
from sentinel_mcp.opensearch_client import SentinelOpenSearchClient
from sentinel_mcp.tools.investigate_user import InvestigateUserTool
from sentinel_mcp.correlation.engine import CorrelationEngine
from sentinel_mcp.tools.search import AdvancedSIEMSearchTool

app = FastAPI(title="Sentinel AI Service", description="AI-powered SIEM Backend")

# 2. Configuration (Load from env vars in production)
OPENSEARCH_CONFIG = {
    "hosts": [os.getenv("OPENSEARCH_HOST", "http://192.168.1.12:9200")],
    "username": os.getenv("OPENSEARCH_USER", "admin"),
    "password": os.getenv("OPENSEARCH_PASS", "admin"),
    "verify_certs": False
}

# 3. Global Client Singleton
# Initialize once on startup to maintain connection pool
os_client = SentinelOpenSearchClient(OPENSEARCH_CONFIG)

# 4. Request Models
class AnalyzeRequest(BaseModel):
    query: str
    context: Optional[Dict[str, Any]] = {}

class InvestigationResponse(BaseModel):
    verdict: str
    risk_score: int
    summary: str
    details: Dict[str, Any]

# 5. Dependency Injection for Tools
def get_user_tool():
    return InvestigateUserTool(os_client, {})

def get_correlation_engine():
    return CorrelationEngine(os_client)

def get_search_tool():
    return AdvancedSIEMSearchTool(os_client, {})

# --- Routes ---

@app.on_event("startup")
async def startup_event():
    print("✅ Sentinel AI Service Starting...")
    if not await os_client.validate_connection():
        print("❌ WARNING: Could not connect to OpenSearch!")

@app.post("/api/investigate/user")
async def investigate_user_endpoint(
    username: str, 
    time_range: str = "24h",
    tool: InvestigateUserTool = Depends(get_user_tool)
):
    """
    Endpoint for specific UEBA investigation
    """
    try:
        report = await tool.execute(
            username=username,
            time_range=time_range,
            baseline_window="30d"
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/investigate/ip")
async def investigate_ip_endpoint(
    ip: str, 
    time_range: str = "12h",
    engine: CorrelationEngine = Depends(get_correlation_engine)
):
    """
    Endpoint for IP Correlation
    """
    try:
        # Convert string time range to timedelta if needed, or update Engine to accept strings
        # For this example, we assume the engine helper handles it or we parse it here
        from datetime import timedelta
        # Simple parser for demo
        hours = int(time_range.replace('h', ''))
        
        result = await engine.correlate_by_ip(ip, timedelta(hours=hours))
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/chat")
async def chat_endpoint(
    request: AnalyzeRequest,
    search_tool: AdvancedSIEMSearchTool = Depends(get_search_tool)
):
    """
    Your AI Chat Endpoint - Combining LLM with MCP Tools
    """
    user_query = request.query
    
    # Step 1: Tool Selection Logic (Mocking your LLM logic)
    # in reality: tools = [search_tool.description(), ...]
    # llm_response = llm.decide_tool(user_query, tools)
    
    context_data = {}
    
    # Simple keyword detection for demo
    if "search" in user_query.lower() or "log" in user_query.lower():
        print(f"🤖 AI executing tool: search_logs for '{user_query}'")
        context_data = await search_tool.execute(query=user_query, time_range="24h")
        
    # Step 2: Feed Tool Output back to LLM
    # final_response = llm.generate_response(user_query, context=context_data)
    
    # Mock response
    final_response = f"Based on the analysis of {len(context_data.get('hits', []))} logs, here is what I found..."
    
    return {
        "response": final_response,
        "tool_data": context_data
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
