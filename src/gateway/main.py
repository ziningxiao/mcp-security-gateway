"""
MCP Security Gateway Main Application
"""
import asyncio
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Optional

from .security_pipeline import SecurityPipeline
from .models import MCPRequest, SecurityDecision

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MCP Security Gateway",
    description="Real-time threat detection for MCP requests",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize security pipeline
security_pipeline = SecurityPipeline()

@app.on_event("startup")
async def startup_event():
    """Initialize models and connections on startup"""
    await security_pipeline.initialize()
    logger.info("MCP Security Gateway started successfully")

@app.post("/analyze", response_model=SecurityDecision)
async def analyze_request(request: MCPRequest) -> SecurityDecision:
    """
    Analyze MCP request for security threats
    
    Returns decision: ALLOW, BLOCK, or CONFIRM
    """
    try:
        decision = await security_pipeline.analyze(request)
        return decision
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Analysis failed")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "0.1.0"}

@app.get("/metrics")
async def get_metrics():
    """Get performance metrics"""
    return await security_pipeline.get_metrics()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
