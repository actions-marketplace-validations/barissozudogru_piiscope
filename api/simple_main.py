"""Simplified FastAPI application for testing database integrations."""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Set environment variables
os.environ["DATABASE_URL"] = "sqlite:///./data_security_checker.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/0" 
os.environ["JWT_SECRET_KEY"] = "your-super-secret-jwt-key-here-minimum-32-characters-long"
os.environ["ENCRYPTION_KEY"] = "cGFzc3dvcmQxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ="

app = FastAPI(
    title="Data Security Checker API",
    version="1.0.0",
    description="API for managing database connections and privacy risk detection"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Data Security Checker API is running!", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected"}

# Mock data source endpoints
@app.get("/api/data-sources")
async def get_data_sources():
    return {
        "data_sources": [
            {
                "id": 1,
                "name": "Production MySQL",
                "description": "Main production database",
                "source_type": "mysql",
                "status": "active",
                "created_at": "2024-01-10T09:00:00Z"
            },
            {
                "id": 2,
                "name": "BigQuery Analytics", 
                "description": "Data warehouse for analytics",
                "source_type": "gcp_bigquery",
                "status": "error",
                "test_error": "Invalid credentials",
                "created_at": "2024-01-12T14:30:00Z"
            }
        ]
    }

@app.post("/api/data-sources")
async def create_data_source(data_source: dict):
    return {
        "id": 3,
        "name": data_source.get("name", "New Data Source"),
        "description": data_source.get("description", ""),
        "source_type": data_source.get("source_type", "mysql"),
        "status": "inactive",
        "created_at": "2024-09-06T16:15:00Z"
    }

@app.post("/api/data-sources/{source_id}/test")
async def test_connection(source_id: int):
    return {
        "success": True,
        "message": "Connection test successful",
        "details": {"latency": "45ms", "version": "8.0.33"}
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)