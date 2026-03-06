"""Real FastAPI application with actual database connections and privacy scanning."""
import os
import json
import re
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import base64

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.fernet import Fernet

# Database imports
from google.cloud import bigquery
from google.oauth2 import service_account
import pymysql
import psycopg2
from sqlalchemy import create_engine, text
import pandas as pd

_SAFE_IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_$]*$')


def _validate_table_name(name: str) -> None:
    """Raise ValueError if *name* is not a safe SQL identifier.

    Only ASCII letters, digits, underscores and dollar signs are permitted,
    and the name must start with a letter or underscore.  This prevents SQL
    injection when the identifier is interpolated into a query string.
    """
    if not _SAFE_IDENTIFIER_RE.match(name):
        raise ValueError(f"Invalid table name: {name!r}")


# All configuration is read from environment variables.
# DATABASE_URL falls back to a local SQLite path for development convenience;
# the remaining secrets must be set explicitly before starting the process.
_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data_security_checker.db")
_REDIS_URL = os.getenv("REDIS_URL") or ""
_JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or ""
_ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if _ENCRYPTION_KEY:
    cipher_suite = Fernet(_ENCRYPTION_KEY.encode() if isinstance(_ENCRYPTION_KEY, str) else _ENCRYPTION_KEY)
else:
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)

app = FastAPI(
    title="Data Security Checker API",
    version="2.0.0",
    description="API for managing real database connections and privacy risk detection"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (replace with real database in production)
data_sources = {}
scan_results = {}
risk_findings = {}

# Privacy detection patterns
PRIVACY_PATTERNS = {
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
    'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    'date_of_birth': re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b'),
}

SENSITIVE_COLUMN_NAMES = [
    'email', 'phone', 'ssn', 'social_security', 'credit_card', 'password', 
    'dob', 'birth_date', 'address', 'first_name', 'last_name', 'name',
    'user_id', 'customer_id', 'account_number', 'passport', 'driver_license'
]

# Models
class DataSourceCreate(BaseModel):
    name: str
    description: str
    source_type: str
    connection_config: Dict[str, Any]

class DataSourceResponse(BaseModel):
    id: str
    name: str
    description: str
    source_type: str
    status: str
    created_at: str
    last_tested_at: Optional[str] = None
    test_error: Optional[str] = None
    tables_count: Optional[int] = None

class ConnectionTestResult(BaseModel):
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None

class ScanRequest(BaseModel):
    data_source_id: str
    table_name: Optional[str] = None
    query: Optional[str] = None

class RiskFinding(BaseModel):
    id: str
    scan_id: str
    table_name: str
    column_name: str
    risk_type: str
    severity: str
    confidence: float
    sample_value: str
    record_count: int
    description: str

# Database connection classes
class DatabaseConnector:
    @staticmethod
    async def test_bigquery_connection(config: Dict[str, Any]) -> ConnectionTestResult:
        try:
            credentials_info = config.get('credentials')
            if isinstance(credentials_info, str):
                credentials_info = json.loads(credentials_info)
            
            credentials = service_account.Credentials.from_service_account_info(credentials_info)
            client = bigquery.Client(
                project=config['project_id'],
                credentials=credentials
            )
            
            # Test query
            query = "SELECT 1 as test_connection"
            query_job = client.query(query)
            results = list(query_job.result())
            
            # Count tables
            datasets = list(client.list_datasets())
            table_count = sum(len(list(client.list_tables(dataset.dataset_id))) for dataset in datasets)
            
            return ConnectionTestResult(
                success=True,
                message="BigQuery connection successful",
                details={
                    "project_id": config['project_id'],
                    "datasets": len(datasets),
                    "tables": table_count
                }
            )
        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"BigQuery connection failed: {str(e)}"
            )
    
    @staticmethod
    async def test_mysql_connection(config: Dict[str, Any]) -> ConnectionTestResult:
        try:
            connection = pymysql.connect(
                host=config['host'],
                port=int(config.get('port', 3306)),
                user=config['username'],
                password=config['password'],
                database=config.get('database', ''),
                connect_timeout=10
            )
            
            with connection.cursor() as cursor:
                cursor.execute("SELECT VERSION()")
                version = cursor.fetchone()[0]
                
                # Count tables
                cursor.execute("SHOW TABLES")
                table_count = len(cursor.fetchall())
            
            connection.close()
            
            return ConnectionTestResult(
                success=True,
                message="MySQL connection successful",
                details={
                    "host": config['host'],
                    "database": config.get('database'),
                    "version": version,
                    "tables": table_count
                }
            )
        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"MySQL connection failed: {str(e)}"
            )
    
    @staticmethod
    async def test_postgresql_connection(config: Dict[str, Any]) -> ConnectionTestResult:
        try:
            connection = psycopg2.connect(
                host=config['host'],
                port=int(config.get('port', 5432)),
                user=config['username'],
                password=config['password'],
                database=config.get('database', ''),
                connect_timeout=10
            )
            
            with connection.cursor() as cursor:
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]
                
                # Count tables
                cursor.execute("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """)
                table_count = cursor.fetchone()[0]
            
            connection.close()
            
            return ConnectionTestResult(
                success=True,
                message="PostgreSQL connection successful",
                details={
                    "host": config['host'],
                    "database": config.get('database'),
                    "version": version.split(',')[0],
                    "tables": table_count
                }
            )
        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"PostgreSQL connection failed: {str(e)}"
            )

class PrivacyScanner:
    @staticmethod
    def scan_dataframe(df: pd.DataFrame, table_name: str) -> List[Dict[str, Any]]:
        findings = []
        
        for column in df.columns:
            column_lower = column.lower()
            sample_values = df[column].astype(str).head(100).tolist()
            
            # Check column name for sensitive patterns
            for sensitive_name in SENSITIVE_COLUMN_NAMES:
                if sensitive_name in column_lower:
                    findings.append({
                        'table_name': table_name,
                        'column_name': column,
                        'risk_type': f'sensitive_column_name_{sensitive_name}',
                        'severity': 'HIGH',
                        'confidence': 0.9,
                        'sample_value': str(sample_values[0]) if sample_values else '',
                        'record_count': len(df),
                        'description': f'Column name "{column}" suggests sensitive data ({sensitive_name})'
                    })
            
            # Check data patterns
            for pattern_name, pattern in PRIVACY_PATTERNS.items():
                matches = []
                for value in sample_values[:20]:  # Check first 20 values
                    if pattern.search(str(value)):
                        matches.append(value)
                
                if matches:
                    confidence = min(0.95, len(matches) / 20)
                    findings.append({
                        'table_name': table_name,
                        'column_name': column,
                        'risk_type': f'data_pattern_{pattern_name}',
                        'severity': 'HIGH' if confidence > 0.7 else 'MEDIUM',
                        'confidence': confidence,
                        'sample_value': str(matches[0]),
                        'record_count': len(df),
                        'description': f'Column "{column}" contains {pattern_name} patterns'
                    })
        
        return findings

# API Endpoints
@app.get("/")
async def root():
    return {"message": "Real Data Security Checker API is running!", "version": "2.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "connections": len(data_sources)}

@app.post("/api/data-sources", response_model=DataSourceResponse)
async def create_data_source(data_source: DataSourceCreate):
    # Encrypt connection config
    encrypted_config = cipher_suite.encrypt(json.dumps(data_source.connection_config).encode())
    
    source_id = f"ds_{len(data_sources) + 1}_{int(datetime.now().timestamp())}"
    
    data_sources[source_id] = {
        "id": source_id,
        "name": data_source.name,
        "description": data_source.description,
        "source_type": data_source.source_type,
        "connection_config": encrypted_config,
        "status": "inactive",
        "created_at": datetime.now().isoformat(),
        "last_tested_at": None,
        "test_error": None,
        "tables_count": 0
    }
    
    return DataSourceResponse(**data_sources[source_id])

@app.get("/api/data-sources", response_model=List[DataSourceResponse])
async def get_data_sources():
    return [DataSourceResponse(**ds) for ds in data_sources.values()]

@app.post("/api/data-sources/{source_id}/test", response_model=ConnectionTestResult)
async def test_connection(source_id: str):
    if source_id not in data_sources:
        raise HTTPException(status_code=404, detail="Data source not found")
    
    source = data_sources[source_id]
    
    # Decrypt connection config
    decrypted_config = json.loads(cipher_suite.decrypt(source["connection_config"]).decode())
    
    # Update status to testing
    data_sources[source_id]["status"] = "testing"
    data_sources[source_id]["last_tested_at"] = datetime.now().isoformat()
    
    try:
        if source["source_type"] == "gcp_bigquery":
            result = await DatabaseConnector.test_bigquery_connection(decrypted_config)
        elif source["source_type"] == "mysql":
            result = await DatabaseConnector.test_mysql_connection(decrypted_config)
        elif source["source_type"] == "postgresql":
            result = await DatabaseConnector.test_postgresql_connection(decrypted_config)
        else:
            result = ConnectionTestResult(
                success=False,
                message=f"Connection testing not implemented for {source['source_type']}"
            )
        
        # Update source status
        if result.success:
            data_sources[source_id]["status"] = "active"
            data_sources[source_id]["test_error"] = None
            if result.details and "tables" in result.details:
                data_sources[source_id]["tables_count"] = result.details["tables"]
        else:
            data_sources[source_id]["status"] = "error"
            data_sources[source_id]["test_error"] = result.message
        
        return result
        
    except Exception as e:
        data_sources[source_id]["status"] = "error"
        data_sources[source_id]["test_error"] = str(e)
        
        return ConnectionTestResult(
            success=False,
            message=f"Connection test failed: {str(e)}"
        )

@app.get("/api/data-sources/{source_id}/tables")
async def list_tables(source_id: str):
    if source_id not in data_sources:
        raise HTTPException(status_code=404, detail="Data source not found")
    
    source = data_sources[source_id]
    if source["status"] != "active":
        raise HTTPException(status_code=400, detail="Data source is not active")
    
    # Decrypt connection config
    decrypted_config = json.loads(cipher_suite.decrypt(source["connection_config"]).decode())
    
    try:
        if source["source_type"] == "mysql":
            connection = pymysql.connect(**{
                'host': decrypted_config['host'],
                'port': int(decrypted_config.get('port', 3306)),
                'user': decrypted_config['username'],
                'password': decrypted_config['password'],
                'database': decrypted_config.get('database', ''),
            })
            with connection.cursor() as cursor:
                cursor.execute("SHOW TABLES")
                tables = [row[0] for row in cursor.fetchall()]
            connection.close()
            
        elif source["source_type"] == "postgresql":
            connection = psycopg2.connect(
                host=decrypted_config['host'],
                port=int(decrypted_config.get('port', 5432)),
                user=decrypted_config['username'],
                password=decrypted_config['password'],
                database=decrypted_config.get('database', ''),
            )
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT table_name FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """)
                tables = [row[0] for row in cursor.fetchall()]
            connection.close()
            
        else:
            tables = ["Table listing not implemented for this database type"]
        
        return {"tables": tables}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list tables: {str(e)}")

@app.post("/api/scan")
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    if scan_request.data_source_id not in data_sources:
        raise HTTPException(status_code=404, detail="Data source not found")
    
    scan_id = f"scan_{int(datetime.now().timestamp())}"
    
    # Add background task for scanning
    background_tasks.add_task(perform_scan, scan_id, scan_request)
    
    return {"scan_id": scan_id, "status": "started", "message": "Privacy scan initiated"}

async def perform_scan(scan_id: str, scan_request: ScanRequest):
    """Perform actual privacy scanning on the database."""
    try:
        source = data_sources[scan_request.data_source_id]
        decrypted_config = json.loads(cipher_suite.decrypt(source["connection_config"]).decode())
        
        findings = []
        
        if source["source_type"] == "mysql":
            connection = pymysql.connect(**{
                'host': decrypted_config['host'],
                'port': int(decrypted_config.get('port', 3306)),
                'user': decrypted_config['username'],
                'password': decrypted_config['password'],
                'database': decrypted_config.get('database', ''),
            })
            
            if scan_request.table_name:
                # Validate table name against an allowlist of safe identifier characters
                # to prevent SQL injection via table name interpolation.
                _validate_table_name(scan_request.table_name)
                df = pd.read_sql(
                    f"SELECT * FROM `{scan_request.table_name}` LIMIT 1000",  # noqa: S608
                    connection,
                )
                findings.extend(PrivacyScanner.scan_dataframe(df, scan_request.table_name))
            else:
                # Scan all tables
                with connection.cursor() as cursor:
                    cursor.execute("SHOW TABLES")
                    tables = [row[0] for row in cursor.fetchall()]

                for table in tables[:5]:  # Limit to first 5 tables for demo
                    try:
                        _validate_table_name(table)
                        df = pd.read_sql(
                            f"SELECT * FROM `{table}` LIMIT 100",  # noqa: S608
                            connection,
                        )
                        findings.extend(PrivacyScanner.scan_dataframe(df, table))
                    except Exception as e:
                        print(f"Error scanning table {table}: {e}")
                        continue
            
            connection.close()
        
        # Store results
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "data_source_id": scan_request.data_source_id,
            "status": "completed",
            "started_at": datetime.now().isoformat(),
            "completed_at": datetime.now().isoformat(),
            "findings_count": len(findings),
            "high_risk_count": len([f for f in findings if f['severity'] == 'HIGH']),
            "medium_risk_count": len([f for f in findings if f['severity'] == 'MEDIUM']),
        }
        
        # Store individual findings
        for i, finding in enumerate(findings):
            finding_id = f"{scan_id}_finding_{i}"
            finding['id'] = finding_id
            finding['scan_id'] = scan_id
            risk_findings[finding_id] = finding
        
    except Exception as e:
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "data_source_id": scan_request.data_source_id,
            "status": "failed",
            "error": str(e),
            "started_at": datetime.now().isoformat(),
            "completed_at": datetime.now().isoformat(),
        }

@app.get("/api/scans/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

@app.get("/api/scans")
async def list_scans():
    return list(scan_results.values())

@app.get("/api/findings")
async def get_risk_findings(scan_id: Optional[str] = None):
    if scan_id:
        findings = [f for f in risk_findings.values() if f['scan_id'] == scan_id]
    else:
        findings = list(risk_findings.values())
    
    return {"findings": findings, "total": len(findings)}

@app.get("/api/findings/{finding_id}")
async def get_finding_details(finding_id: str):
    if finding_id not in risk_findings:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return risk_findings[finding_id]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)