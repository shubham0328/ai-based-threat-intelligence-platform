from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List
from datetime import datetime, timedelta
import re

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory DB
threat_log_db = []

IP_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

class ThreatData(BaseModel):
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    threat_type: str = Field(..., description="Type of threat")
    severity: int = Field(..., ge=1, le=10, description="Severity from 1 (low) to 10 (critical)")
    timestamp: datetime = Field(..., description="Timestamp in ISO format")

    @validator('source_ip')
    def validate_source_ip(cls, v):
        if not IP_REGEX.match(v):
            raise ValueError("Invalid source IP format")
        return v

    @validator('destination_ip')
    def validate_destination_ip(cls, v):
        if not IP_REGEX.match(v):
            raise ValueError("Invalid destination IP format")
        return v

    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v > datetime.utcnow() + timedelta(minutes=5):
            raise ValueError("Timestamp cannot be in the future")
        return v

def ip_in_blacklist(ip: str) -> bool:
    blacklisted_ips = {"192.168.1.100", "10.0.0.66"}
    return ip in blacklisted_ips

@app.post("/analyze-threat/")
async def analyze_threat(data: ThreatData):
    time_diff = datetime.utcnow() - data.timestamp
    source_blacklisted = ip_in_blacklist(data.source_ip)

    if data.severity >= 9 or source_blacklisted:
        alert = "Critical Threat Detected"
        recommendation = "Isolate node immediately and notify security team."
    elif 6 <= data.severity < 9:
        alert = "High Risk Threat"
        recommendation = "Monitor closely and prepare mitigation."
    elif 3 <= data.severity < 6:
        alert = "Medium Risk Threat"
        recommendation = "Log event and review regularly."
    else:
        alert = "Low Risk Threat"
        recommendation = "Monitor source for repeated suspicious activity."

    if time_diff > timedelta(days=7):
        recommendation += " (Note: Threat data is older than 7 days.)"

    threat_entry = {
        "source_ip": data.source_ip,
        "destination_ip": data.destination_ip,
        "threat_type": data.threat_type,
        "severity": data.severity,
        "timestamp": data.timestamp.isoformat(),
        "alert": alert,
        "recommendation": recommendation
    }
    threat_log_db.append(threat_entry)

    return {"alert": alert, "recommendation": recommendation}

@app.get("/threats/", response_model=List[dict])
async def get_threats():
    return threat_log_db

@app.get("/threats/{source_ip}", response_model=List[dict])
async def get_threats_by_source(source_ip: str):
    if not IP_REGEX.match(source_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    results = [t for t in threat_log_db if t["source_ip"] == source_ip]
    if not results:
        raise HTTPException(status_code=404, detail="No threats found for given source IP")
    return results

@app.get("/health")
async def health_check():
    return {"status": "running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)