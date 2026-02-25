import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import base64
import os

# ==========================================
# 1. CYBERGUARD CLOUD SETTINGS
# ==========================================
VT_API_KEY = "c452705659e4e8ef8fe35e85c8d08ee5dc1e94ed2e23b3734c950eb8e16019f2"

app = FastAPI(title="CyberGuard Cloud API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # ලෝකේ ඕනෙම තැනකින් එන Mobile App එකකට කතා කරන්න දෙනවා
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 2. ENDPOINTS (URL Scan, Chat)
# ==========================================
class URLRequest(BaseModel):
    url: str

class AgentRequest(BaseModel):
    user_message: str

@app.post("/scan_url")
async def scan_url_endpoint(request: URLRequest):
    url_id = base64.urlsafe_b64encode(request.url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            if stats['malicious'] > 0:
                return {"status": "blocked", "message": f"🛑 CLOUD ALERT: MALICIOUS URL BLOCKED!"}
            return {"status": "clean", "message": f"✅ URL is safe."}
        else:
            return {"status": "error", "message": "API Error or URL not found."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/chat")
async def chat_with_agent(request: AgentRequest):
    # දැනට Cloud එකේ Ollama නැති නිසා, අපි තාවකාලික AI පිළිතුරක් දෙනවා.
    return {"status": "success", "agent_reply": "CyberGuard Cloud AI Online: System is operating optimally from the cloud server. (Note: Advanced AI needs an external API key setup)."}

@app.get("/")
async def root():
    return {"message": "CyberGuard Cloud Engine is Running!"}

# ==========================================
# 3. SERVER STARTUP (Cloud Port Configuration)
# ==========================================
if __name__ == "__main__":
    # Cloud එකෙන් දෙන Port එක ගන්නවා, නැත්නම් 10000 පාවිච්චි කරනවා
    port = int(os.environ.get("PORT", 10000))
    print(f"CyberGuard Cloud Engine Initializing on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)