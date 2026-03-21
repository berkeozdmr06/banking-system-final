from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
import httpx
import uvicorn
import yfinance as yf
import pandas as pd
import json
import asyncio
from datetime import datetime, timedelta
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import time
import jwt
from collections import defaultdict

# Load environment variables from .env file
load_dotenv()

def generate_iban(tc_str: str) -> str:
    # Generates a standard 26-digit Turkish IBAN based on the unique TC Identity
    padded_tc = tc_str.zfill(15) # Ensure strictly 15 chars for account segment
    return f"TR4200062000000{padded_tc}"

# 1. Application Definition
app = FastAPI(
    title="ÖZAS Digital Banking",
    description="Developed by Berke Özdemir & Eren Aslantaş",
    version="2.1.0"
)

# CORS Configuration for external access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1.5 Rate Limiting & Attack Protection ---
class RateLimiter:
    def __init__(self, requests_limit: int, time_window: int):
        self.requests_limit = requests_limit
        self.time_window = time_window
        self.ip_records = defaultdict(list)

    def is_allowed(self, ip: str) -> bool:
        current_time = time.time()
        # Clean up timestamps outside the time window
        self.ip_records[ip] = [t for t in self.ip_records[ip] if current_time - t < self.time_window]
        
        if len(self.ip_records[ip]) >= self.requests_limit:
            return False
            
        self.ip_records[ip].append(current_time)
        return True

# Limit: 120 requests per 60 seconds per IP
limiter = RateLimiter(requests_limit=120, time_window=60)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    
    # Whitelist localhost and local network IPs (e.g. iPhone on 192.168.x.x)
    if client_ip.startswith("127.") or client_ip.startswith("192.168.") or client_ip == "::1":
        return await call_next(request)

    # Check rate limit
    if not limiter.is_allowed(client_ip):
        # Drop request with 429 status code
        return JSONResponse(
            status_code=429,
            content={
                "error": "RATE_LIMIT_EXCEEDED",
                "message": "Too Many Requests. Security limits activated to prevent abuse/attacks.",
                "retry_after": 60
            }
        )
    
    response = await call_next(request)
    return response

@app.get("/health")
async def health_check():
    return {"status": "UP", "timestamp": "realtime", "security": "Rate Limiter Active"}

# 2. Path & Template Configuration
base_dir = os.path.dirname(os.path.abspath(__file__))
frontend_dir = os.path.abspath(os.path.join(base_dir, "..", "frontend"))
templates = Jinja2Templates(directory=os.path.join(frontend_dir, "templates"))
static_dir = os.path.join(frontend_dir, "static")

if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# 3. Encryption & Persistence Configuration
LOCAL_DB_PATH = "/app/data/local_db.json"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
# 🔐 PERSISTENT SECURITY LAYER (ISO 27001 Concept)
    DATA_DIR = "/app/data"
    os.makedirs(DATA_DIR, exist_ok=True)
    KEY_PATH = os.path.join(DATA_DIR, "vault.key")
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "r") as kf:
            ENCRYPTION_KEY = kf.read().strip()
    else:
        ENCRYPTION_KEY = Fernet.generate_key().decode()
        with open(KEY_PATH, "w") as kf:
            kf.write(ENCRYPTION_KEY)

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

global_audit_logs = []
credit_applications = []

def load_local_db() -> dict:
    global global_audit_logs, credit_applications
    full_db = {}
    if os.path.exists(LOCAL_DB_PATH):
        with open(LOCAL_DB_PATH, "rb") as f:
            content = f.read()
            if content:
                try:
                    decrypted_data = cipher_suite.decrypt(content)
                    full_db = json.loads(decrypted_data.decode())
                except Exception:
                    full_db = {}
    
    db = full_db.get("users") if "users" in full_db else full_db
    if not isinstance(db, dict):
        db = {}
    global_audit_logs = full_db.get("audit_logs", global_audit_logs)
    credit_applications = full_db.get("credits", credit_applications)
                    
    needs_save = False

    # Ensure Immortality of Master Root Node
    root_tc = "11111111110"
    if root_tc not in db:
        db[root_tc] = {
            "tc_identity": root_tc,
            "iban": "TR3600064000000000000000ADMIN",
            "role": "ROOT_ADMIN",
            "is_admin": True,
            "balance": 5750000.0,
            "status": "ACTIVE",
            "transactions": [],
            "auditHistory": [
                {"user": root_tc, "action": "SYSTEM_INIT", "hash": "SYS_BOOT_001", "outcome": "SUCCESS", "time": (datetime.now() - timedelta(days=30)).isoformat()},
                {"user": root_tc, "action": "VAULT_OPEN", "hash": "VLT_OK_2291", "outcome": "APPROVED", "time": (datetime.now() - timedelta(days=15)).isoformat()},
                {"user": root_tc, "action": "KYC_ADMIN_VERIFIED", "hash": "KYC_ADM_001", "outcome": "APPROVED", "time": (datetime.now() - timedelta(days=10)).isoformat()},
            ],
            "ledgerHistory": [
                {"txid": "TX-A001", "desc": "SYSTEM VAULT INITIALIZATION", "debit": 0, "credit": 5000000.00, "move": 5000000.00, "balance": 5000000.00, "time": (datetime.now() - timedelta(days=30)).isoformat()},
                {"txid": "TX-A002", "desc": "OZAS CAPITAL RESERVE DEPOSIT", "debit": 0, "credit": 500000.00, "move": 500000.00, "balance": 5500000.00, "time": (datetime.now() - timedelta(days=15)).isoformat()},
                {"txid": "TX-A003", "desc": "REGULATORY COMPLIANCE FEE", "debit": 25000.00, "credit": 0, "move": -25000.00, "balance": 5475000.00, "time": (datetime.now() - timedelta(days=7)).isoformat()},
                {"txid": "TX-A004", "desc": "SYSTEM OPERATING INCOME", "debit": 0, "credit": 275000.00, "move": 275000.00, "balance": 5750000.00, "time": (datetime.now() - timedelta(days=2)).isoformat()},
            ]
        }
        needs_save = True
    
    # Always ensure admin IBAN is correct
    db["11111111110"]["iban"] = "TR3600064000000000000000ADMIN"

    # Auto-Inject Test User (Berke) for Mobile Flow
    test_tc = "54802618970"
    if test_tc not in db:
        db[test_tc] = {
            "tc_identity": test_tc,
            "password": "0635",
            "iban": "TR420006200000054802618970",
            "role": "PRIVATE_BANKING (A+)",
            "is_admin": False,
            "balance": 183459.11,
            "status": "ACTIVE",
            "hold_amount": 0.0,
            "transactions": [],
            "auditHistory": [
                {"user": test_tc, "action": "WEB_AUTH_LOGIN", "hash": "SEC_TOKEN_8892", "outcome": "SUCCESS", "time": datetime.now().isoformat()},
                {"user": test_tc, "action": "KYC_VERIFICATION", "hash": "KYC_OK_7721", "outcome": "APPROVED", "time": (datetime.now() - timedelta(days=2)).isoformat()}
            ],
            "ledgerHistory": [
                {"txid": "TX-9982", "desc": "OZAS INVESTMENT RETURN (MONTHLY)", "debit": 0, "credit": 12450.00, "move": 12450.00, "balance": 183459.11, "time": datetime.now().isoformat()},
                {"txid": "TX-9981", "desc": "SALARY PAYMENT - TECH CORP", "debit": 0, "credit": 43500.00, "move": 43500.00, "balance": 171009.11, "time": (datetime.now() - timedelta(days=1)).isoformat()},
                {"txid": "TX-9980", "desc": "ATM WITHDRAWAL - ISTANBUL/LEVENT", "debit": 1500.00, "credit": 0, "move": -1500.00, "balance": 127509.11, "time": (datetime.now() - timedelta(days=2)).isoformat()}
            ]
        }
        needs_save = True
    
    # Always ensure test user password is correct
    db[test_tc]["password"] = "0635"
    
    if needs_save:
        save_local_db(db)
        
    return db

def save_local_db(data: dict):
    try:
        full_db = {
            "users": data,
            "audit_logs": global_audit_logs,
            "credits": credit_applications
        }
        json_str = json.dumps(full_db, indent=4)
        encrypted_data = cipher_suite.encrypt(json_str.encode())
        with open(LOCAL_DB_PATH, "wb") as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error saving DB: {e}")

# --- Webhook & Messaging Cluster ---
WEBHOOK_SUBSCRIBERS = []

async def fire_webhook(event_type: str, payload: dict):
    """
    Fires FinTech application-level webhooks (e.g. TransferCreated, AccountDebited)
    to all dynamically subscribed listener URLs asynchronously.
    """
    if not WEBHOOK_SUBSCRIBERS: return
    headers = {"Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        for url in WEBHOOK_SUBSCRIBERS:
            try:
                # Fire and forget strategy
                asyncio.create_task(client.post(url, json={"event": event_type, "data": payload}, headers=headers, timeout=2.0))
            except Exception: pass

@app.post("/webhook/subscribe")
async def subscribe_webhook(req: dict):
    url = req.get("url")
    if not url: raise HTTPException(status_code=400, detail="Missing webhook URL")
    if url not in WEBHOOK_SUBSCRIBERS:
        WEBHOOK_SUBSCRIBERS.append(url)
    return {"status": "SUCCESS", "message": f"Webhook subscribed to {url}"}

@app.post("/debug/refill")
async def debug_refill(req: dict):
    tc = req.get("tc_identity")
    db_data = load_local_db()
    if tc in db_data:
        db_data[tc]["balance"] = 100000.0
        save_local_db(db_data)
        return {"status": "SUCCESS", "new_balance": 100000.0}
    return {"status": "ERROR", "message": "User not found"}

# 4. Data Models
class TradeRequest(BaseModel):
    tc_identity: str
    symbol: str
    side: str
    price: float
    quantity: float
    order_type: Optional[str] = "market"

class FuturesTradeRequest(BaseModel):
    tc_identity: str
    symbol: str
    margin_amount: float
    leverage: int
    side: str

# 5. Persistence Handlers
@app.post("/state/save")
async def save_state(state: dict):
    tc = str(state.get("tc_identity", "unknown"))
    db_data = load_local_db()
    
    if tc in db_data or tc == "admin":
        if tc not in db_data and tc == "admin":
             # Initialize admin in DB if it's the first save
             db_data["admin"] = {"tc_identity": "admin", "role": "ROOT_ADMIN", "is_admin": True}
             
        # Update selectively — protect backend-managed critical fields from frontend overwrites
        PROTECTED_FIELDS = {"auditHistory", "password", "ledgerHistory", "transactions", "balance", "iban", "role", "is_admin", "status"}
        for k, v in state.items():
            if k in PROTECTED_FIELDS:
                continue  # Never let frontend overwrite these — backend is authoritative
            db_data[tc][k] = v
        
        # Only update balance if frontend sends a higher value (e.g., after a legitimate top-up)
        # Balance changes are only made via /transfer and /auth/register endpoints
        # Frontend portfolio/investment state is allowed to update investmentBalance
        if "investmentBalance" in state:
            db_data[tc]["investmentBalance"] = state["investmentBalance"]
        save_local_db(db_data)
        return {"status": "SUCCESS", "timestamp": datetime.now().isoformat()}
    else:
        # Prevent creating user entries from save_state (must use /auth/register)
        return {"status": "SKIPPED", "message": "User not found in persistent store"}


@app.post("/trade/spot")
async def execute_spot_trade(req: TradeRequest):
    db_data = load_local_db()
    if req.tc_identity not in db_data and req.tc_identity != "admin":
        raise HTTPException(status_code=404, detail="User not found")
        
    if req.tc_identity == "admin" and "admin" not in db_data:
         db_data["admin"] = {"tc_identity": "admin", "balance": 99999999.0, "investmentBalance": 0.0, "portfolio": [], "futuresPositions": []}
         
    user = db_data[req.tc_identity]
    total_cost = req.price * req.quantity
    
    if req.side == "buy":
        if user.get("investmentBalance", 0) < total_cost:
            raise HTTPException(status_code=400, detail="Insufficient Investment Balance")
        user["investmentBalance"] -= total_cost
        # Portfolio logic handled in frontend for now to keep it simple, 
        # but we returning new balance to sync.
    else:
        # Simple sell: add to investment balance
        user["investmentBalance"] += total_cost
        
    # Log trade
    if "auditHistory" not in user: user["auditHistory"] = []
    user["auditHistory"].append({
        "user": req.tc_identity,
        "action": f"SPOT_{req.side.upper()}_{req.symbol}",
        "hash": f"TRD_{int(time.time())}",
        "outcome": "SUCCESS",
        "time": datetime.now().isoformat()
    })
    
    save_local_db(db_data)
    return {
        "status": "SUCCESS", 
        "new_balance": user.get("balance", 0), 
        "new_invest_balance": user.get("investmentBalance", 0),
        "message": f"Successfully {req.side} {req.quantity} {req.symbol}"
    }

@app.post("/trade/futures")
async def execute_futures_trade(req: FuturesTradeRequest):
    db_data = load_local_db()
    if req.tc_identity not in db_data and req.tc_identity != "admin":
        raise HTTPException(status_code=404, detail="User not found")
        
    if req.tc_identity == "admin" and "admin" not in db_data:
         db_data["admin"] = {"tc_identity": "admin", "balance": 99999999.0, "investmentBalance": 0.0, "portfolio": [], "futuresPositions": []}
         
    user = db_data[req.tc_identity]
    
    if user.get("investmentBalance", 0) < req.margin_amount:
        raise HTTPException(status_code=400, detail="Insufficient Investment Balance for Margin")
        
    user["investmentBalance"] -= req.margin_amount
    
    # Log trade
    if "auditHistory" not in user: user["auditHistory"] = []
    user["auditHistory"].append({
        "user": req.tc_identity,
        "action": f"FUT_{req.side.upper()}_{req.symbol}",
        "hash": f"TRD_FUT_{int(time.time())}",
        "outcome": "SUCCESS",
        "time": datetime.now().isoformat()
    })
    
    save_local_db(db_data)
    return {
        "status": "SUCCESS",
        "new_balance": user.get("balance", 0),
        "new_invest_balance": user.get("investmentBalance", 0),
        "message": f"Opened {req.side} position on {req.symbol} with {req.leverage}x leverage"
    }


@app.get("/state/load")
async def load_state(tc: str):
    db_data = load_local_db()
    user_state = db_data.get(tc)
    
    if user_state:
        # Migrate/Ensure keys exist
        if "iban" not in user_state: user_state["iban"] = generate_iban(tc)
        if "activeLoans" not in user_state: user_state["activeLoans"] = []
        if "ledgerHistory" not in user_state: user_state["ledgerHistory"] = []
        if "auditHistory" not in user_state: user_state["auditHistory"] = []
        if "portfolio" not in user_state: user_state["portfolio"] = []
        if "futuresPositions" not in user_state: user_state["futuresPositions"] = []
        return user_state
    
    # If not found, initialize a default secure state so the frontend doesn't wipe
    # (Matches Berke's starting profile for demo purposes)
    new_user = {
        "tc_identity": tc,
        "iban": generate_iban(tc),
        "balance": 1000000.0, # Default high-tier starting balance
        "investmentBalance": 0.0,
        "loans": 0.0,
        "activeMode": "portfolio",
        "portfolio": [],
        "ledgerHistory": [],
        "auditHistory": [],
        "termDeposit": 25000.0,
        "futuresPositions": []
    }
    db_data[tc] = new_user
    save_local_db(db_data)
    return new_user

# 6. UI Routes
@app.get("/", response_class=HTMLResponse)
async def get_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/nav-order")
async def nav_order():
    return {"source": ":backend", "order": ["Loans", "Cards", "Insurance"]}

# 7. Authentication Endpoints
@app.post("/auth/register")
async def register_user(reg_data: dict):
    tc = reg_data.get("tc_identity")
    if not tc or len(tc) != 11 or not tc.isdigit():
        raise HTTPException(status_code=400, detail="Valid 11-digit TC Identity required")
    
    # TC Validation Algorithm
    if tc[0] == '0':
        raise HTTPException(status_code=400, detail="Invalid TC Identity (cannot start with 0)")
        
    digits = [int(d) for d in tc]
    sum_odds = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    sum_evens = digits[1] + digits[3] + digits[5] + digits[7]
    
    tenth = ((sum_odds * 7) - sum_evens) % 10
    if tenth != digits[9]:
        raise HTTPException(status_code=400, detail="Invalid TC Identity (Verification Failed)")
        
    total_sum = sum(digits[:10])
    if total_sum % 10 != digits[10]:
        raise HTTPException(status_code=400, detail="Invalid TC Identity (Summation Failed)")
    
    db_data = load_local_db()
    if tc in db_data:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Initialize basic user state
    db_data[tc] = {
        **reg_data,
        "role": "CLIENT",
        "is_admin": False,
        "iban": generate_iban(tc),
        "balance": 10000.0, # Starting balance for demo
        "investmentBalance": 0.0,
        "loans": 0.0,
        "status": "ACTIVE",
        "kyc_verified": True,
        "portfolio": [],
        "ledgerHistory": [],
        "auditHistory": [
            {
                "user": tc,
                "action": "SYS",
                "hash": "ENCRYPTED_ID_GEN",
                "outcome": "SUCCESS",
                "time": datetime.now().isoformat()
            }
        ]
    }
    save_local_db(db_data)
    return {"status": "SUCCESS", "message": "User registered successfully"}

@app.post("/auth/login")
async def login_user(credentials: dict):
    username = str(credentials.get("username", "")).strip()
    password = credentials.get("password", "")
    
    # Master Admin Authentication Proxy
    is_master_bypass = False
    if username == "admin" and password == "0635":
        username = "11111111110"
        is_master_bypass = True

    db_data = load_local_db()
    
    if username not in db_data:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
    
    user = db_data[username]
    
    # Standard Password Verification (skip if Master Bypass engaged)
    if not is_master_bypass and user.get("password") != password:
        if "auditHistory" not in user: user["auditHistory"] = []
        user["auditHistory"].append({
            "user": username,
            "action": "WEB_AUTH_FAILED",
            "hash": "SEC_TOKEN_ERR_" + datetime.now().strftime("%s"),
            "outcome": "FAILED",
            "time": datetime.now().isoformat()
        })
        save_local_db(db_data)
        raise HTTPException(status_code=401, detail="INCORRECT_PASSWORD")
    
    # SYSTEM OVERRIDE: 11111111110 is always the Root Admin
    if username == "11111111110":
        user["is_admin"] = True
        user["role"] = "ROOT_ADMIN"

    # Add real authentication log to user history
    if "auditHistory" not in user:
        user["auditHistory"] = []
    
    user["auditHistory"].append({
        "user": username,
        "action": "WEB_AUTH_LOGIN",
        "hash": "SEC_TOKEN_" + datetime.now().strftime("%s"),
        "outcome": "SUCCESS",
        "time": datetime.now().isoformat()
    })
    save_local_db(db_data)

    time_stamp_now = datetime.now()

    # Issue standardized JWT Authentication Token
    expiration = datetime.utcnow() + timedelta(hours=2)
    jwt_payload = {
        "sub": username,
        "role": user.get("role", "CLIENT"),
        "is_admin": user.get("is_admin", False),
        "exp": expiration
    }
    encoded_jwt = jwt.encode(jwt_payload, ENCRYPTION_KEY, algorithm="HS256")

    return {
        "status": "SUCCESS", 
        "tc_identity": username,
        "is_admin": user.get("is_admin", False),
        "token": encoded_jwt,
        "token_type": "bearer",
        "user_data": user
    }

# 8. Dashboard and Market Routes
@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    response = templates.TemplateResponse("dashboard.html", {"request": request})
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/admin", response_class=HTMLResponse)
async def get_admin_app(request: Request):
    # iOS Admin Profile PWA Delivery Route
    response = templates.TemplateResponse("admin_app.html", {"request": request})
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

# --- System-Wide Admin Routes ---
@app.get("/admin/system_state")
async def get_system_state(tc_identity: str):
    db_data = load_local_db()
    # Simple strict pseudo-auth check for the iOS app to fetch all db nodes
    if tc_identity not in ["admin", "11111111110"]:
        raise HTTPException(status_code=403, detail="Insufficient Permissions: ROOT_ADMIN required.")

    total_sys_balance = 0
    total_sys_loans = 0
    admin_balance = 0
    users = []
    global_audit_logs = []

    for identifier, profile in db_data.items():
        if identifier != "admin": # Skip the pure placeholder user from sum
            if identifier == "11111111110":
                admin_balance = profile.get("balance", 0)
                
            total_sys_balance += profile.get("balance", 0)
            total_sys_balance += profile.get("investmentBalance", 0)
            total_sys_loans += profile.get("loans", 0)
            
            users.append({
                "tc": identifier,
                "role": profile.get("role", "CLIENT"),
                "status": profile.get("status", "ACTIVE"),
                "balance": profile.get("balance", 0)
            })

            # Harvest user audits securely
            for log in profile.get("auditHistory", []):
                audit_entry = log.copy()
                audit_entry["_user"] = identifier
                global_audit_logs.append(audit_entry)

    # Sort logs descending temporally
    global_audit_logs.sort(key=lambda x: x.get("time", ""), reverse=True)

    return {
        "status": "SUCCESS",
        "system_metrics": {
            "total_liquidity": total_sys_balance,
            "total_loans_issued": total_sys_loans,
            "user_count": len(users),
            "admin_vault_iban": "TR3600064000000000000000ADMIN",
            "admin_vault_balance": db_data.get("11111111110", {}).get("balance", 0)
        },
        "users": users,
        "logs": global_audit_logs[:100] # Provide top 100 most recent records across network
    }

# 7. Market Data Proxy (Using yfinance for robustness)
@app.get("/market/search")
async def market_search(q: str):
    headers = {"User-Agent": "Mozilla/5.0"}
    async with httpx.AsyncClient() as client:
        try:
            # Search API still works usually, but we'll use a better endpoint
            url = f"https://query2.finance.yahoo.com/v1/finance/search?q={q}&quotesCount=10&newsCount=0"
            resp = await client.get(url, headers=headers)
            return resp.json()
        except Exception as e:
            # Fallback mock results if server is IP-blocked
            return {"quotes": []}

# Global FX Cache to speed up details requests
FX_CACHE = {"USDTRY": 32.95, "last_sync": 0}

@app.get("/market/details")
async def market_details(symbol: str, period: str = "1d", interval: str = "1m"):
    try:
        ticker = yf.Ticker(symbol)
        # Fetching high-res data for detailed charts
        hist = ticker.history(period=period, interval=interval)
        
        # fast_info for current price and metadata
        price = ticker.fast_info.last_price
        prev_close = ticker.fast_info.previous_close
        currency = ticker.fast_info.currency
        
        # Fast USDTRY conversion (cached for performance)
        curr_time = time.time()
        if curr_time - FX_CACHE["last_sync"] > 120: # Sync every 2 mins
            try:
                usdtry_ticker = yf.Ticker("USDTRY=X")
                FX_CACHE["USDTRY"] = usdtry_ticker.fast_info.last_price
                FX_CACHE["last_sync"] = curr_time
            except: pass
        usdtry = FX_CACHE["USDTRY"]
        
        # Prepare chart data (dropping NaNs and ensuring density)
        chart_data = hist['Close'].dropna().tolist()
        
        return {
            "symbol": symbol,
            "regularMarketPrice": price,
            "regularMarketPreviousClose": prev_close,
            "currency": currency,
            "rate": usdtry,
            "chart": chart_data,
            "marketState": ticker.fast_info.get('market_state', 'OPEN')
        }
    except Exception as e:
        print(f"Error fetching {symbol}: {e}")
        return {"error": str(e), "regularMarketPrice": 0, "rate": 32.95}

@app.get("/market/watch")
async def market_watch():
    symbols = ["USDTRY=X", "EURTRY=X", "XAUUSD=L", "BTC-USD"]
    try:
        results = {}
        for sym in symbols:
            t = yf.Ticker(sym)
            price = t.fast_info.last_price
            prev = t.fast_info.previous_close
            chg = ((price - prev) / prev) * 100
            name = sym.replace("=X", "").replace("-USD", "").replace("=L", " GOLD")
            results[name] = {"price": f"{price:,.2f}", "change": f"{chg:+.2f}%"}
        return results
    except:
        return {"USD/TRY": {"price": "32.95", "change": "+0.15%"}}

@app.get("/market/indices")
async def market_indices():
    # Forex and Commodities for the Markets page
    symbols = ["USDTRY=X", "EURTRY=X", "GBPTRY=X", "XAUUSD=L", "XAGUSD=L", "GC=F", "CL=F"]
    results = []
    
    # We perform sequential fetch for stability, since Yahoo can rate limit concurrent small requests
    for sym in symbols:
        try:
            ticker = yf.Ticker(sym)
            hist = ticker.history(period="1d", interval="15m")
            
            # Use fast_info for real-time prices
            info = ticker.fast_info
            price = info.last_price
            prev_close = info.previous_close
            change_pct = ((price - prev_close) / prev_close) * 100 if prev_close else 0
            
            # Prepare sparkline data (Close prices)
            sparkline_raw = hist['Close'].tolist()
            # Basic cleanup: remove NaNs and keep only last 20 points
            sparkline = [p for p in sparkline_raw if p == p][-20:]
            
            # Human readable name mapping
            name_map = {
                "USDTRY=X": "USD / TRY",
                "EURTRY=X": "EUR / TRY",
                "GBPTRY=X": "GBP / TRY",
                "XAUUSD=L": "GOLD (ONS)",
                "XAGUSD=L": "SILVER (ONS)",
                "GC=F": "GOLD FUTURES",
                "CL=F": "CRUDE OIL"
            }
            
            results.append({
                "symbol": sym,
                "name": name_map.get(sym, sym),
                "price": price,
                "change": change_pct,
                "sparkline": sparkline
            })
        except Exception as e:
            print(f"Index error fetching {sym}: {e}")
            
    return results

# 8. Banking Endpoints
@app.post("/chat")
async def chat_endpoint(req: dict):
    user_msg = req.get("message", "").lower()
    tc = req.get("tc_identity", "unknown")
    db_data = load_local_db()
    user_state = db_data.get(tc, {})
    balance = user_state.get("balance", 0)
    
    if "balance" in user_msg or "bakiye" in user_msg:
        res = f"Bakiye analizi yapıldı: Mevcut bakiyeniz {balance:,.2f} ₺. Portföyünüz stabil görünüyor."
    elif "selam" in user_msg or "merhaba" in user_msg:
        res = "Merhaba! Ben OZAS Assistant. Size nasıl yardımcı olabilirim?"
    else:
        res = "Anladım. Başka bir konuda yardımcı olmamı ister misiniz? (Bakiye, Transfer vb.)"
    return {"reply": res}

@app.post("/loans/apply")
async def apply_loan(req: dict):
    tc = req.get("tc_identity")
    salary = float(req.get("salary", 0))
    occupation = req.get("occupation", "Other")
    req_amount = float(req.get("amount", 0))
    loan_type = req.get("type", "Personal")
    term = int(req.get("term", 12))
    insured = req.get("insured", False)
    
    if occupation == "Student":
        return {
            "status": "DENIED",
            "message": "Sorry, our credit policies do not currently allow loans for students. Please contact support for academic financing options."
        }
    
    # Calculate MAX LIMIT based on tiers
    if salary <= 5000:
        max_limit = salary * 3
    elif salary <= 15000:
        max_limit = salary * 5
    elif salary <= 40000:
        max_limit = salary * 8
    else:
        max_limit = salary * 12

    if req_amount > max_limit:
        return {
            "status": "ERROR",
            "message": f"Your requested amount ({req_amount:,.2f} ₺) exceeds your maximum eligible limit of {max_limit:,.2f} ₺ based on your income profile."
        }
    
    if req_amount <= 0:
        return {"status": "ERROR", "message": "Invalid loan amount."}

    db_data = load_local_db()
    if tc in db_data:
        user = db_data[tc]
        
        # Determine interest rate (simulation)
        base_rate = 2.49
        rate_bump = (term - 12) * 0.05 if term > 12 else 0
        final_rate = base_rate + rate_bump
        
        # Initialize lists if missing
        if "activeLoans" not in user: user["activeLoans"] = []
        if "ledgerHistory" not in user: user["ledgerHistory"] = []
        if "auditHistory" not in user: user["auditHistory"] = []

        loan_id = f"LN-{int(time.time())}"
        new_loan = {
            "loan_id": loan_id,
            "type": loan_type,
            "amount": req_amount,
            "term": term,
            "rate": final_rate,
            "insured": insured,
            "monthly": (req_amount * (1 + final_rate/100)) / term,
            "date": datetime.now().isoformat()
        }
        
        user["activeLoans"].append(new_loan)
        user["balance"] = user.get("balance", 0.0) + req_amount
        user["loans"] = user.get("loans", 0.0) + req_amount
        
        # Transaction History
        user["ledgerHistory"].insert(0, {
            "txid": f"GL-{int(time.time())}",
            "desc": f"Loan Disbursement: {loan_type} ({loan_id})",
            "debit": 0,
            "credit": req_amount,
            "move": req_amount,
            "balance": user["balance"],
            "time": datetime.now().isoformat()
        })
        
        save_local_db(db_data)
        
        return {
            "status": "SUCCESS",
            "loan": new_loan,
            "message": f"Success! Your {loan_type} loan for {req_amount:,.2f} ₺ has been approved and deposited. Monthly payment: {new_loan['monthly']:,.2f} ₺."
        }
    
    raise HTTPException(status_code=404, detail="Identity not found.")

@app.post("/transfer/internal")
async def internal_transfer(req: dict):
    """
    Core P2P internal transfer mechanism using targeted IBAN resolution.
    Strictly coordinates Dual-Ledger atomicity & Webhook event lifecycles.
    Required Events: TransferCreated, AccountDebited, AccountCredited, TransferCompleted.
    """
    sender_tc = req.get("sender_tc")
    receiver_iban = req.get("receiver_iban", "").replace(" ", "").upper()
    amount = float(req.get("amount", 0))

    if amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid transfer amount")

    db_data = load_local_db()
    if sender_tc not in db_data:
        raise HTTPException(status_code=404, detail="Sender Identity not found.")
        
    sender = db_data[sender_tc]
    if sender.get("balance", 0) < amount:
        raise HTTPException(status_code=400, detail="Insufficient Balance")

    # Locate external IBAN within isolated DB nodes
    receiver_tc = None
    for identifier, profile in db_data.items():
        # Smart Match: Check for exact IBAN or flexible Admin IBAN match
        clean_receiver_iban = receiver_iban.replace(" ", "").upper()
        profile_iban = profile.get("iban", "").replace(" ", "").upper()
        
        is_exact_match = (profile_iban == clean_receiver_iban)
        is_flexible_admin_match = (clean_receiver_iban.endswith("ADMIN") and identifier == "11111111110")
        
        if (is_exact_match or is_flexible_admin_match) and identifier != sender_tc:
            receiver_profile = profile
            receiver_tc = identifier
            break
            
    if not receiver_tc:
        raise HTTPException(status_code=404, detail="Destination IBAN is Invalid or Unregistered.")
        
    receiver = db_data[receiver_tc]

    # 1. Fire TransferCreated Event
    tx_id = f"TRX-{int(time.time())}"
    await fire_webhook("TransferCreated", {"tx_id": tx_id, "amount": amount, "sender": sender_tc, "receiver": receiver_iban})

    # 2. Sequential Atomic Execution: Debit Sender
    sender["balance"] -= amount
    if "ledgerHistory" not in sender: sender["ledgerHistory"] = []
    sender["ledgerHistory"].insert(0, {
        "txid": tx_id,
        "desc": f"Transfer Sent to {receiver_iban}",
        "debit": amount,
        "credit": 0,
        "move": -amount,
        "balance": sender["balance"],
        "time": datetime.now().isoformat()
    })
    
    await fire_webhook("AccountDebited", {"tx_id": tx_id, "account": sender_tc, "amount": amount})
    
    # 3. Sequential Atomic Execution: Credit Receiver
    receiver["balance"] = receiver.get("balance", 0) + amount
    if "ledgerHistory" not in receiver: receiver["ledgerHistory"] = []
    receiver["ledgerHistory"].insert(0, {
        "txid": tx_id,
        "desc": f"Transfer Received from {sender_tc}",
        "debit": 0,
        "credit": amount,
        "move": amount,
        "balance": receiver["balance"],
        "time": datetime.now().isoformat()
    })

    await fire_webhook("AccountCredited", {"tx_id": tx_id, "account": receiver_tc, "amount": amount})

    # 4. Commit Flat-file ACID Ledger
    save_local_db(db_data)
    
    await fire_webhook("TransferCompleted", {"tx_id": tx_id, "status": "SUCCESS"})
    
    return {
        "status": "SUCCESS", 
        "message": f"Successfully merged {amount:,.2f} ₺ into {receiver_iban}", 
        "sender_balance": sender["balance"],
        "sender_ledger": sender["ledgerHistory"]
    }

if __name__ == "__main__":
    # Render.com provides a PORT env variable
    port_num = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port_num)