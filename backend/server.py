"""
CIAP - Crime Intelligence & Analytical Platform
FastAPI backend for Karnataka State Police / SCRB
"""
from dotenv import load_dotenv
load_dotenv()

import os
import jwt
import bcrypt
import uuid
import random
import math
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from collections import defaultdict, Counter

from fastapi import FastAPI, HTTPException, Request, Response, Depends, Query, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient
import numpy as np
from sklearn.cluster import KMeans

# -----------------------------------------------------------
# Config
# -----------------------------------------------------------
JWT_ALGORITHM = "HS256"
JWT_SECRET = os.environ["JWT_SECRET"]
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="CIAP API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

api = APIRouter(prefix="/api")

# -----------------------------------------------------------
# Auth Utilities
# -----------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["sub"]})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user.pop("password_hash", None)
        user.pop("_id", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_roles(*roles):
    async def _dep(user: dict = Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return _dep

# -----------------------------------------------------------
# Models
# -----------------------------------------------------------
class LoginPayload(BaseModel):
    email: str
    password: str

class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    district: Optional[str] = None
    station: Optional[str] = None

# -----------------------------------------------------------
# Karnataka reference data
# -----------------------------------------------------------
KARNATAKA_DISTRICTS = [
    # (name, lat, lng, population_lakh, urban_index 0-1)
    ("Bengaluru Urban", 12.9716, 77.5946, 96.2, 0.98),
    ("Bengaluru Rural", 13.2846, 77.7947, 9.9, 0.55),
    ("Mysuru", 12.2958, 76.6394, 30.1, 0.62),
    ("Mangaluru (Dakshina Kannada)", 12.9141, 74.8560, 20.9, 0.72),
    ("Hubballi-Dharwad", 15.3647, 75.1240, 18.4, 0.68),
    ("Belagavi", 15.8497, 74.4977, 47.8, 0.48),
    ("Kalaburagi", 17.3297, 76.8343, 25.7, 0.42),
    ("Ballari", 15.1394, 76.9214, 24.5, 0.44),
    ("Vijayapura", 16.8302, 75.7100, 21.7, 0.38),
    ("Shivamogga", 13.9299, 75.5681, 17.5, 0.50),
    ("Tumakuru", 13.3379, 77.1173, 26.8, 0.46),
    ("Davanagere", 14.4644, 75.9218, 19.5, 0.52),
    ("Raichur", 16.2076, 77.3463, 19.3, 0.36),
    ("Kolar", 13.1362, 78.1296, 15.4, 0.44),
    ("Mandya", 12.5218, 76.8951, 18.1, 0.40),
    ("Hassan", 13.0033, 76.1004, 17.7, 0.42),
    ("Udupi", 13.3409, 74.7421, 11.8, 0.68),
    ("Chikkamagaluru", 13.3161, 75.7720, 11.3, 0.38),
    ("Bagalkot", 16.1867, 75.6960, 18.9, 0.40),
    ("Bidar", 17.9133, 77.5301, 17.0, 0.40),
    ("Yadgir", 16.7686, 77.1379, 11.7, 0.28),
    ("Koppal", 15.3547, 76.1547, 13.9, 0.34),
    ("Gadag", 15.4310, 75.6355, 10.6, 0.42),
    ("Haveri", 14.7935, 75.4041, 15.9, 0.40),
    ("Uttara Kannada", 14.7936, 74.6869, 14.4, 0.44),
    ("Chitradurga", 14.2251, 76.4009, 16.6, 0.42),
    ("Chikkaballapur", 13.4355, 77.7315, 12.6, 0.44),
    ("Ramanagara", 12.7217, 77.2807, 10.8, 0.46),
    ("Kodagu", 12.3375, 75.8069, 5.5, 0.44),
    ("Chamarajanagar", 11.9261, 76.9437, 10.2, 0.34),
]

CRIME_HEADS = [
    ("Cybercrime", ["Online Fraud", "Phishing", "Identity Theft", "Cyber Stalking", "Data Breach"]),
    ("Property Theft", ["Burglary", "Motor Vehicle Theft", "Chain Snatching", "House Break-in", "Shop Theft"]),
    ("Narcotics (NDPS)", ["Cannabis", "MDMA", "Cocaine", "Synthetic Drugs", "Trafficking"]),
    ("Violent Crime", ["Murder", "Assault", "Attempt to Murder", "Robbery", "Kidnapping"]),
    ("Financial Fraud", ["Chit Fund Fraud", "Bank Fraud", "Investment Scam", "Cheque Bounce", "Loan Fraud"]),
    ("Organized Crime", ["Extortion", "Gang Violence", "Illegal Arms", "Betting", "Racketeering"]),
    ("Crime Against Women", ["Dowry Harassment", "Domestic Violence", "Sexual Assault", "Eve Teasing", "Stalking"]),
    ("Public Order", ["Rioting", "Communal Violence", "Illegal Assembly", "Trespass", "Nuisance"]),
]

GRAVITY_LEVELS = ["Petty", "Non-Cognizable", "Cognizable", "Heinous"]
CASE_STATUSES = ["Under Investigation", "Chargesheet Filed", "Convicted", "Acquitted", "Pending Trial", "Closed"]
CASTE_MASTER = ["General", "OBC", "SC", "ST", "Other"]
RELIGIONS = ["Hindu", "Muslim", "Christian", "Jain", "Sikh", "Buddhist", "Other"]
OCCUPATIONS = ["Unemployed", "Daily Wage", "Farmer", "Business", "Service", "Student", "Retired", "IT Professional"]
GENDERS = ["Male", "Female", "Other"]
MODUS_OPERANDI = [
    "Impersonation", "Lock Breaking", "Digital Wallet Fraud", "Cheque Cloning",
    "Chain Snatching (2-wheeler)", "Honey Trap", "OTP Phishing", "SIM Swap",
    "Fake Job Offer", "Ponzi Scheme", "Break-in via Window", "Extortion Call",
    "Group Assault", "Late Night Robbery", "Gang Coordination via Messenger",
]

# -----------------------------------------------------------
# Seed data
# -----------------------------------------------------------
async def seed_users():
    users_spec = [
        (os.environ["ADMIN_EMAIL"], os.environ["ADMIN_PASSWORD"], "SCRB Admin", "scrb_admin", None, None),
        (os.environ["DISTRICT_OFFICER_EMAIL"], os.environ["DISTRICT_OFFICER_PASSWORD"], "Dy. SP - Bengaluru", "district_officer", "Bengaluru Urban", None),
        (os.environ["STATION_OFFICER_EMAIL"], os.environ["STATION_OFFICER_PASSWORD"], "SI - Ashok Nagar PS", "station_officer", "Bengaluru Urban", "Ashok Nagar PS"),
    ]
    for email, pw, name, role, district, station in users_spec:
        existing = await db.users.find_one({"email": email})
        if existing is None:
            await db.users.insert_one({
                "id": str(uuid.uuid4()),
                "email": email,
                "password_hash": hash_password(pw),
                "name": name,
                "role": role,
                "district": district,
                "station": station,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
        elif not verify_password(pw, existing["password_hash"]):
            await db.users.update_one({"email": email}, {"$set": {"password_hash": hash_password(pw)}})

async def seed_cases(force: bool = False):
    if not force and await db.cases.count_documents({}) > 0:
        return
    await db.cases.delete_many({})
    await db.persons.delete_many({})

    rng = random.Random(42)
    cases = []
    persons_by_key = {}   # dedupe repeat offenders
    accused_pool_all = []

    # Create a set of repeat offenders (25) - they'll be reused across cases
    repeat_offenders = []
    for i in range(25):
        po = {
            "id": str(uuid.uuid4()),
            "type": "accused",
            "name": f"REP-OFF-{i+1:03d} " + rng.choice(["Kumar","Rao","Shetty","Reddy","Naik","Gowda","Khan","Patel","Fernandes","Iyer"]),
            "age": rng.randint(22, 55),
            "gender": rng.choice(GENDERS),
            "religion": rng.choice(RELIGIONS),
            "caste": rng.choice(CASTE_MASTER),
            "occupation": rng.choice(OCCUPATIONS),
            "repeat_offender": True,
            "signature_mo": rng.sample(MODUS_OPERANDI, 2),
            "home_district": rng.choice(KARNATAKA_DISTRICTS)[0],
        }
        repeat_offenders.append(po)
        accused_pool_all.append(po)

    # Generate ~900 cases across 2 years
    now = datetime.now(timezone.utc)
    two_years_ago = now - timedelta(days=730)

    for _ in range(900):
        district = rng.choices(
            KARNATAKA_DISTRICTS,
            weights=[d[3] * (1 + d[4]) for d in KARNATAKA_DISTRICTS],  # weighted by pop*urban
            k=1
        )[0]
        d_name, d_lat, d_lng, pop, urban = district

        # Choose crime head with district bias
        if "Bengaluru Urban" in d_name:
            head_choice = rng.choices(CRIME_HEADS, weights=[6,3,2,2,4,2,3,2], k=1)[0]
        elif "Mangaluru" in d_name:
            head_choice = rng.choices(CRIME_HEADS, weights=[2,3,5,2,2,3,3,2], k=1)[0]  # Narcotics spike
        elif urban > 0.6:
            head_choice = rng.choices(CRIME_HEADS, weights=[4,4,2,2,3,2,3,2], k=1)[0]
        else:
            head_choice = rng.choices(CRIME_HEADS, weights=[1,4,2,3,2,2,3,3], k=1)[0]

        head_name, sub_heads = head_choice
        sub_head = rng.choice(sub_heads)
        gravity = rng.choice(GRAVITY_LEVELS)
        status = rng.choice(CASE_STATUSES)
        # Temporal skew: more cases in recent 6 months (emerging trend)
        if rng.random() < 0.4:
            crime_dt = now - timedelta(days=rng.randint(0, 180), hours=rng.randint(0,23))
        else:
            crime_dt = two_years_ago + timedelta(days=rng.randint(0, 730), hours=rng.randint(0,23))

        # Simulate red-zone spike for Cybercrime Bengaluru last 60 days
        if "Bengaluru Urban" in d_name and head_name == "Cybercrime" and rng.random() < 0.3:
            crime_dt = now - timedelta(days=rng.randint(0, 60), hours=rng.randint(0, 23))

        # Time of day distribution
        hour = crime_dt.hour
        # For property/violent → skew nights
        if head_name in ("Property Theft", "Violent Crime", "Organized Crime"):
            hour = rng.choices(range(24), weights=[3,3,4,4,4,3,2,1,1,1,1,1,1,1,1,1,2,2,3,3,4,4,4,3], k=1)[0]
        elif head_name == "Cybercrime":
            hour = rng.choices(range(24), weights=[1,1,1,1,1,1,2,3,4,5,5,5,5,4,4,4,5,5,4,3,2,2,1,1], k=1)[0]
        crime_dt = crime_dt.replace(hour=hour, minute=rng.randint(0,59))

        # Geo jitter within district
        lat = d_lat + rng.uniform(-0.15, 0.15)
        lng = d_lng + rng.uniform(-0.15, 0.15)

        case_id = str(uuid.uuid4())
        fir_no = f"FIR/{crime_dt.year}/{rng.randint(1000,9999)}"

        # Complainants (1)
        complainant = {
            "id": str(uuid.uuid4()),
            "type": "complainant",
            "name": f"Complainant-{rng.randint(1000,9999)}",
            "age": rng.randint(18, 72),
            "gender": rng.choice(GENDERS),
            "religion": rng.choice(RELIGIONS),
            "caste": rng.choice(CASTE_MASTER),
            "occupation": rng.choice(OCCUPATIONS),
            "case_id": case_id,
        }

        # Victims (0-3)
        n_victims = rng.choices([1,2,3,0], weights=[6,2,1,1], k=1)[0]
        victims = []
        for _ in range(n_victims):
            victims.append({
                "id": str(uuid.uuid4()),
                "type": "victim",
                "name": f"Victim-{rng.randint(1000,9999)}",
                "age": rng.randint(6, 85),
                "gender": rng.choice(GENDERS),
                "case_id": case_id,
                "is_police": rng.random() < 0.02,
            })

        # Accused (1-4). Sometimes reuse repeat offender.
        n_accused = rng.choices([1,2,3,4], weights=[5,3,2,1], k=1)[0]
        accused = []
        for _ in range(n_accused):
            if rng.random() < 0.22 and repeat_offenders:
                ro = rng.choice(repeat_offenders)
                accused.append({
                    "person_id": ro["id"],
                    "name": ro["name"],
                    "age": ro["age"],
                    "gender": ro["gender"],
                    "repeat_offender": True,
                })
            else:
                acid = str(uuid.uuid4())
                pnew = {
                    "id": acid,
                    "type": "accused",
                    "name": f"Suspect-{rng.randint(10000,99999)}",
                    "age": rng.randint(17, 65),
                    "gender": rng.choice(GENDERS),
                    "religion": rng.choice(RELIGIONS),
                    "caste": rng.choice(CASTE_MASTER),
                    "occupation": rng.choice(OCCUPATIONS),
                    "repeat_offender": False,
                    "signature_mo": [rng.choice(MODUS_OPERANDI)],
                    "home_district": d_name,
                }
                accused_pool_all.append(pnew)
                accused.append({
                    "person_id": acid,
                    "name": pnew["name"],
                    "age": pnew["age"],
                    "gender": pnew["gender"],
                    "repeat_offender": False,
                })

        mo = rng.choice(MODUS_OPERANDI)
        # Repeat offender pattern: use their signature MO
        for a in accused:
            if a.get("repeat_offender"):
                ro = next((r for r in repeat_offenders if r["id"] == a["person_id"]), None)
                if ro and rng.random() < 0.7:
                    mo = rng.choice(ro["signature_mo"])
                    break

        arrests = []
        if status in ("Chargesheet Filed", "Convicted", "Acquitted"):
            for a in accused:
                if rng.random() < 0.75:
                    arrests.append({
                        "person_id": a["person_id"],
                        "name": a["name"],
                        "date": (crime_dt + timedelta(days=rng.randint(1, 60))).isoformat(),
                        "district": d_name,
                        "type": "Arrest",
                    })

        police_station = f"{d_name.split(' (')[0]} PS-{rng.randint(1,8)}"

        case_doc = {
            "id": case_id,
            "fir_no": fir_no,
            "crime_no": f"CR-{rng.randint(100000,999999)}",
            "district": d_name,
            "police_station": police_station,
            "lat": lat,
            "lng": lng,
            "crime_head": head_name,
            "crime_sub_head": sub_head,
            "gravity": gravity,
            "status": status,
            "modus_operandi": mo,
            "acts_sections": rng.sample([
                "IPC 302","IPC 307","IPC 379","IPC 380","IPC 420","IPC 498A",
                "IPC 376","IT Act 66C","IT Act 66D","NDPS 20","Arms Act 25"], k=rng.randint(1,3)),
            "complainant": complainant,
            "victims": victims,
            "accused": accused,
            "arrests": arrests,
            "occurrence_at": crime_dt.isoformat(),
            "registered_at": (crime_dt + timedelta(hours=rng.randint(1, 48))).isoformat(),
            "chargesheet": {
                "filed": status in ("Chargesheet Filed","Convicted","Acquitted"),
                "date": (crime_dt + timedelta(days=rng.randint(30,180))).isoformat() if status in ("Chargesheet Filed","Convicted","Acquitted") else None,
            },
        }
        cases.append(case_doc)

    # Insert persons (dedup by id)
    seen = set()
    persons_docs = []
    for p in accused_pool_all + repeat_offenders:
        if p["id"] in seen: continue
        seen.add(p["id"])
        persons_docs.append(p)
    if persons_docs:
        await db.persons.insert_many(persons_docs)
    if cases:
        await db.cases.insert_many(cases)

# -----------------------------------------------------------
# Startup
# -----------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    await db.users.create_index("email", unique=True)
    await db.cases.create_index("district")
    await db.cases.create_index("crime_head")
    await db.cases.create_index("occurrence_at")
    await seed_users()
    await seed_cases(force=False)

# -----------------------------------------------------------
# Auth endpoints
# -----------------------------------------------------------
@api.post("/auth/login")
async def login(payload: LoginPayload, response: Response):
    email = payload.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user["id"], user["email"], user["role"])
    return {
        "access_token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
            "district": user.get("district"),
            "station": user.get("station"),
        }
    }

@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "district": user.get("district"),
        "station": user.get("station"),
    }

# -----------------------------------------------------------
# Reference endpoints
# -----------------------------------------------------------
@api.get("/reference")
async def reference(user=Depends(get_current_user)):
    return {
        "districts": [
            {"name": d[0], "lat": d[1], "lng": d[2], "pop_lakh": d[3], "urban_index": d[4]}
            for d in KARNATAKA_DISTRICTS
        ],
        "crime_heads": [h[0] for h in CRIME_HEADS],
        "sub_heads_by_head": {h[0]: h[1] for h in CRIME_HEADS},
        "gravity": GRAVITY_LEVELS,
        "statuses": CASE_STATUSES,
    }

# -----------------------------------------------------------
# Filter helper
# -----------------------------------------------------------
def parse_filters(
    district: Optional[str],
    crime_head: Optional[str],
    gravity: Optional[str],
    status: Optional[str],
    days: Optional[int],
) -> dict:
    q: dict = {}
    if district and district != "all":
        q["district"] = district
    if crime_head and crime_head != "all":
        q["crime_head"] = crime_head
    if gravity and gravity != "all":
        q["gravity"] = gravity
    if status and status != "all":
        q["status"] = status
    if days:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        q["occurrence_at"] = {"$gte": cutoff}
    return q

# -----------------------------------------------------------
# Dashboard analytics
# -----------------------------------------------------------
@api.get("/analytics/kpi")
async def analytics_kpi(
    district: Optional[str] = None,
    crime_head: Optional[str] = None,
    gravity: Optional[str] = None,
    status: Optional[str] = None,
    days: Optional[int] = None,
    user=Depends(get_current_user),
):
    q = parse_filters(district, crime_head, gravity, status, days)
    total = await db.cases.count_documents(q)
    active = await db.cases.count_documents({**q, "status": {"$in": ["Under Investigation","Pending Trial"]}})
    chargesheet = await db.cases.count_documents({**q, "chargesheet.filed": True})
    heinous = await db.cases.count_documents({**q, "gravity": "Heinous"})

    # arrests count
    pipeline = [
        {"$match": q},
        {"$project": {"arrests_n": {"$size": {"$ifNull": ["$arrests", []]}}}},
        {"$group": {"_id": None, "total": {"$sum": "$arrests_n"}}},
    ]
    agg = await db.cases.aggregate(pipeline).to_list(1)
    total_arrests = agg[0]["total"] if agg else 0

    disposal_rate = round((chargesheet / total) * 100, 1) if total else 0.0

    # last 7d vs prev 7d trend
    now = datetime.now(timezone.utc)
    last7 = (now - timedelta(days=7)).isoformat()
    prev7 = (now - timedelta(days=14)).isoformat()
    n_last = await db.cases.count_documents({**q, "occurrence_at": {"$gte": last7}})
    n_prev = await db.cases.count_documents({**q, "occurrence_at": {"$gte": prev7, "$lt": last7}})
    trend_pct = round(((n_last - n_prev) / n_prev) * 100, 1) if n_prev else 0.0

    return {
        "total_cases": total,
        "active_investigations": active,
        "chargesheets_filed": chargesheet,
        "heinous_cases": heinous,
        "total_arrests": total_arrests,
        "disposal_rate": disposal_rate,
        "week_trend_pct": trend_pct,
        "last_week_count": n_last,
        "prev_week_count": n_prev,
    }

@api.get("/analytics/by_district")
async def by_district(
    crime_head: Optional[str] = None, gravity: Optional[str] = None,
    status: Optional[str] = None, days: Optional[int] = None,
    user=Depends(get_current_user)
):
    q = parse_filters(None, crime_head, gravity, status, days)
    pipeline = [
        {"$match": q},
        {"$group": {"_id": "$district", "count": {"$sum": 1},
                    "heinous": {"$sum": {"$cond": [{"$eq":["$gravity","Heinous"]},1,0]}}}},
    ]
    rows = await db.cases.aggregate(pipeline).to_list(200)
    dmap = {d[0]: d for d in KARNATAKA_DISTRICTS}
    out = []
    for r in rows:
        d = dmap.get(r["_id"])
        if not d: continue
        out.append({
            "district": r["_id"],
            "lat": d[1], "lng": d[2],
            "count": r["count"],
            "heinous": r["heinous"],
            "pop_lakh": d[3],
            "urban_index": d[4],
            "crime_rate_per_lakh": round(r["count"] / d[3], 2),
        })
    out.sort(key=lambda x: x["count"], reverse=True)
    return out

@api.get("/analytics/trends")
async def analytics_trends(
    district: Optional[str] = None, crime_head: Optional[str] = None,
    gravity: Optional[str] = None, days: int = 365,
    user=Depends(get_current_user)
):
    q = parse_filters(district, crime_head, gravity, None, days)
    cases = await db.cases.find(q, {"occurrence_at":1, "crime_head":1}).to_list(20000)
    # bucket by month
    buckets: Dict[str, Dict[str,int]] = defaultdict(lambda: defaultdict(int))
    for c in cases:
        try:
            dt = datetime.fromisoformat(c["occurrence_at"].replace("Z",""))
        except Exception:
            continue
        key = dt.strftime("%Y-%m")
        buckets[key][c["crime_head"]] += 1
        buckets[key]["_total"] += 1
    keys = sorted(buckets.keys())
    series = []
    heads = [h[0] for h in CRIME_HEADS]
    for k in keys:
        row = {"month": k, "total": buckets[k].get("_total",0)}
        for h in heads:
            row[h] = buckets[k].get(h, 0)
        series.append(row)
    return {"series": series, "heads": heads}

@api.get("/analytics/heatmap")
async def analytics_heatmap(
    crime_head: Optional[str] = None, district: Optional[str] = None,
    days: Optional[int] = 365,
    user=Depends(get_current_user)
):
    q = parse_filters(district, crime_head, None, None, days)
    cases = await db.cases.find(q, {"occurrence_at":1, "district":1}).to_list(20000)
    grid: Dict[str, Dict[int,int]] = defaultdict(lambda: defaultdict(int))
    days_of_week = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
    for c in cases:
        try:
            dt = datetime.fromisoformat(c["occurrence_at"].replace("Z",""))
        except Exception:
            continue
        dow = days_of_week[dt.weekday()]
        grid[dow][dt.hour] += 1
    out = []
    for dow in days_of_week:
        for h in range(24):
            out.append({"day": dow, "hour": h, "count": grid[dow].get(h, 0)})
    return {"cells": out}

@api.get("/analytics/by_crime_head")
async def by_crime_head(
    district: Optional[str] = None, gravity: Optional[str] = None,
    days: Optional[int] = None,
    user=Depends(get_current_user)
):
    q = parse_filters(district, None, gravity, None, days)
    pipeline = [
        {"$match": q},
        {"$group": {"_id": "$crime_head", "count": {"$sum":1}}},
        {"$sort": {"count": -1}}
    ]
    rows = await db.cases.aggregate(pipeline).to_list(50)
    return [{"crime_head": r["_id"], "count": r["count"]} for r in rows]

@api.get("/analytics/status_mix")
async def status_mix(district: Optional[str]=None, crime_head: Optional[str]=None, user=Depends(get_current_user)):
    q = parse_filters(district, crime_head, None, None, None)
    pipeline = [{"$match": q}, {"$group": {"_id":"$status","count":{"$sum":1}}}]
    rows = await db.cases.aggregate(pipeline).to_list(50)
    return [{"status": r["_id"], "count": r["count"]} for r in rows]

# -----------------------------------------------------------
# Predictive / Anomaly
# -----------------------------------------------------------
@api.get("/predict/risk")
async def predict_risk(user=Depends(get_current_user)):
    """
    Per-district risk score using recent 90d vs prior 90d volume trend,
    heinous ratio, urban index, and simple z-scored composite.
    """
    now = datetime.now(timezone.utc)
    d1 = (now - timedelta(days=90)).isoformat()
    d2 = (now - timedelta(days=180)).isoformat()

    dmap = {d[0]: d for d in KARNATAKA_DISTRICTS}
    features = []
    for name in dmap.keys():
        n_recent = await db.cases.count_documents({"district": name, "occurrence_at": {"$gte": d1}})
        n_prev = await db.cases.count_documents({"district": name, "occurrence_at": {"$gte": d2, "$lt": d1}})
        heinous = await db.cases.count_documents({"district": name, "gravity": "Heinous", "occurrence_at": {"$gte": d1}})
        growth = ((n_recent - n_prev) / n_prev) if n_prev else 0.0
        heinous_ratio = (heinous / n_recent) if n_recent else 0.0
        urban = dmap[name][4]
        features.append({
            "district": name,
            "recent_90d": n_recent,
            "prev_90d": n_prev,
            "growth_pct": round(growth*100, 1),
            "heinous_ratio": round(heinous_ratio*100, 1),
            "urban_index": urban,
        })
    # Z-score based composite
    vols = np.array([f["recent_90d"] for f in features], dtype=float)
    grw  = np.array([f["growth_pct"]  for f in features], dtype=float)
    hein = np.array([f["heinous_ratio"] for f in features], dtype=float)
    urb  = np.array([f["urban_index"]  for f in features], dtype=float)
    def z(a): 
        s = a.std() or 1.0
        return (a - a.mean()) / s
    composite = 0.45*z(vols) + 0.25*z(grw) + 0.20*z(hein) + 0.10*z(urb)
    # Scale to 0-100
    lo, hi = composite.min(), composite.max()
    scores = ((composite - lo) / (hi - lo) * 100) if hi != lo else np.zeros_like(composite)
    for i, f in enumerate(features):
        s = float(round(scores[i], 1))
        f["risk_score"] = s
        f["risk_band"] = "Critical" if s >= 75 else ("High" if s >= 55 else ("Medium" if s >= 35 else "Low"))
    features.sort(key=lambda x: x["risk_score"], reverse=True)
    return features

@api.get("/predict/anomalies")
async def anomalies(user=Depends(get_current_user)):
    """
    Detect anomalies: districts with >2 z-score spike in last 30d for a specific crime head vs preceding months.
    """
    now = datetime.now(timezone.utc)
    cutoff_recent = (now - timedelta(days=30)).isoformat()
    cutoff_hist = (now - timedelta(days=210)).isoformat()  # 6 prior months
    pipeline_hist = [
        {"$match": {"occurrence_at": {"$gte": cutoff_hist, "$lt": cutoff_recent}}},
        {"$group": {"_id": {"district":"$district","head":"$crime_head","month":{"$substr":["$occurrence_at",0,7]}},
                    "count": {"$sum": 1}}}
    ]
    hist = await db.cases.aggregate(pipeline_hist).to_list(10000)
    # For each (district, head) compute mean & std of monthly counts
    stats: Dict[tuple, List[int]] = defaultdict(list)
    for h in hist:
        key = (h["_id"]["district"], h["_id"]["head"])
        stats[key].append(h["count"])

    recent = await db.cases.aggregate([
        {"$match": {"occurrence_at": {"$gte": cutoff_recent}}},
        {"$group": {"_id": {"district":"$district","head":"$crime_head"}, "count":{"$sum":1}}},
    ]).to_list(2000)

    anomalies_out = []
    for r in recent:
        key = (r["_id"]["district"], r["_id"]["head"])
        arr = stats.get(key, [])
        if len(arr) >= 3:
            mean = float(np.mean(arr))
            std = float(np.std(arr)) or 1.0
            z_val = (r["count"] - mean) / std
            if z_val >= 1.8:
                anomalies_out.append({
                    "district": r["_id"]["district"],
                    "crime_head": r["_id"]["head"],
                    "recent_count": r["count"],
                    "historic_mean": round(mean, 1),
                    "z_score": round(float(z_val), 2),
                    "severity": "Critical" if z_val >= 3 else "High",
                })
    anomalies_out.sort(key=lambda x: x["z_score"], reverse=True)
    return anomalies_out[:30]

@api.get("/predict/clusters")
async def clusters(user=Depends(get_current_user)):
    """K-means spatial clustering of last 180d cases into hotspots."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()
    cases = await db.cases.find({"occurrence_at": {"$gte": cutoff}}, {"lat":1,"lng":1,"crime_head":1,"district":1}).to_list(20000)
    if len(cases) < 20:
        return {"clusters": []}
    X = np.array([[c["lat"], c["lng"]] for c in cases])
    k = min(8, len(cases)//20)
    km = KMeans(n_clusters=k, n_init=10, random_state=42).fit(X)
    labels = km.labels_
    centers = km.cluster_centers_
    cl_out = []
    for i in range(k):
        members = [c for j,c in enumerate(cases) if labels[j] == i]
        top_head = Counter([m["crime_head"] for m in members]).most_common(1)[0][0]
        top_district = Counter([m["district"] for m in members]).most_common(1)[0][0]
        cl_out.append({
            "id": i,
            "lat": float(centers[i][0]),
            "lng": float(centers[i][1]),
            "size": len(members),
            "top_crime_head": top_head,
            "top_district": top_district,
        })
    cl_out.sort(key=lambda x: x["size"], reverse=True)
    return {"clusters": cl_out}

# -----------------------------------------------------------
# Network / Link analysis
# -----------------------------------------------------------
@api.get("/network/graph")
async def network_graph(
    limit: int = 60,
    district: Optional[str] = None,
    crime_head: Optional[str] = None,
    user=Depends(get_current_user),
):
    q = parse_filters(district, crime_head, None, None, None)
    cases = await db.cases.find(q).sort("occurrence_at", -1).to_list(limit)
    nodes: Dict[str, dict] = {}
    links = []

    def add_node(nid, label, ntype, extra=None):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": ntype, **(extra or {})}

    for c in cases:
        case_nid = f"case::{c['id']}"
        add_node(case_nid, c["fir_no"], "case", {"crime_head": c["crime_head"], "district": c["district"]})
        loc_nid = f"loc::{c['district']}"
        add_node(loc_nid, c["district"], "location")
        links.append({"source": case_nid, "target": loc_nid, "label": "at"})

        for a in c.get("accused", []):
            pid = f"per::{a['person_id']}"
            add_node(pid, a["name"], "suspect", {"repeat_offender": a.get("repeat_offender", False)})
            links.append({"source": pid, "target": case_nid, "label": "accused_in"})
        for v in c.get("victims", []):
            pid = f"per::{v['id']}"
            add_node(pid, v["name"], "victim")
            links.append({"source": pid, "target": case_nid, "label": "victim_of"})

        mo_nid = f"mo::{c['modus_operandi']}"
        add_node(mo_nid, c["modus_operandi"], "mo")
        links.append({"source": case_nid, "target": mo_nid, "label": "mo"})
    return {"nodes": list(nodes.values()), "links": links}

@api.get("/network/repeat_offenders")
async def repeat_offenders(user=Depends(get_current_user)):
    # Count number of cases per accused person_id
    pipeline = [
        {"$unwind": "$accused"},
        {"$group": {"_id": "$accused.person_id",
                    "name": {"$first": "$accused.name"},
                    "case_count": {"$sum": 1},
                    "districts": {"$addToSet": "$district"},
                    "heads": {"$addToSet": "$crime_head"},
                    "mos": {"$addToSet": "$modus_operandi"}}},
        {"$match": {"case_count": {"$gte": 3}}},
        {"$sort": {"case_count": -1}},
        {"$limit": 40},
    ]
    rows = await db.cases.aggregate(pipeline).to_list(100)
    out = []
    for r in rows:
        out.append({
            "person_id": r["_id"],
            "name": r["name"],
            "case_count": r["case_count"],
            "district_count": len(r["districts"]),
            "districts": r["districts"],
            "crime_heads": r["heads"],
            "modus_operandi": r["mos"],
        })
    return out

@api.get("/network/offender/{person_id}")
async def offender_detail(person_id: str, user=Depends(get_current_user)):
    person = await db.persons.find_one({"id": person_id}, {"_id":0})
    cases = await db.cases.find({"accused.person_id": person_id}, {
        "id":1,"fir_no":1,"district":1,"police_station":1,"crime_head":1,"crime_sub_head":1,
        "modus_operandi":1,"status":1,"occurrence_at":1,"gravity":1
    }).sort("occurrence_at", -1).to_list(200)
    for c in cases:
        c.pop("_id", None)
    return {"person": person, "cases": cases}

# -----------------------------------------------------------
# Cases explorer
# -----------------------------------------------------------
@api.get("/cases")
async def list_cases(
    district: Optional[str] = None,
    crime_head: Optional[str] = None,
    gravity: Optional[str] = None,
    status: Optional[str] = None,
    days: Optional[int] = None,
    q: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
    user=Depends(get_current_user),
):
    filters = parse_filters(district, crime_head, gravity, status, days)
    if q:
        filters["$or"] = [
            {"fir_no": {"$regex": q, "$options": "i"}},
            {"crime_no": {"$regex": q, "$options": "i"}},
            {"crime_sub_head": {"$regex": q, "$options": "i"}},
            {"modus_operandi": {"$regex": q, "$options": "i"}},
            {"district": {"$regex": q, "$options": "i"}},
        ]
    total = await db.cases.count_documents(filters)
    cursor = db.cases.find(filters, {"_id":0}).sort("occurrence_at", -1).skip(skip).limit(limit)
    items = await cursor.to_list(limit)
    return {"total": total, "items": items}

@api.get("/cases/{case_id}")
async def case_detail(case_id: str, user=Depends(get_current_user)):
    c = await db.cases.find_one({"id": case_id}, {"_id":0})
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    # find linked cases (same MO or shared accused)
    linked = []
    accused_ids = [a["person_id"] for a in c.get("accused", [])]
    if accused_ids:
        others = await db.cases.find({
            "accused.person_id": {"$in": accused_ids},
            "id": {"$ne": case_id}
        }, {"_id":0, "id":1,"fir_no":1,"district":1,"crime_head":1,"occurrence_at":1,"status":1}).limit(15).to_list(15)
        linked.extend(others)
    return {"case": c, "linked_cases": linked}

@api.get("/health")
async def health():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}

app.include_router(api)
