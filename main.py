from fastapi import FastAPI, APIRouter, HTTPException, Header, Depends
from starlette.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras
import os
import uuid
import jwt
import bcrypt
from pathlib import Path
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Literal
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).parent

DATABASE_URL = os.environ["DATABASE_URL"]  # Supabase Postgres connection string

JWT_SECRET = os.environ.get("JWT_SECRET", "hisabbook-secret-change-me-in-production")
JWT_ALG = "HS256"
JWT_EXP_DAYS = 365  # stay logged in for a year

app = FastAPI(title="HisabBook API")
api_router = APIRouter(prefix="/api")


# ---------------- DB setup ----------------
class DBWrapper:
    """Thin wrapper so the rest of the code can keep using the
    conn.execute(query, params).fetchone()/.fetchall() shortcut style,
    just like the old sqlite3 connection did."""

    def __init__(self, conn):
        self.conn = conn

    def execute(self, query, params=None):
        cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, params or ())
        return cur

    def executescript(self, script):
        cur = self.conn.cursor()
        cur.execute(script)
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return DBWrapper(conn)


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            language TEXT DEFAULT 'en',
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT DEFAULT 'cash',
            opening_balance REAL DEFAULT 0,
            color TEXT,
            icon TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS categories (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            kind TEXT DEFAULT 'expense',
            color TEXT,
            icon TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            amount REAL NOT NULL,
            account_id TEXT,
            category_id TEXT,
            company_id TEXT,
            note TEXT,
            date TEXT,
            month TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS companies (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            members TEXT NOT NULL,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS split_expenses (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            description TEXT,
            amount REAL NOT NULL,
            paid_by TEXT,
            split_among TEXT,
            date TEXT,
            created_at TEXT
        );
        ALTER TABLE transactions ADD COLUMN IF NOT EXISTS company_id TEXT;
        """
    )
    conn.commit()
    conn.close()


init_db()


# ---------------- helpers ----------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def make_jwt(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "iat": int(now_utc().timestamp()),
        "exp": int((now_utc() + timedelta(days=JWT_EXP_DAYS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE user_id=%s", (payload["sub"],)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)


def user_public(row: dict) -> dict:
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "name": row["name"],
        "language": row["language"],
    }


DEFAULT_CATEGORIES = [
    {"name": "Food", "kind": "expense", "color": "#D35400", "icon": "coffee"},
    {"name": "Travel", "kind": "expense", "color": "#0277BD", "icon": "compass"},
    {"name": "Bills", "kind": "expense", "color": "#C62828", "icon": "zap"},
    {"name": "Shopping", "kind": "expense", "color": "#8E24AA", "icon": "shopping-bag"},
    {"name": "Groceries", "kind": "expense", "color": "#2E7D32", "icon": "shopping-cart"},
    {"name": "Health", "kind": "expense", "color": "#EF6C00", "icon": "heart"},
    {"name": "Entertainment", "kind": "expense", "color": "#6A1B9A", "icon": "film"},
    {"name": "Other", "kind": "expense", "color": "#4F5753", "icon": "more-horizontal"},
    {"name": "Salary", "kind": "income", "color": "#2E7D32", "icon": "briefcase"},
    {"name": "Business", "kind": "income", "color": "#1E5128", "icon": "trending-up"},
    {"name": "Gift", "kind": "income", "color": "#D35400", "icon": "gift"},
    {"name": "Other Income", "kind": "income", "color": "#4F5753", "icon": "plus-circle"},
]
DEFAULT_ACCOUNTS = [
    {"name": "Cash", "type": "cash", "opening_balance": 0.0, "color": "#1E5128", "icon": "dollar-sign"},
    {"name": "Bank", "type": "bank", "opening_balance": 0.0, "color": "#0277BD", "icon": "credit-card"},
    {"name": "UPI", "type": "upi", "opening_balance": 0.0, "color": "#D35400", "icon": "smartphone"},
]


def seed_defaults(conn, user_id: str):
    ts = now_utc().isoformat()
    for cat in DEFAULT_CATEGORIES:
        conn.execute(
            "INSERT INTO categories (id,user_id,name,kind,color,icon,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (str(uuid.uuid4()), user_id, cat["name"], cat["kind"], cat["color"], cat["icon"], ts),
        )
    for acc in DEFAULT_ACCOUNTS:
        conn.execute(
            "INSERT INTO accounts (id,user_id,name,type,opening_balance,color,icon,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (str(uuid.uuid4()), user_id, acc["name"], acc["type"], acc["opening_balance"], acc["color"], acc["icon"], ts),
        )


# ---------------- models ----------------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class AccountIn(BaseModel):
    name: str
    type: Literal["cash", "bank", "upi", "card", "other"] = "cash"
    opening_balance: float = 0.0
    color: Optional[str] = None
    icon: Optional[str] = None


class CategoryIn(BaseModel):
    name: str
    kind: Literal["income", "expense"] = "expense"
    color: Optional[str] = None
    icon: Optional[str] = None


class CompanyIn(BaseModel):
    name: str


class TransactionIn(BaseModel):
    kind: Literal["income", "expense"]
    amount: float
    account_id: str
    category_id: Optional[str] = None
    company_id: Optional[str] = None
    note: Optional[str] = None
    date: Optional[str] = None


class GroupIn(BaseModel):
    name: str
    members: List[str]


class SplitExpenseIn(BaseModel):
    description: str
    amount: float
    paid_by: str
    split_among: List[str]
    date: Optional[str] = None


class LanguageIn(BaseModel):
    language: Literal["en", "gu"]


# ---------------- auth routes ----------------
@api_router.get("/")
async def root():
    return {"message": "HisabBook API running"}


@api_router.post("/auth/register")
async def register(payload: RegisterIn):
    conn = get_db()
    existing = conn.execute("SELECT * FROM users WHERE email=%s", (payload.email.lower(),)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered. Please login instead.")
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    conn.execute(
        "INSERT INTO users (user_id,email,password_hash,name,language,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
        (user_id, payload.email.lower(), hash_password(payload.password),
         payload.name or payload.email.split("@")[0], "en", now_utc().isoformat()),
    )
    seed_defaults(conn, user_id)
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE user_id=%s", (user_id,)).fetchone()
    conn.close()
    token = make_jwt(user_id)
    return {"token": token, "user": user_public(dict(row))}


@api_router.post("/auth/login")
async def login(payload: LoginIn):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE email=%s", (payload.email.lower(),)).fetchone()
    conn.close()
    if not row or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = make_jwt(row["user_id"])
    return {"token": token, "user": user_public(dict(row))}


@api_router.get("/auth/me")
async def me(user: dict = Depends(current_user)):
    return {"user": user_public(user)}


@api_router.post("/auth/language")
async def set_language(payload: LanguageIn, user: dict = Depends(current_user)):
    conn = get_db()
    conn.execute("UPDATE users SET language=%s WHERE user_id=%s", (payload.language, user["user_id"]))
    conn.commit()
    conn.close()
    return {"ok": True, "language": payload.language}


# ---------------- accounts ----------------
@api_router.get("/accounts")
async def list_accounts(user: dict = Depends(current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM accounts WHERE user_id=%s", (user["user_id"],)).fetchall()
    items = []
    for r in rows:
        it = dict(r)
        inc = conn.execute(
            "SELECT COALESCE(SUM(amount),0) t FROM transactions WHERE user_id=%s AND account_id=%s AND kind='income'",
            (user["user_id"], it["id"]),
        ).fetchone()["t"]
        exp = conn.execute(
            "SELECT COALESCE(SUM(amount),0) t FROM transactions WHERE user_id=%s AND account_id=%s AND kind='expense'",
            (user["user_id"], it["id"]),
        ).fetchone()["t"]
        it["balance"] = float(it["opening_balance"]) + inc - exp
        items.append(it)
    conn.close()
    return {"accounts": items}


@api_router.post("/accounts")
async def create_account(payload: AccountIn, user: dict = Depends(current_user)):
    conn = get_db()
    doc_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO accounts (id,user_id,name,type,opening_balance,color,icon,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (doc_id, user["user_id"], payload.name, payload.type, payload.opening_balance,
         payload.color, payload.icon, now_utc().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"account": {"id": doc_id, **payload.dict()}}


@api_router.delete("/accounts/{account_id}")
async def delete_account(account_id: str, user: dict = Depends(current_user)):
    conn = get_db()
    conn.execute("DELETE FROM accounts WHERE id=%s AND user_id=%s", (account_id, user["user_id"]))
    conn.execute("DELETE FROM transactions WHERE account_id=%s AND user_id=%s", (account_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


# ---------------- categories ----------------
@api_router.get("/categories")
async def list_categories(user: dict = Depends(current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM categories WHERE user_id=%s", (user["user_id"],)).fetchall()
    conn.close()
    return {"categories": [dict(r) for r in rows]}


@api_router.post("/categories")
async def create_category(payload: CategoryIn, user: dict = Depends(current_user)):
    conn = get_db()
    doc_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO categories (id,user_id,name,kind,color,icon,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (doc_id, user["user_id"], payload.name, payload.kind, payload.color, payload.icon, now_utc().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"category": {"id": doc_id, **payload.dict()}}


@api_router.delete("/categories/{category_id}")
async def delete_category(category_id: str, user: dict = Depends(current_user)):
    conn = get_db()
    conn.execute("DELETE FROM categories WHERE id=%s AND user_id=%s", (category_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


# ---------------- companies ----------------
@api_router.get("/companies")
async def list_companies(user: dict = Depends(current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM companies WHERE user_id=%s", (user["user_id"],)).fetchall()
    conn.close()
    return {"companies": [dict(r) for r in rows]}


@api_router.post("/companies")
async def create_company(payload: CompanyIn, user: dict = Depends(current_user)):
    doc_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO companies (id,user_id,name,created_at) VALUES (%s,%s,%s,%s)",
        (doc_id, user["user_id"], payload.name, now_utc().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"company": {"id": doc_id, "name": payload.name}}


@api_router.delete("/companies/{company_id}")
async def delete_company(company_id: str, user: dict = Depends(current_user)):
    conn = get_db()
    conn.execute("DELETE FROM companies WHERE id=%s AND user_id=%s", (company_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


# ---------------- transactions ----------------
@api_router.get("/transactions")
async def list_transactions(user: dict = Depends(current_user), limit: int = 200, month: Optional[str] = None, company_id: Optional[str] = None):
    conn = get_db()
    if company_id:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE user_id=%s AND company_id=%s ORDER BY date DESC LIMIT %s",
            (user["user_id"], company_id, limit),
        ).fetchall()
    elif month:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE user_id=%s AND month=%s ORDER BY date DESC LIMIT %s",
            (user["user_id"], month, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE user_id=%s ORDER BY date DESC LIMIT %s",
            (user["user_id"], limit),
        ).fetchall()
    conn.close()
    return {"transactions": [dict(r) for r in rows]}


@api_router.post("/transactions")
async def create_transaction(payload: TransactionIn, user: dict = Depends(current_user)):
    date_str = payload.date or now_utc().isoformat()
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        dt = now_utc()
    month = dt.strftime("%Y-%m")
    doc_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO transactions (id,user_id,kind,amount,account_id,category_id,company_id,note,date,month,created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (doc_id, user["user_id"], payload.kind, payload.amount, payload.account_id,
         payload.category_id, payload.company_id, payload.note or "", dt.isoformat(), month, now_utc().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"transaction": {"id": doc_id, "date": dt.isoformat(), "month": month, **payload.dict()}}


@api_router.put("/transactions/{tx_id}")
async def update_transaction(tx_id: str, payload: TransactionIn, user: dict = Depends(current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM transactions WHERE id=%s AND user_id=%s", (tx_id, user["user_id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Transaction not found")
    date_str = payload.date or row["date"]
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.fromisoformat(row["date"])
    month = dt.strftime("%Y-%m")
    conn.execute(
        "UPDATE transactions SET kind=%s, amount=%s, account_id=%s, category_id=%s, company_id=%s, note=%s, date=%s, month=%s "
        "WHERE id=%s AND user_id=%s",
        (payload.kind, payload.amount, payload.account_id, payload.category_id, payload.company_id,
         payload.note or "", dt.isoformat(), month, tx_id, user["user_id"]),
    )
    conn.commit()
    conn.close()
    return {"transaction": {"id": tx_id, "date": dt.isoformat(), "month": month, **payload.dict()}}


@api_router.delete("/transactions/{tx_id}")
async def delete_transaction(tx_id: str, user: dict = Depends(current_user)):
    conn = get_db()
    conn.execute("DELETE FROM transactions WHERE id=%s AND user_id=%s", (tx_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


# ---------------- summary ----------------
@api_router.get("/summary")
async def summary(user: dict = Depends(current_user), month: Optional[str] = None):
    month = month or now_utc().strftime("%Y-%m")
    conn = get_db()
    income = conn.execute(
        "SELECT COALESCE(SUM(amount),0) t FROM transactions WHERE user_id=%s AND month=%s AND kind='income'",
        (user["user_id"], month),
    ).fetchone()["t"]
    expense = conn.execute(
        "SELECT COALESCE(SUM(amount),0) t FROM transactions WHERE user_id=%s AND month=%s AND kind='expense'",
        (user["user_id"], month),
    ).fetchone()["t"]

    cat_rows = conn.execute(
        "SELECT category_id, SUM(amount) t FROM transactions WHERE user_id=%s AND month=%s AND kind='expense' GROUP BY category_id",
        (user["user_id"], month),
    ).fetchall()
    cats = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM categories WHERE user_id=%s", (user["user_id"],)).fetchall()}
    by_category = []
    for r in cat_rows:
        meta = cats.get(r["category_id"], {"name": "Uncategorized", "color": "#4F5753"})
        by_category.append({"category_id": r["category_id"], "name": meta.get("name"), "color": meta.get("color"), "total": float(r["t"])})
    by_category.sort(key=lambda x: -x["total"])

    months_list = []
    base = now_utc().replace(day=1)
    for i in range(5, -1, -1):
        year, m = base.year, base.month - i
        while m <= 0:
            m += 12
            year -= 1
        months_list.append(f"{year:04d}-{m:02d}")
    monthly = {mm: {"income": 0.0, "expense": 0.0} for mm in months_list}
    placeholders = ",".join("%s" for _ in months_list)
    m_rows = conn.execute(
        f"SELECT month, kind, SUM(amount) t FROM transactions WHERE user_id=%s AND month IN ({placeholders}) GROUP BY month, kind",
        (user["user_id"], *months_list),
    ).fetchall()
    for r in m_rows:
        if r["month"] in monthly:
            monthly[r["month"]][r["kind"]] = float(r["t"])
    conn.close()
    monthly_series = [{"month": mm, **monthly[mm]} for mm in months_list]

    return {
        "month": month, "income": float(income), "expense": float(expense),
        "balance": float(income) - float(expense),
        "by_category": by_category, "monthly_series": monthly_series,
    }


# ---------------- splits ----------------
@api_router.get("/groups")
async def list_groups(user: dict = Depends(current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM groups WHERE user_id=%s", (user["user_id"],)).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["members"] = d["members"].split("|")
        out.append(d)
    return {"groups": out}


@api_router.post("/groups")
async def create_group(payload: GroupIn, user: dict = Depends(current_user)):
    members = list(dict.fromkeys([m.strip() for m in payload.members if m.strip()]))
    if not members:
        raise HTTPException(400, "At least one member required")
    if "You" not in members:
        members = ["You"] + members
    doc_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO groups (id,user_id,name,members,created_at) VALUES (%s,%s,%s,%s,%s)",
        (doc_id, user["user_id"], payload.name, "|".join(members), now_utc().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"group": {"id": doc_id, "name": payload.name, "members": members}}


@api_router.delete("/groups/{group_id}")
async def delete_group(group_id: str, user: dict = Depends(current_user)):
    conn = get_db()
    conn.execute("DELETE FROM groups WHERE id=%s AND user_id=%s", (group_id, user["user_id"]))
    conn.execute("DELETE FROM split_expenses WHERE group_id=%s AND user_id=%s", (group_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"ok": True}


@api_router.get("/groups/{group_id}")
async def get_group(group_id: str, user: dict = Depends(current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM groups WHERE id=%s AND user_id=%s", (group_id, user["user_id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Not found")
    group = dict(row)
    group["members"] = group["members"].split("|")
    exp_rows = conn.execute(
        "SELECT * FROM split_expenses WHERE group_id=%s AND user_id=%s ORDER BY date DESC",
        (group_id, user["user_id"]),
    ).fetchall()
    conn.close()
    expenses = []
    balances = {m: 0.0 for m in group["members"]}
    for r in exp_rows:
        e = dict(r)
        e["split_among"] = e["split_among"].split("|")
        expenses.append(e)
        splitters = e["split_among"]
        if not splitters:
            continue
        share = float(e["amount"]) / len(splitters)
        balances[e["paid_by"]] = balances.get(e["paid_by"], 0.0) + float(e["amount"])
        for s in splitters:
            balances[s] = balances.get(s, 0.0) - share
    return {"group": group, "expenses": expenses, "balances": balances, "your_net": balances.get("You", 0.0)}


@api_router.post("/groups/{group_id}/expenses")
async def add_split(group_id: str, payload: SplitExpenseIn, user: dict = Depends(current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM groups WHERE id=%s AND user_id=%s", (group_id, user["user_id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Group not found")
    members = row["members"].split("|")
    if payload.paid_by not in members:
        conn.close()
        raise HTTPException(400, "paid_by not in members")
    for s in payload.split_among:
        if s not in members:
            conn.close()
            raise HTTPException(400, f"{s} not in members")
    doc_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO split_expenses (id,user_id,group_id,description,amount,paid_by,split_among,date,created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (doc_id, user["user_id"], group_id, payload.description, payload.amount, payload.paid_by,
         "|".join(payload.split_among), payload.date or now_utc().isoformat(), now_utc().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"expense": {"id": doc_id, **payload.dict()}}


@api_router.delete("/groups/{group_id}/expenses/{expense_id}")
async def delete_split(group_id: str, expense_id: str, user: dict = Depends(current_user)):
    conn = get_db()
    conn.execute(
        "DELETE FROM split_expenses WHERE id=%s AND group_id=%s AND user_id=%s",
        (expense_id, group_id, user["user_id"]),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
