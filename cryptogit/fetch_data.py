from pathlib import Path
from typing import List, Tuple
import pandas as pd
import hashlib
import secrets
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = Path("data")
COIN_DATA_DIR = DATA_DIR / "coin_data"
USERS_FILE = DATA_DIR / "users.csv"
COINS_FILE = DATA_DIR / "coins.csv"

# hashing params
HASH_ALGO = "sha256"
PBKDF2_ITERS = 120_000
SALT_BYTES = 16


def _make_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac(HASH_ALGO, password.encode("utf-8"), salt, PBKDF2_ITERS)
    return base64.b64encode(dk).decode("utf-8")


def ensure_structure():
    DATA_DIR.mkdir(exist_ok=True)
    COIN_DATA_DIR.mkdir(exist_ok=True)
    if not COINS_FILE.exists():
        pd.DataFrame([
            {"symbol": "bitcoin", "name": "Bitcoin"},
            {"symbol": "ethereum", "name": "Ethereum"},
            {"symbol": "dogecoin", "name": "Dogecoin"},
        ]).to_csv(COINS_FILE, index=False)
        logger.info("Created default coins.csv")
    if not USERS_FILE.exists():
        # create default admin (admin/admin)
        salt = _make_salt()
        ph = _hash_password("admin", salt)
        df = pd.DataFrame([{"username": "admin", "password_hash": ph, "salt": base64.b64encode(salt).decode("utf-8"), "is_admin": True}])
        df.to_csv(USERS_FILE, index=False)
        logger.info("Created default users.csv with admin/admin (hashed)")
    # coin_data seeds are provided in data/coin_data if you saved them; ensure folder exists


ensure_structure()


# Users
def read_users() -> pd.DataFrame:
    df = pd.read_csv(USERS_FILE, dtype=str).fillna("")
    for c in ["username", "password_hash", "salt", "is_admin"]:
        if c not in df.columns:
            df[c] = ""
    df["is_admin"] = df["is_admin"].map(lambda v: v == "True" or v == "true" or v == "1")
    return df[["username", "password_hash", "salt", "is_admin"]]


def write_users(df: pd.DataFrame):
    out = df.copy()
    out["is_admin"] = out["is_admin"].astype(bool)
    out.to_csv(USERS_FILE, index=False)


def register_user(username: str, password: str, is_admin: bool = False) -> Tuple[bool, str]:
    username = username.strip()
    if not username:
        return False, "Username required."
    users = read_users()
    if username in users["username"].values:
        return False, "Username already exists."
    salt = _make_salt()
    password_hash = _hash_password(password, salt)
    new = {"username": username, "password_hash": password_hash, "salt": base64.b64encode(salt).decode("utf-8"), "is_admin": bool(is_admin)}
    users = pd.concat([users, pd.DataFrame([new])], ignore_index=True)
    write_users(users)
    return True, "Registered."


def authenticate_user(username: str, password: str) -> Tuple[bool, bool]:
    users = read_users()
    row = users[users["username"] == username]
    if row.empty:
        return False, False
    row = row.iloc[0]
    stored_hash = str(row["password_hash"])
    stored_salt = str(row["salt"]) if row["salt"] else ""
    is_admin = bool(row["is_admin"])

    def looks_like_base64(s: str) -> bool:
        try:
            base64.b64decode(s.encode("utf-8"))
            return True
        except Exception:
            return False

    if stored_salt and looks_like_base64(stored_hash):
        salt = base64.b64decode(stored_salt.encode("utf-8"))
        attempt = _hash_password(password, salt)
        if secrets.compare_digest(attempt, stored_hash):
            return True, is_admin
        return False, False
    else:
        # legacy plaintext stored in password_hash column
        if password == stored_hash:
            # upgrade to hashed form
            salt = _make_salt()
            password_hash = _hash_password(password, salt)
            users_df = read_users()
            users_df.loc[users_df["username"] == username, "password_hash"] = password_hash
            users_df.loc[users_df["username"] == username, "salt"] = base64.b64encode(salt).decode("utf-8")
            write_users(users_df)
            logger.info(f"Upgraded legacy user {username} to hashed password.")
            return True, is_admin
        return False, False


def list_users() -> List[str]:
    users = read_users()
    return users["username"].tolist()


# Coins
def get_all_coins() -> List[Tuple[str, str]]:
    if not COINS_FILE.exists():
        return []
    df = pd.read_csv(COINS_FILE)
    return list(zip(df["symbol"].astype(str), df["name"].astype(str)))


def add_new_coin(symbol: str, name: str) -> Tuple[bool, str]:
    symbol = symbol.strip().lower()
    name = name.strip()
    if not symbol or not name:
        return False, "Symbol and name required."
    coins = pd.read_csv(COINS_FILE) if COINS_FILE.exists() else pd.DataFrame(columns=["symbol", "name"])
    if symbol in coins["symbol"].values:
        return False, "Coin exists."
    coins = pd.concat([coins, pd.DataFrame([{"symbol": symbol, "name": name}])], ignore_index=True)
    coins.to_csv(COINS_FILE, index=False)
    # create empty coin data file
    path = COIN_DATA_DIR / f"{symbol}.csv"
    if not path.exists():
        pd.DataFrame(columns=["Time", "Price"]).to_csv(path, index=False)
    return True, "Coin added."


def remove_coin(symbol: str) -> Tuple[bool, str]:
    symbol = symbol.strip().lower()
    if not COINS_FILE.exists():
        return False, "No coins configured."
    coins = pd.read_csv(COINS_FILE)
    if symbol not in coins["symbol"].values:
        return False, "Not found."
    coins = coins[coins["symbol"] != symbol]
    coins.to_csv(COINS_FILE, index=False)
    # optionally remove coin data file
    path = COIN_DATA_DIR / f"{symbol}.csv"
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass
    return True, "Removed."


# Coin data (central)
def coin_data_filepath(symbol: str) -> Path:
    return COIN_DATA_DIR / f"{symbol}.csv"


def read_coin_data(symbol: str) -> pd.DataFrame:
    path = coin_data_filepath(symbol)
    if not path.exists():
        return pd.DataFrame(columns=["Time", "Price"])
    return pd.read_csv(path)


def add_coin_data(symbol: str, time_str: str, price: float) -> Tuple[bool, str]:
    """
    Append a Time,Price row to the central coin dataset (admin action).
    """
    path = coin_data_filepath(symbol)
    row = {"Time": time_str, "Price": float(price)}
    if path.exists():
        existing = pd.read_csv(path)
        combined = pd.concat([existing, pd.DataFrame([row])], ignore_index=True)
    else:
        combined = pd.DataFrame([row])
    try:
        combined["Time"] = pd.to_datetime(combined["Time"])
        combined = combined.sort_values("Time")
        combined["Time"] = combined["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    combined.to_csv(path, index=False)
    return True, "Data added."


def import_csv_to_coin(symbol: str, csv_path: str) -> Tuple[bool, str]:
    """
    Overwrite coin data with CSV (admin action). CSV must contain Time and Price.
    """
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        return False, f"Failed to read CSV: {e}"
    if "Time" not in df.columns or "Price" not in df.columns:
        return False, "CSV must contain Time and Price columns."
    try:
        df["Time"] = pd.to_datetime(df["Time"])
        df = df.sort_values("Time")
        df["Time"] = df["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
        df["Price"] = pd.to_numeric(df["Price"], errors="coerce")
        df = df.dropna(subset=["Price"])
    except Exception:
        df["Price"] = pd.to_numeric(df["Price"], errors="coerce")
        df = df.dropna(subset=["Price"])
    df.to_csv(coin_data_filepath(symbol), index=False)
    return True, "Coin data imported."