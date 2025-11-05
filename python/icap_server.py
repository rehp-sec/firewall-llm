# script2_monitoreo_contraseña.py
# ICAP REQMOD en modo MONITOREO (no bloquea): siempre ICAP 204 (passthrough)
# Multi-hilo (ThreadingMixIn) + debounce (QUIET_WINDOW/MAX_WAIT) + dedupe 24h + cooldown
# Envío de correo FINAL con el mismo formato del script 1
# Patrones múltiples de credenciales/PII/API keys/tokens (ver BLOCK_PATTERNS)

import collections, collections.abc  # noqa: F401
if not hasattr(collections, "Callable"):
    collections.Callable = collections.abc.Callable

from socketserver import ThreadingMixIn
from pyicap import BaseICAPRequestHandler, ICAPServer

import re
import gzip
import zlib
import time
import json
import smtplib
import ssl
import threading
import hashlib
import unicodedata
from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timezone, timedelta

try:
    import brotli  # type: ignore
    _HAS_BROTLI = True
except Exception:
    _HAS_BROTLI = False


# ========= Configuración =========

# Patrones múltiples (insensibles a mayúsculas por re.IGNORECASE)
BLOCK_PATTERNS = [
    # === Palabras clave genéricas (Español e Inglés) ===
    r"\bcontraseña\b",
    r"\bclave\b",
    r"\bpassword\b",
    r"\bpasswd\b",
    r"\bpassphrase\b",
    r"\bsecreto\b",
    r"\bsecret\b",
    r"\btoken\b",

    # === Claves de API y Tokens ===
    r"\bapi[-_ ]?key\b",
    r"\bx-api-key\b",
    r"\bauth[-_ ]?token\b",
    r"\baccess[-_ ]?token\b",
    r"\bclient[-_ ]?secret\b",
    r"authorization\s*:\s*bearer\s+[A-Za-z0-9_\-\.=]{20,}",  # Token Bearer
    r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",  # JWT (JSON Web Token)

    # === Formatos JSON/YAML comunes para credenciales ===
    r'"password"\s*:\s*".{4,}"',
    r'"pass(?:word)?"\s*:\s*".{4,}"',
    r'"secret"\s*:\s*".{4,}"',
    r'"api[_-]?key"\s*:\s*".{10,}"',
    r'"access[_-]?token"\s*:\s*".{10,}"',
    r'"refresh[_-]?token"\s*:\s*".{10,}"',
    r'"client[_-]?secret"\s*:\s*".{10,}"',

    # === Claves Privadas (SSH, PGP, etc.) ===
    r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",

    # === Claves de proveedores Cloud (AWS, Google, Azure, etc.) ===
    r"AKIA[0-9A-Z]{16}",                                           # AWS Access Key ID
    r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{38,40}",   # AWS Secret Key
    r"AIza[0-9A-Za-z\-_]{35}",                                      # Google API Key
    r"\bAccountKey=[A-Za-z0-9+/=]{20,}",                           # Azure Storage Account Key
    r"\bSharedAccessKey=[A-Za-z0-9+/=]{20,}",                      # Azure SAS Key

    # === Claves de servicios populares (Stripe, GitHub, Slack) ===
    r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}",                   # Stripe API Key
    r"gh[pousr]_[A-Za-z0-9]{36,}",                                 # GitHub Token
    r"xox[baprs]-[A-Za-z0-9-]{10,}",                               # Slack Token

    # === Cadenas de conexión a Bases de Datos (con usuario:pass) ===
    r"\bpostgres(?:ql)?://[^ \n\r]+:[^ \n\r]+@[^ \n\r]+",
    r"\bmysql://[^ \n\r]+:[^ \n\r]+@[^ \n\r]+",
    r"\bmongodb(?:\+srv)?:\/\/[^ \n\r]+:[^ \n\r]+@[^ \n\r]+",

    # === Información Personal (Chile) ===
    # RUT (Rol Único Tributario) con y sin puntos/guión
    r"\b(?:\d{1,2}\.\d{3}\.\d{3}-[\dkK])\b",                      # Formato: 12.345.678-K
    r"\b\d{7,8}-[\dkK]\b",                                        # Formato: 12345678-K

    # === Información Financiera (Tarjetas de crédito) ===
    r"\b4\d{12}(\d{3})?\b",                                       # Visa
    r"\b5[1-5]\d{14}\b",                                          # MasterCard
    r"\b3[47]\d{13}\b",                                           # American Express

    # === Otros datos personales ===
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",            # Email (puede ser muy ruidoso)
]

# El filtrado de dominios (GenAI/otros) se asume en Squid (ACL/adaptation_access)
BLOCK_HOSTS: Set[str] = set()

# Filtros previos
MIN_TEXT_LEN = 20
MAX_BODY_SCAN_BYTES = 256 * 1024  # no escanear cuerpos enormes (rendimiento)
ANALYTICS_HOST_SUBSTR = (
    "google-analytics", "analytics.", ".analytics.", "segment", "datadoghq",
    "sentry", "posthog", "mixpanel", "fullstory", "hotjar", "bugsnag",
    "detectportal", "amplitude"
)

# Ventanas/tiempos (segundos)
QUIET_WINDOW = 2.0                 # inactividad para FINAL (rápido)
MAX_WAIT = 8.0                     # corte de ráfaga
WORKER_TICK = 0.25                 # revisión frecuente (bajo impacto)
DEDUP_TTL_SEC = 24 * 3600          # dedupe global del contenido FINAL
EARLY_MIN_LEN = 8                  # (no se usa para envío)
EARLY_COOLDOWN_SEC = 30.0          # (no se usa)
FINAL_COOLDOWN_SEC = 45.0          # 1 FINAL por dominio+patrón cada 45s
EMAIL_TEXT_LIMIT = 20000           # máx. caracteres en el correo

# Zona horaria (para mostrar fecha/hora local)
try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo("America/Santiago")
except Exception:
    LOCAL_TZ = timezone(timedelta(hours=-3))  # fallback

# ====== SMTP (formato de envío igual al script 1) ======
SMTP_HOST = "in-v3.mailjet.com"
SMTP_PORT = 587
SMTP_USER = "ce476ee29f90a8780a68d299b5799d69"
SMTP_PASSWORD = "e73ebe46f06b6aa18b6c0a62c4c8b6f0"
ALERT_FROM = "herrerapraul@gmail.com"  # remitente validado
ALERT_TO = [
    "herrerapraul@gmail.com",
    "guillermogurvich@gmail.com",
]
EMAIL_SUBJECT_PREFIX = "[ICAP ALERT]"

# ========= Estado (memoria) =========

_rx_compiled = [(pat, re.compile(pat, re.IGNORECASE)) for pat in BLOCK_PATTERNS]
_buckets_lock = threading.Lock()
_dedupe_lock = threading.Lock()
_cooldown_lock = threading.Lock()

class Bucket:
    __slots__ = ("first_ts", "last_seen_ts", "best_text", "best_len",
                 "patterns", "regdom", "count", "early_sent", "early_hash",
                 "src_ips")
    def __init__(self, regdom: str):
        now = time.time()
        self.first_ts = now
        self.last_seen_ts = now
        self.best_text = ""
               self.best_len = 0
        self.patterns: Set[str] = set()
        self.regdom = regdom
        self.count = 0
        self.early_sent = False
        self.early_hash = ""
        # Conjunto de IPs de origen (TCP y/o X-Forwarded-For)
        self.src_ips: Set[str] = set()

# Buckets por session_key
SESSION_BUCKETS: Dict[str, Bucket] = {}

# Dedupe global por hash canónico del **texto** (para FINAL)
DEDUP_CACHE: Dict[str, float] = {}

# Cooldown por (tipo, key) -> ts  — solo usamos "final"
COOLDOWN: Dict[Tuple[str, str], float] = {}

# ========= Utilidades =========

def log(msg: str) -> None:
    print(msg, flush=True)

def registrable_domain(host: Optional[str]) -> str:
    if not host:
        return ""
    h = host.lower().strip()
    if ":" in h:
        h = h.split(":", 1)[0]
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    sld = {"co.uk", "org.uk", "ac.uk", "com.au", "com.br", "com.ar", "gob.cl"}
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in sld:
        return ".".join(parts[-3:])
    if last3 in sld:
        return ".".join(parts[-4:])
    return ".".join(parts[-2:])

def norm_headers(hdrs) -> Dict[str, List[str]]:
    if not hdrs:
        return {}
    out: Dict[str, List[str]] = {}
    for k, vals in hdrs.items():
        if isinstance(k, bytes):
            k = k.decode("utf-8", "ignore")
        k = k.lower()
        vlist: List[str] = []
        for v in vals:
            if isinstance(v, bytes):
                v = v.decode("utf-8", "ignore")
            vlist.append(v)
        out[k] = vlist
    return out

def _decompress_if_needed(body: bytes, headers: Dict[str, List[str]]) -> Tuple[bytes, str]:
    enc = (headers.get("content-encoding", ["identity"]) or ["identity"])[0].lower().strip()
    if enc == "gzip":
        try:
            return gzip.decompress(body), "gzip"
        except Exception:
            try:
                return zlib.decompress(body, 16 + zlib.MAX_WBITS), "gzip"
            except Exception:
                return body, "identity"
    elif enc == "deflate":
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                return zlib.decompress(body, wbits), "deflate"
            except Exception:
                pass
        return body, "identity"
    elif enc == "br":
        if _HAS_BROTLI:
            try:
                return brotli.decompress(body), "br"
            except Exception:
                return body, "identity"
        else:
            return body, "identity"
    else:
        return body, "identity"

def _canonicalize_text_for_hash(text: str) -> str:
    s = text.lower()
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"\d+", "0", s)            # números → "0"
    s = re.sub(r"\s+", " ", s).strip()    # colapsar espacios
    return s

def _hash_alert(text: str) -> str:
    can = _canonicalize_text_for_hash(text)
    return hashlib.sha1(can.encode("utf-8", "ignore")).hexdigest()[:12]

def _looks_like_analytics_json(obj: object) -> bool:
    if isinstance(obj, dict):
        t = str(obj.get("type", "")).lower()
        if t in ("track", "page", "identify", "group"):
            return True
        if "analytics.js" in json.dumps(obj.get("context", {})).lower():
            return True
        if "segment.io" in json.dumps(obj.get("integrations", {})).lower():
            return True
    return False

def _should_inspect_host(host: Optional[str]) -> bool:
    if not host:
        return False
    # El filtrado de dominios (GenAI, etc.) se asume en Squid
    if BLOCK_HOSTS and host.lower() not in BLOCK_HOSTS:
        return False
    h = host.lower()
    for bad in ANALYTICS_HOST_SUBSTR:
        if bad in h:
            return False
    return True

def _client_ip24(ip: Optional[str]) -> str:
    if not ip:
        return ""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return ip

def _session_key(host: str, hdrs: Dict[str, List[str]], client_ip: Optional[str]) -> str:
    regdom = registrable_domain(host)
    cookie = (hdrs.get("cookie", [""]) or [""])[0]
    ua = (hdrs.get("user-agent", [""]) or [""])[0]
    auth = (hdrs.get("authorization", [""]) or [""])[0]
    did = (hdrs.get("oai-device-id", [""]) or [""])[0]
    if not did:
        m = re.search(r"oai-did=([^;]+)", cookie)
        if m:
            did = m.group(1)
    user_id = ""
    m = re.search(r"user-?id=([^;]+)", cookie)
    if m:
        user_id = m.group(1)
    ua_h = hashlib.md5(ua.encode("utf-8", "ignore")).hexdigest()[:8] if ua else ""
    auth_h = hashlib.md5(auth.encode("utf-8", "ignore")).hexdigest()[:8] if auth else ""
    ip24 = _client_ip24(client_ip or "")
    ident = did or user_id or auth_h or ip24
    return f"{regdom}|{ident}|{ua_h}"

def _compile_patterns():
    return _rx_compiled

COMPILED_PATS = _compile_patterns()

def _find_patterns(text: str) -> Set[str]:
    hits: Set[str] = set()
    for pat_str, rx in COMPILED_PATS:
        if rx.search(text):
            hits.add(pat_str)
    return hits

def _maybe_unescape_json_string(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        try:
            return json.loads(s)
        except Exception:
            return s
    return s

def _extract_candidate_text(raw_text: str) -> str:
    """
    Devuelve TEXTO PLANO con prioridad a prompts:
      - input_text, prompt
      - messages[*].content (role=user)
      - parts (strings)
    Evita payloads analytics (Segment, etc.). Si no hay nada útil, devuelve "".
    ***IMPORTANTE***: NO hacemos fallback a raw JSON si esto queda vacío.
    """
    s = raw_text.strip()
    if not s:
        return ""
    # si no parece JSON, devolvemos tal cual (ya es texto)
    if not (s.startswith("{") or s.startswith("[")):
        return s

    try:
        data = json.loads(s)
    except Exception:
        return s

    if _looks_like_analytics_json(data):
        return ""  # ignorar analytics

    collected: List[str] = []

    def collect(obj):
        if isinstance(obj, dict):
            # preferidos
            for k in ("input_text", "prompt"):
                if k in obj and isinstance(obj[k], str):
                    collected.append(obj[k])
            # OpenAI-style messages
            if "messages" in obj and isinstance(obj["messages"], list):
                for m in obj["messages"]:
                    if isinstance(m, dict):
                        role = m.get("role", "")
                        if role == "user":
                            c = m.get("content")
                            if isinstance(c, str):
                                collected.append(c)
                            elif isinstance(c, list):
                                for it in c:
                                    if isinstance(it, dict) and it.get("type") == "text" and isinstance(it.get("text"), str):
                                        collected.append(it["text"])
            # parts (ChatGPT web)
            if "parts" in obj and isinstance(obj["parts"], list):
                for p in obj["parts"]:
                    if isinstance(p, str):
                        collected.append(p)
            # recorrer profundidad
            for v in obj.values():
                collect(v)
        elif isinstance(obj, list):
            for it in obj:
                collect(it)

    collect(data)
    # priorizamos el string más largo (probable prompt completo)
    collected = [t for t in collected if isinstance(t, str) and t.strip()]
    if not collected:
        return ""
    collected.sort(key=len, reverse=True)
    return _maybe_unescape_json_string(collected[0])

def _send_email(subject: str, body_text: str) -> None:
    # Forma de envío como en script 1
    if not SMTP_USER or not SMTP_PASSWORD:
        log("[icap] SMTP deshabilitado: falta SMTP_USER/SMTP_PASSWORD")
        return
    msg = EmailMessage()
    msg["Subject"] = subject.replace("\r", " ").replace("\n", " ")
    msg["From"] = ALERT_FROM
    msg["To"] = ", ".join(ALERT_TO)
    msg.set_content(body_text)
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
        s.ehlo()
        s.starttls(context=context)
        s.login(SMTP_USER, SMTP_PASSWORD)
        s.send_message(msg)

def _now_str_local() -> str:
    return datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %z")

# ========= Buckets y workers =========

def _accept_for_analysis(headers: Dict[str, List[str]], host: str, raw_text: str, cand_text: str) -> bool:
    if not _should_inspect_host(host):
        return False
    # Content-Type
    ctype = (headers.get("content-type", [""]) or [""])[0].lower()
    if ctype and not (ctype.startswith("application/json") or ctype.startswith("text/")):
        return False
    # limitar tamaño a inspeccionar (rendimiento)
    if len(raw_text) > MAX_BODY_SCAN_BYTES:
        return False
    # longitud mínima ***SOLO candidate_text*** (NO hay fallback a raw_text)
    if len(cand_text.strip()) < MIN_TEXT_LEN:
        return False
    return True

def _update_bucket(session_key: str, regdom: str, text: str, hits: Set[str], src_ips: Optional[Set[str]] = None) -> None:
    now = time.time()
    with _buckets_lock:
        b = SESSION_BUCKETS.get(session_key)
        if b is None:
            b = Bucket(regdom)
            SESSION_BUCKETS[session_key] = b
        b.last_seen_ts = now
        b.count += 1
        if len(text) > b.best_len:
            b.best_text = text
            b.best_len = len(text)
        b.patterns.update(hits)
        if src_ips:
            for ip in src_ips:
                ip = (ip or "").strip()
                if ip:
                    b.src_ips.add(ip)

def _cooldown_allowed(kind: str, key: str, window_sec: float) -> bool:
    now = time.time()
    with _cooldown_lock:
        ts = COOLDOWN.get((kind, key), 0.0)
        if ts and (now - ts) < window_sec:
            return False
        COOLDOWN[(kind, key)] = now
        # limpieza ligera (opcional si crece mucho)
        if len(COOLDOWN) > 5000:
            cutoff = now - max(EARLY_COOLDOWN_SEC, FINAL_COOLDOWN_SEC) * 2
            for k in list(COOLDOWN.keys()):
                if COOLDOWN[k] < cutoff:
                    del COOLDOWN[k]
    return True

def _format_email(kind: str, regdom: str, patterns: List[str], text: str, alert_hash: Optional[str], bucket: Bucket) -> Tuple[str, str]:
    """
    kind ∈ {"PRELIMINAR", "FINAL"} — Solo usamos "FINAL".
    Formato idéntico al script 1 (incluye hash e IPs).
    """
    pat_main = patterns[0] if patterns else "patrón"
    plus = f" (+{len(patterns)-1})" if len(patterns) > 1 else ""
    subject = f"{EMAIL_SUBJECT_PREFIX} {kind} · {regdom or 'desconocido'} · {pat_main}{plus}"

    txt = text.strip()
    if len(txt) > EMAIL_TEXT_LIMIT:
        txt = txt[:EMAIL_TEXT_LIMIT] + "\n[...truncado...]"

    hash_line = f"Hash alerta: {alert_hash}\n" if alert_hash else ""

    src_ip_line = "IP(s) de origen: "
    if bucket.src_ips:
        src_ip_line += ", ".join(sorted(bucket.src_ips)) + "\n"
    else:
        src_ip_line += "desconocida\n"

    body = (
        f"Alerta ICAP – Posible filtración de información confidencial ({kind})\n\n"
        f"Fecha/Hora: {_now_str_local()}\n"
        f"Dominio solicitado: {regdom or 'desconocido'}\n"
        f"{src_ip_line}"
        f"{hash_line}"
        f"Patrones activados ({len(patterns)}):\n" +
        "".join([f" - {p}\n" for p in patterns]) +
        "\nTexto detectado (PLANO):\n"
        "----------------------------------------\n"
        f"{txt}\n"
        "----------------------------------------\n\n"
    )

    if kind == "FINAL":
        dur = max(0.0, time.time() - bucket.first_ts)
        body += "Alerta ICAP\n"

    return subject, body

def _flush_worker():
    while True:
        time.sleep(WORKER_TICK)
        now = time.time()
        to_finalize: List[Tuple[str, Bucket]] = []

        # Recolectar FINAL sin bloquear el loop ICAP
        with _buckets_lock:
            for sk, b in list(SESSION_BUCKETS.items()):
                idle = now - b.last_seen_ts
                span = now - b.first_ts
                if (idle >= QUIET_WINDOW) or (span >= MAX_WAIT):
                    to_finalize.append((sk, b))

        # Enviar SOLO FINAL (sin PRELIMINAR)
        for sk, b in to_finalize:
            regdom = b.regdom or "desconocido"
            text = b.best_text or ""
            if not text or not b.patterns:
                with _buckets_lock:
                    SESSION_BUCKETS.pop(sk, None)
                continue

            alert_hash = _hash_alert(text)

            # DEDUPE global 24h del contenido FINAL
            with _dedupe_lock:
                prev = DEDUP_CACHE.get(alert_hash)
                if prev and (now - prev) < DEDUP_TTL_SEC:
                    log(f"[icap] FINAL suprimido por dedupe (hash={alert_hash})")
                    with _buckets_lock:
                        SESSION_BUCKETS.pop(sk, None)
                    continue

            pats = sorted(b.patterns)

            # Cooldown FINAL por (regdom + patrón principal)
            cd_key = f"{regdom}:{pats[0]}"
            if not _cooldown_allowed("final", cd_key, FINAL_COOLDOWN_SEC):
                log("[icap] FINAL suprimido por cooldown (dominio+patrón)")
                with _buckets_lock:
                    SESSION_BUCKETS.pop(sk, None)
                continue

            # Enviar correo FINAL
            subject, body = _format_email("FINAL", regdom, pats, text, alert_hash, b)
            try:
                _send_email(subject, body)
                with _dedupe_lock:
                    DEDUP_CACHE[alert_hash] = time.time()
                    if len(DEDUP_CACHE) > 10000:
                        cutoff = time.time() - DEDUP_TTL_SEC
                        for k in list(DEDUP_CACHE.keys()):
                            if DEDUP_CACHE[k] < cutoff:
                                del DEDUP_CACHE[k]
                log("[icap] alerta FINAL enviada por correo")
            except Exception as e:
                log(f"[icap] error al enviar FINAL: {e!r}")
            finally:
                with _buckets_lock:
                    SESSION_BUCKETS.pop(sk, None)

# Lanza el worker en background
_worker_started = False
def _ensure_worker():
    global _worker_started
    if _worker_started:
        return
    th = threading.Thread(target=_flush_worker, daemon=True)
    th.start()
    _worker_started = True

# ========= Handler =========

def _first_xff_ip(hdrs: Dict[str, List[str]]) -> Optional[str]:
    """
    Retorna la primera IP de X-Forwarded-For si existe, limpiando espacios.
    """
    xff_vals = hdrs.get("x-forwarded-for", []) or []
    if not xff_vals:
        return None
    first_hdr = (xff_vals[0] or "").strip()
    if not first_hdr:
        return None
    first_ip = first_hdr.split(",")[0].strip()
    return first_ip or None

class ICAPHandler(BaseICAPRequestHandler):
    # ----- OPTIONS -----
    def _send_options(self, service_name: bytes):
        self.set_icap_response(200)
        self.set_icap_header(b"Methods", b"REQMOD, RESPMOD")
        self.set_icap_header(b"Service", service_name)
        self.set_icap_header(b"ISTag", b"v1")
        self.set_icap_header(b"Allow", b"204")
        self.set_icap_header(b"Preview", b"1024")
        self.send_headers(False)

    def reqmod_OPTIONS(self):
        log("[icap] /reqmod OPTIONS")
        self._send_options(b"ICAP REQMOD (async, debounce, FINAL only)")

    def respmod_OPTIONS(self):
        log("[icap] /respmod OPTIONS")
        self._send_options(b"ICAP RESPMOD (passthrough)")

    # ----- REQMOD (MONITOREO: ICAP 204; SIN BLOQUEO; SIN FALLBACK A RAW) -----
    def reqmod_REQMOD(self):
        _ensure_worker()

        enc_req_headers = norm_headers(getattr(self, "enc_req_headers", None))
        req_headers = norm_headers(getattr(self, "req_headers", None))
        hdrs = enc_req_headers or req_headers or {}

        host = (hdrs.get("host", [""]) or [""])[0]
        client_ip_tcp = None
        try:
            client_ip_tcp = self.client_address[0]
        except Exception:
            client_ip_tcp = None

        xff_ip = _first_xff_ip(hdrs)

        # Leer cuerpo (maneja preview internamente)
        body = b""
        if self.has_body:
            while True:
                chunk = self.read_chunk()
                if not chunk:
                    break
                body += chunk

        # Descomprimir/decodificar
        body_dec, _ = _decompress_if_needed(body, hdrs)
        raw_text = body_dec.decode("utf-8", errors="ignore")

        # Extraer PROMPT plano (SIN fallback a raw si queda vacío)
        candidate_text = _extract_candidate_text(raw_text)

        # Filtros + detección SOLO sobre candidate_text
        if _accept_for_analysis(hdrs, host, raw_text, candidate_text):
            hits = _find_patterns(candidate_text)
            if hits:
                regdom = registrable_domain(host)
                sk = _session_key(host, hdrs, client_ip_tcp)
                src_ips: Set[str] = set()
                if client_ip_tcp:
                    src_ips.add(client_ip_tcp)
                if xff_ip:
                    src_ips.add(xff_ip)

                _update_bucket(sk, regdom, candidate_text, hits, src_ips=src_ips)
                log(f"[icap] /reqmod HIT host={host!r} patt={len(hits)} sess={sk[:16]}... len={len(candidate_text)}")

        # Passthrough: nunca bloquea (ICAP 204)
        self.set_icap_response(204)
        try:
            self.send_headers(False)
        except ConnectionResetError:
            log("[icap] peer cerró la conexión al enviar headers (REQMOD). Ignorando.")

    # ----- RESPMOD -----
    def respmod_RESPMOD(self):
        self.set_icap_response(204)
        try:
            self.send_headers(False)
        except ConnectionResetError:
            log("[icap] peer cerró la conexión al enviar headers (RESPMOD). Ignorando.")


# ========= Main =========
class ThreadedICAPServer(ThreadingMixIn, ICAPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    log("[icap] Iniciando SERVIDOR MULTI-HILO (monitoreo, passthrough 204, FINAL-only) 0.0.0.0:1344 ...")
    _ensure_worker()
    ThreadedICAPServer(("", 1344), ICAPHandler).serve_forever()
