"""Tool registry and configuration for the fingerprinting harness."""

from dataclasses import dataclass, field

HARNESS_NETWORK = "harness-net"
HARNESS_SUBNET = "172.30.0.0/24"
HONEYPOT_IP = "172.30.0.2"
HONEYPOT_PORT = 8443
TARGET_URL = f"https://{HONEYPOT_IP}:{HONEYPOT_PORT}"

# Ollama LLM sidecar for cat6-llm-local tools
OLLAMA_IP = "172.30.0.3"
OLLAMA_PORT = 11434
OLLAMA_MODEL = "llama3.1:8b"
OLLAMA_IMAGE = "ollama/ollama:latest"
OLLAMA_CONTAINER = "harness-ollama"


@dataclass
class ToolSpec:
    name: str
    category: str
    dockerfile: str  # relative to harness/tools/
    scan_command: list[str]  # {target_url}, {target_ip}, {target_host}, {target_port} are substituted
    static_ip: str  # on harness-net
    timeout_seconds: int = 120
    needs_wordlist: bool = False
    version_command: list[str] = field(default_factory=list)
    target_mode: str = "url"  # url | ip | host_port
    notes: str = ""
    needs_ollama: bool = False  # requires Ollama sidecar on harness-net
    llm_provider: str = ""  # ollama | openai | anthropic | etc.
    llm_env_vars: dict[str, str] = field(default_factory=dict)  # injected into container


# IP assignments: 172.30.0.2 = honeypot, 172.30.0.3 = ollama, 172.30.0.10+ = tools
# Cat 1: .10-.20, Cat 2: .30-.39, Cat 3: .40-.49, Cat 4: .50-.59, Cat 5: .60-.69
# Cat 6: .70-.79 (LLM-local/Ollama), Cat 7: .80-.89 (LLM-cloud API)

TOOL_REGISTRY: dict[str, ToolSpec] = {
    # --- Built-in validation tool (no Dockerfile needed) ---
    "curl": ToolSpec(
        name="curl",
        category="validation",
        dockerfile="",  # uses host curl via docker run
        scan_command=[
            "curl", "-sk", "{target_url}/", "-o", "/dev/null", "-w", "%{http_code}",
        ],
        static_ip="172.30.0.100",
        timeout_seconds=30,
        version_command=["curl", "--version"],
        notes="Validation tool — uses the curl image to verify pipeline end-to-end",
    ),

    # --- Category 1: Web scanners ---
    "nikto": ToolSpec(
        name="nikto",
        category="cat1-scanners",
        dockerfile="nikto.Dockerfile",
        scan_command=["nikto", "-h", "{target_url}", "-ssl", "-nointeractive", "-maxtime", "60s"],
        static_ip="172.30.0.10",
        timeout_seconds=90,
        version_command=["nikto", "-Version"],
    ),
    "dirb": ToolSpec(
        name="dirb",
        category="cat1-scanners",
        dockerfile="dirb.Dockerfile",
        scan_command=["dirb", "{target_url}/", "/wordlists/common.txt", "-S", "-a", "Mozilla/5.0"],
        static_ip="172.30.0.11",
        timeout_seconds=120,
        needs_wordlist=True,
        version_command=["dirb", "2>&1", "|", "head", "-1"],
    ),
    "dirsearch": ToolSpec(
        name="dirsearch",
        category="cat1-scanners",
        dockerfile="dirsearch.Dockerfile",
        scan_command=["dirsearch", "-u", "{target_url}", "--no-color", "-t", "5"],
        static_ip="172.30.0.12",
        timeout_seconds=120,
        version_command=["dirsearch", "--version"],
    ),
    "gobuster": ToolSpec(
        name="gobuster",
        category="cat1-scanners",
        dockerfile="gobuster.Dockerfile",
        scan_command=[
            "gobuster", "dir", "-u", "{target_url}", "-w", "/wordlists/common.txt",
            "-k", "-q", "-t", "5",
        ],
        static_ip="172.30.0.13",
        timeout_seconds=120,
        needs_wordlist=True,
        version_command=["gobuster", "version"],
    ),
    "ffuf": ToolSpec(
        name="ffuf",
        category="cat1-scanners",
        dockerfile="ffuf.Dockerfile",
        scan_command=[
            "ffuf", "-u", "{target_url}/FUZZ", "-w", "/wordlists/common.txt",
            "-mc", "all", "-t", "5", "-s",
        ],
        static_ip="172.30.0.14",
        timeout_seconds=120,
        needs_wordlist=True,
        version_command=["ffuf", "-V"],
    ),
    "feroxbuster": ToolSpec(
        name="feroxbuster",
        category="cat1-scanners",
        dockerfile="feroxbuster.Dockerfile",
        scan_command=[
            "feroxbuster", "-u", "{target_url}", "-w", "/wordlists/common.txt",
            "-k", "-q", "-t", "5", "--time-limit", "60s",
        ],
        static_ip="172.30.0.15",
        timeout_seconds=90,
        needs_wordlist=True,
        version_command=["feroxbuster", "--version"],
    ),
    "wpscan": ToolSpec(
        name="wpscan",
        category="cat1-scanners",
        dockerfile="wpscan.Dockerfile",
        scan_command=[
            "wpscan", "--url", "{target_url}", "--disable-tls-checks",
            "--detection-mode", "passive", "--max-threads", "5",
        ],
        static_ip="172.30.0.16",
        timeout_seconds=120,
        version_command=["wpscan", "--version"],
    ),
    "sqlmap": ToolSpec(
        name="sqlmap",
        category="cat1-scanners",
        dockerfile="sqlmap.Dockerfile",
        scan_command=[
            "sqlmap", "-u", "{target_url}/api/v1/users?id=1",
            "--batch", "--level=1", "--risk=1", "--timeout=10",
        ],
        static_ip="172.30.0.17",
        timeout_seconds=120,
        version_command=["sqlmap", "--version"],
    ),
    "testssl": ToolSpec(
        name="testssl",
        category="cat1-scanners",
        dockerfile="testssl.Dockerfile",
        scan_command=["testssl.sh", "--quiet", "--fast", "{target_ip}:{target_port}"],
        static_ip="172.30.0.18",
        timeout_seconds=180,
        target_mode="host_port",
        version_command=["testssl.sh", "--version"],
        notes="Generates many TLS handshakes with different cipher configurations",
    ),
    "sslscan": ToolSpec(
        name="sslscan",
        category="cat1-scanners",
        dockerfile="sslscan.Dockerfile",
        scan_command=["sslscan", "--no-colour", "{target_ip}:{target_port}"],
        static_ip="172.30.0.19",
        timeout_seconds=60,
        target_mode="host_port",
        version_command=["sslscan", "--version"],
    ),
    "sslyze": ToolSpec(
        name="sslyze",
        category="cat1-scanners",
        dockerfile="sslyze.Dockerfile",
        scan_command=["sslyze", "{target_ip}:{target_port}"],
        static_ip="172.30.0.20",
        timeout_seconds=120,
        target_mode="host_port",
        version_command=["sslyze", "--version"],
    ),

    # --- Category 2: Recon ---
    "httpx": ToolSpec(
        name="httpx",
        category="cat2-recon",
        dockerfile="httpx.Dockerfile",
        scan_command=["sh", "-c", "echo '{target_url}' | httpx -silent -follow-redirects -tls-grab"],
        static_ip="172.30.0.30",
        timeout_seconds=60,
        version_command=["httpx", "-version"],
    ),
    "katana": ToolSpec(
        name="katana",
        category="cat2-recon",
        dockerfile="katana.Dockerfile",
        scan_command=["katana", "-u", "{target_url}", "-silent", "-depth", "2", "-jc"],
        static_ip="172.30.0.31",
        timeout_seconds=120,
        version_command=["katana", "-version"],
    ),

    # --- Category 3: Browser automation ---
    "playwright-chromium": ToolSpec(
        name="playwright-chromium",
        category="cat3-browsers",
        dockerfile="playwright.Dockerfile",
        scan_command=["python3", "/scripts/run-playwright.py", "{target_url}", "chromium"],
        static_ip="172.30.0.40",
        timeout_seconds=60,
        version_command=["python3", "-c", "import playwright; print(playwright.__version__)"],
    ),
    "playwright-firefox": ToolSpec(
        name="playwright-firefox",
        category="cat3-browsers",
        dockerfile="playwright.Dockerfile",
        scan_command=["python3", "/scripts/run-playwright.py", "{target_url}", "firefox"],
        static_ip="172.30.0.41",
        timeout_seconds=60,
    ),
    "playwright-webkit": ToolSpec(
        name="playwright-webkit",
        category="cat3-browsers",
        dockerfile="playwright.Dockerfile",
        scan_command=["python3", "/scripts/run-playwright.py", "{target_url}", "webkit"],
        static_ip="172.30.0.42",
        timeout_seconds=60,
    ),
    "puppeteer": ToolSpec(
        name="puppeteer",
        category="cat3-browsers",
        dockerfile="puppeteer.Dockerfile",
        scan_command=["node", "/scripts/run-puppeteer.js", "{target_url}"],
        static_ip="172.30.0.43",
        timeout_seconds=60,
        version_command=["node", "-e", "console.log(require('puppeteer/package.json').version)"],
    ),
    "selenium-chrome": ToolSpec(
        name="selenium-chrome",
        category="cat3-browsers",
        dockerfile="selenium-chrome.Dockerfile",
        scan_command=["python3", "/scripts/run-selenium.py", "{target_url}", "chrome"],
        static_ip="172.30.0.44",
        timeout_seconds=60,
    ),
    "selenium-firefox": ToolSpec(
        name="selenium-firefox",
        category="cat3-browsers",
        dockerfile="selenium-firefox.Dockerfile",
        scan_command=["python3", "/scripts/run-selenium.py", "{target_url}", "firefox"],
        static_ip="172.30.0.45",
        timeout_seconds=60,
    ),

    # --- Category 4: Evasion ---
    "curl-impersonate-chrome": ToolSpec(
        name="curl-impersonate-chrome",
        category="cat4-evasion",
        dockerfile="curl-impersonate-chrome.Dockerfile",
        scan_command=["curl_chrome110", "-sk", "{target_url}/", "-o", "/dev/null", "-w", "%{http_code}"],
        static_ip="172.30.0.50",
        timeout_seconds=30,
        version_command=["curl_chrome110", "--version"],
    ),
    "curl-impersonate-firefox": ToolSpec(
        name="curl-impersonate-firefox",
        category="cat4-evasion",
        dockerfile="curl-impersonate-firefox.Dockerfile",
        scan_command=["curl_ff117", "-sk", "{target_url}/", "-o", "/dev/null", "-w", "%{http_code}"],
        static_ip="172.30.0.51",
        timeout_seconds=30,
        version_command=["curl_ff117", "--version"],
    ),

    # --- Category 5: Vuln scanners ---
    "zap": ToolSpec(
        name="zap",
        category="cat5-vulnscanners",
        dockerfile="zap.Dockerfile",
        scan_command=[
            "zap-baseline.py", "-t", "{target_url}", "-I",
        ],
        static_ip="172.30.0.60",
        timeout_seconds=300,
        version_command=["zap.sh", "-version"],
    ),
    # arachni removed — project abandoned since 2021, GitHub release downloads broken

    # --- Category 6: LLM-powered (local/Ollama) ---
    "pentest-swarm-ai": ToolSpec(
        name="pentest-swarm-ai",
        category="cat6-llm-local",
        dockerfile="pentest-swarm-ai.Dockerfile",
        scan_command=[
            "sh", "/scripts/run-pentest-swarm-ai.sh",
        ],
        static_ip="172.30.0.70",
        timeout_seconds=600,
        needs_ollama=True,
        llm_provider="ollama",
        llm_env_vars={
            "OLLAMA_HOST": f"http://{OLLAMA_IP}:{OLLAMA_PORT}",
            "TARGET_URL": "{target_url}",
            "TARGET_IP": "{target_ip}",
        },
        version_command=["pentestswarm", "--version"],
        notes="Go multi-agent swarm, native HTTP to target. Go crypto/tls fingerprint.",
    ),
    "hackingbuddygpt": ToolSpec(
        name="hackingbuddygpt",
        category="cat6-llm-local",
        dockerfile="hackingbuddygpt.Dockerfile",
        scan_command=[
            "sh", "/scripts/run-hackingbuddygpt.sh",
        ],
        static_ip="172.30.0.71",
        timeout_seconds=600,
        needs_ollama=True,
        llm_provider="ollama",
        llm_env_vars={
            "TARGET_URL": "{target_url}",
            "LLM_MODEL": f"ollama_chat/{OLLAMA_MODEL}",
            "LLM_API_BASE": f"http://{OLLAMA_IP}:{OLLAMA_PORT}/v1",
            "LLM_API_KEY": "dummy",
            "MAX_ROUNDS": "30",
            "OLLAMA_HOST": f"http://{OLLAMA_IP}:{OLLAMA_PORT}",
            "OLLAMA_API_BASE": f"http://{OLLAMA_IP}:{OLLAMA_PORT}",
        },
        version_command=["wintermute", "--help"],
        notes="Python httpx, LiteLLM. WebAPITesting mode makes direct HTTP to target.",
    ),

    # --- Category 7: LLM-powered (cloud API) ---
    "strix": ToolSpec(
        name="strix",
        category="cat7-llm-cloud",
        dockerfile="strix.Dockerfile",
        scan_command=[
            "strix", "scan", "{target_url}",
        ],
        static_ip="172.30.0.80",
        timeout_seconds=600,
        llm_provider="openai",
        llm_env_vars={"OPENAI_API_KEY": "{OPENAI_API_KEY}"},
        notes="Python/TS, OpenAI. 36k+ stars. AWS-only (needs internet for API).",
    ),
    "rogue": ToolSpec(
        name="rogue",
        category="cat7-llm-cloud",
        dockerfile="rogue.Dockerfile",
        scan_command=[
            "python3", "/opt/rogue/main.py", "--target", "{target_url}",
        ],
        static_ip="172.30.0.81",
        timeout_seconds=600,
        llm_provider="openai",
        llm_env_vars={"OPENAI_API_KEY": "{OPENAI_API_KEY}"},
        notes="Python + Playwright/Chromium. Browser fingerprint + Python fingerprint.",
    ),
    "pentestgpt": ToolSpec(
        name="pentestgpt",
        category="cat7-llm-cloud",
        dockerfile="pentestgpt.Dockerfile",
        scan_command=[
            "pentestgpt", "--target", "{target_ip}",
            "--mode", "pentest", "--no-telemetry",
        ],
        static_ip="172.30.0.82",
        timeout_seconds=600,
        llm_provider="anthropic",
        llm_env_vars={"ANTHROPIC_API_KEY": "{ANTHROPIC_API_KEY}"},
        notes="Autonomous mode needs Claude SDK. 7k+ stars. AWS-only.",
    ),
}


def get_tools_by_category(category: str) -> list[ToolSpec]:
    return [t for t in TOOL_REGISTRY.values() if t.category == category]


def get_all_categories() -> list[str]:
    return sorted(set(t.category for t in TOOL_REGISTRY.values()))


def resolve_tool_names(tools: list[str] | None, category: str | None, run_all: bool) -> list[ToolSpec]:
    """Resolve CLI args to a list of ToolSpecs."""
    if run_all:
        return [t for t in TOOL_REGISTRY.values() if t.category != "validation"]
    if category:
        specs = get_tools_by_category(category)
        if not specs:
            raise ValueError(f"Unknown category: {category}. Available: {get_all_categories()}")
        return specs
    if tools:
        specs = []
        for name in tools:
            if name not in TOOL_REGISTRY:
                raise ValueError(f"Unknown tool: {name}. Available: {sorted(TOOL_REGISTRY.keys())}")
            specs.append(TOOL_REGISTRY[name])
        return specs
    raise ValueError("Specify --tools, --category, or --all")
