"""
PII-AIRLOCK Server Entry Point

Run with: python -m pii_airlock.main
Or: uvicorn pii_airlock.main:app --reload
"""

import os
import uvicorn

from pii_airlock import __version__
from pii_airlock.logging.setup import setup_logging, get_logger

# Initialize logging early
setup_logging()
logger = get_logger(__name__)

# Import app after logging is set up
from pii_airlock.api.routes import app


def main():
    """Run the PII-AIRLOCK server."""
    host = os.getenv("PII_AIRLOCK_HOST", "0.0.0.0")
    port = int(os.getenv("PII_AIRLOCK_PORT", "8000"))
    reload = os.getenv("PII_AIRLOCK_RELOAD", "false").lower() == "true"
    log_level = os.getenv("PII_AIRLOCK_LOG_LEVEL", "info").lower()

    banner = f"""
╔═══════════════════════════════════════════════════════════════╗
║                      PII-AIRLOCK v{__version__:<22}    ║
║              Make Public LLMs Private                         ║
╠═══════════════════════════════════════════════════════════════╣
║  Server running at: http://{host}:{port}
║  API Docs: http://{host}:{port}/docs
║  Metrics: http://{host}:{port}/metrics
║                                                               ║
║  Usage: Set your OpenAI client base_url to this address       ║
║  Example:                                                     ║
║    client = OpenAI(base_url="http://localhost:{port}/v1")
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

    logger.info(
        "Starting PII-AIRLOCK server",
        extra={
            "event": "server_starting",
            "host": host,
            "port": port,
            "version": __version__,
        },
    )

    uvicorn.run(
        "pii_airlock.api.routes:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level,
    )


if __name__ == "__main__":
    main()
