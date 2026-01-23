"""
PII-AIRLOCK Server Entry Point

Run with: python -m pii_airlock.main
Or: uvicorn pii_airlock.main:app --reload
"""

import os
import sys
import uvicorn

from pii_airlock import __version__
from pii_airlock.logging.setup import setup_logging, get_logger

# Initialize logging early
setup_logging()
logger = get_logger(__name__)

# Import app after logging is set up
from pii_airlock.api.routes import app


# CFG-010 FIX: Add startup environment variable validation
def validate_environment() -> list[str]:
    """Validate environment variables at startup.

    Returns:
        List of validation error messages (empty if all valid).
    """
    errors = []
    warnings = []

    # Validate port
    port_str = os.getenv("PII_AIRLOCK_PORT", "8000")
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            errors.append(f"PII_AIRLOCK_PORT must be between 1 and 65535, got: {port}")
    except ValueError:
        errors.append(f"PII_AIRLOCK_PORT must be an integer, got: {port_str}")

    # Validate TTL
    ttl_str = os.getenv("PII_AIRLOCK_MAPPING_TTL", "300")
    try:
        ttl = int(ttl_str)
        if ttl <= 0:
            errors.append(f"PII_AIRLOCK_MAPPING_TTL must be positive, got: {ttl}")
    except ValueError:
        errors.append(f"PII_AIRLOCK_MAPPING_TTL must be an integer, got: {ttl_str}")

    # Validate timeout
    timeout_str = os.getenv("PII_AIRLOCK_TIMEOUT", "120")
    try:
        timeout = float(timeout_str)
        if timeout <= 0:
            errors.append(f"PII_AIRLOCK_TIMEOUT must be positive, got: {timeout}")
    except ValueError:
        errors.append(f"PII_AIRLOCK_TIMEOUT must be a number, got: {timeout_str}")

    # Validate log level
    valid_log_levels = {"debug", "info", "warning", "error", "critical"}
    log_level = os.getenv("PII_AIRLOCK_LOG_LEVEL", "info").lower()
    if log_level not in valid_log_levels:
        errors.append(f"PII_AIRLOCK_LOG_LEVEL must be one of {valid_log_levels}, got: {log_level}")

    # Validate rate limit format
    rate_limit = os.getenv("PII_AIRLOCK_RATE_LIMIT", "60/minute")
    if "/" not in rate_limit:
        errors.append(f"PII_AIRLOCK_RATE_LIMIT must be in format 'N/period', got: {rate_limit}")
    else:
        parts = rate_limit.split("/")
        try:
            int(parts[0])
        except ValueError:
            errors.append(f"PII_AIRLOCK_RATE_LIMIT count must be integer, got: {parts[0]}")

    # Check API key (warning only)
    api_key = os.getenv("PII_AIRLOCK_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        warnings.append("No API key configured (PII_AIRLOCK_API_KEY or OPENAI_API_KEY). Upstream requests will fail.")

    # Log warnings
    for warning in warnings:
        logger.warning(warning, extra={"event": "config_warning"})

    return errors


def main():
    """Run the PII-AIRLOCK server."""
    # CFG-010 FIX: Validate environment before starting
    validation_errors = validate_environment()
    if validation_errors:
        for error in validation_errors:
            logger.error(error, extra={"event": "config_error"})
        print("\n❌ Configuration errors detected:", file=sys.stderr)
        for error in validation_errors:
            print(f"  - {error}", file=sys.stderr)
        print("\nPlease fix the above errors and restart.", file=sys.stderr)
        sys.exit(1)

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
