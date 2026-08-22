"""Entry point for ufw-mcp over stdio (local Claude Code)."""
import sys
from pathlib import Path
from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))
load_dotenv(_ROOT / ".env")

from ufw_mcp.server import main  # noqa: E402

if __name__ == "__main__":
    main()
