import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from core.config import ScanConfig
from web.backend.api import run_server


def main():
    config = ScanConfig()
    run_server(config, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
