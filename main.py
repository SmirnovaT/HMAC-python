"""Main module for run FastAPI application"""

import uvicorn

from src.app import app
from src.config import get_config


if __name__ == "__main__":
    config = get_config()
    host = config.host
    port = config.port
    uvicorn.run(app, host=host, port=port)
