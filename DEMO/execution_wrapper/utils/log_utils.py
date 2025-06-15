import os
from pathlib import Path

def create_log_directory():
    """Create a log directory if it doesn't exist."""
    current_dir = Path(__file__).parent.parent
    base_dir = current_dir/"logs"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    return base_dir
