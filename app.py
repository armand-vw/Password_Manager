#!/usr/bin/env python3
"""Password Manager — local zero-knowledge encrypted vault."""

from password_manager import create_app

app = create_app()

if __name__ == "__main__":
    import os
    host = os.environ.get("PM_HOST", "0.0.0.0")
    port = int(os.environ.get("PM_PORT", "8080"))
    app.run(host=host, port=port, debug=False)
