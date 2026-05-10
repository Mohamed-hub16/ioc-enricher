#!/usr/bin/env python3
from dotenv import load_dotenv

load_dotenv()

from webapp import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
