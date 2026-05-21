#!/usr/bin/env python3
"""Minimal test: just import the bot's modules and try to start."""
import sys, os
# Fake environment variables (same as GitHub secrets)
os.environ["BOT_TOKEN"] = "8908324765:AAF95UXFERMfUJatoLUlLxRqhEVF3RWq298"
os.environ["ADMIN_USERNAME"] = "StewieCyfer"
os.environ["HIBP_API_KEY"] = ""

print("0. Starting import test...")
try:
    import phantomwatch
    print("1. Imports OK")
except Exception as e:
    print(f"1. Import failed: {e}")
    sys.exit(1)

print("2. Calling main()...")
try:
    phantomwatch.main()
except Exception as e:
    print(f"3. main() crashed: {e}")
