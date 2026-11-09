#!/usr/bin/env python
"""
SecureAudit Pro - Standalone Demo Seeder CLI
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "backend"))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

try:
    import django
    django.setup()
    from fixtures.seed_data import seed_database

    print("Seeding SecureAudit Pro demo data...")
    seed_database(reset_existing=True)
    print("Database successfully seeded with demo organizations, users, targets, and vulnerabilities!")
except Exception as e:
    print(f"Error seeding database: {e}")
    sys.exit(1)
