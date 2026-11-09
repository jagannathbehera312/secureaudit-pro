"""
ASGI config for SecureAudit Pro.
"""

import os
from django.core.asgi import get_asgi_application

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"

application = get_asgi_application()
