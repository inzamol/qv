# Django Settings demonstrating DJG-001, DJG-002, DJG-003, DJG-006

# DJG-001: DEBUG enabled
DEBUG = True

# DJG-002: Hardcoded secret key
SECRET_KEY = "django-insecure-supersecretkeyforproductionmustnotbehardcoded"

# DJG-003: Wildcard allowed hosts
ALLOWED_HOSTS = ["*"]

# DJG-006: Missing CSRF Middleware in MIDDLEWARE
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # "django.middleware.csrf.CsrfViewMiddleware" is missing
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
]
