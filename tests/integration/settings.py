AZURE_EMULATED_MODE = True
AZURE_ACCOUNT_NAME = "XXX"
AZURE_ACCOUNT_KEY = "KXXX"
AZURE_CONTAINER = "test"

SECRET_KEY = 'test'

INSTALLED_APPS = (
    'django.contrib.staticfiles',
    'storages',
    'tests.integration'
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {},
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}
