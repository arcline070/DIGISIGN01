import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'signature_project.settings')
django.setup()

from django.conf import settings
settings.ALLOWED_HOSTS.append('testserver')

from django.test import Client
from django.contrib.auth import get_user_model

User = get_user_model()
client = Client()

user = User.objects.first()

if user:
    client.force_login(user)
    response = client.get('/api/dashboard/summary/')
    
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        print(json.dumps(response.json(), indent=2))
    else:
        print("Error: ", response.content)
else:
    print("No users found in the database to authenticate with.")
