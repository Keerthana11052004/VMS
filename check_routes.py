#!/usr/bin/env python3
from app import app
print('Registered Routes:')
for rule in app.url_map.iter_rules():
    print(f'  {rule}')
