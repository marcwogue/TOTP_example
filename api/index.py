import os
import sys

# Permet à Vercel de trouver le dossier core
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from core.wsgi import application

# Expose l'application pour Vercel
app = application
