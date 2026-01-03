"""
Configuration de l'application
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Paramètres de configuration"""  
    
    # Application
    APP_NAME: str = "Biométrie Examen"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Base de données
    DATABASE_URL: str = "sqlite+aiosqlite:///./biometrie_exam.db"
    
    # Sécurité
    SECRET_KEY: str = "votre-cle-secrete-tres-longue-et-complexe-a-changer"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Biométrie - Seuils
    FACE_RECOGNITION_THRESHOLD: float = 0.6
    VOICE_RECOGNITION_THRESHOLD: float = 0.75  # Seuil pour le score vocal combiné
    MULTIMODAL_THRESHOLD: float = 0.65
    
    # Seuils minimaux individuels - chaque modalité doit les atteindre
    MIN_FACE_SCORE: float = 0.5  # Score facial minimum requis
    MIN_VOICE_SCORE: float = 0.55  # Score vocal minimum requis (assoupli pour l'examen)
    
    # Poids pour la fusion multimodale
    FACE_WEIGHT: float = 0.6
    VOICE_WEIGHT: float = 0.4
    
    # Surveillance (intervalles en secondes)
    FACE_CHECK_INTERVAL_SECONDS: int = 5  # Vérification faciale toutes les 5s (temps réel)
    VOICE_CHALLENGE_INTERVAL_SECONDS: int = 120
    MAX_ABSENCE_DURATION_SECONDS: int = 15  # Absence max 15s (3 échecs consécutifs)
    
    # Stockage
    UPLOAD_DIR: str = "uploads"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# Créer le dossier uploads s'il n'existe pas
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
