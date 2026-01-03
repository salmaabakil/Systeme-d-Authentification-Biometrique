"""
Service de biométrie multimodale
Combine la reconnaissance faciale et vocale
"""
from typing import Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.biometric import BiometricData
from app.models.user import User
from app.models.security_log import SecurityLog, LogType
from app.services.face_service import face_service
from app.services.voice_service import voice_service
from app.services.encryption_service import get_encryption_service
from app.config import settings
import logging

logger = logging.getLogger(__name__)


class BiometricService:
    """Service de biométrie multimodale"""
    
    def __init__(self):
        self.face_weight = settings.FACE_WEIGHT
        self.voice_weight = settings.VOICE_WEIGHT
        self.threshold = settings.MULTIMODAL_THRESHOLD
        # Seuils minimaux individuels - protection contre les imposteurs
        self.min_face_score = settings.MIN_FACE_SCORE
        self.min_voice_score = settings.MIN_VOICE_SCORE
    
    async def enroll_user(
        self,
        db: AsyncSession,
        user_id: int,
        face_image_base64: str,
        voice_audio_base64: str
    ) -> Tuple[bool, str]:
        """
        Enrôler les données biométriques d'un utilisateur
        """
        try:
            # Extraire le descripteur facial
            face_encoding, face_quality = face_service.enroll_face(face_image_base64)
            if face_encoding is None:
                return False, "Impossible de détecter un visage dans l'image"
            
            # Extraire le descripteur vocal
            voice_encoding, voice_quality = voice_service.enroll_voice(voice_audio_base64)
            if voice_encoding is None:
                return False, "Impossible d'extraire les caractéristiques vocales"
            
            # Chiffrer les données biométriques avant stockage
            encryption = get_encryption_service()
            encrypted_face = encryption.encrypt(face_encoding)
            encrypted_voice = encryption.encrypt(voice_encoding)
            logger.info("Données biométriques chiffrées avec AES-256")
            
            # Vérifier si l'utilisateur a déjà des données biométriques
            result = await db.execute(
                select(BiometricData).where(BiometricData.user_id == user_id)
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                # Mettre à jour avec données chiffrées
                existing.face_encoding = encrypted_face
                existing.face_encoding_quality = face_quality
                existing.voice_encoding = encrypted_voice
                existing.voice_encoding_quality = voice_quality
            else:
                # Créer avec données chiffrées
                biometric = BiometricData(
                    user_id=user_id,
                    face_encoding=encrypted_face,
                    face_encoding_quality=face_quality,
                    voice_encoding=encrypted_voice,
                    voice_encoding_quality=voice_quality
                )
                db.add(biometric)
            
            # Marquer l'utilisateur comme enrôlé
            user_result = await db.execute(select(User).where(User.id == user_id))
            user = user_result.scalar_one_or_none()
            if user:
                user.is_enrolled = True
            
            # Logger l'enrôlement
            log = SecurityLog(
                user_id=user_id,
                log_type=LogType.ENROLLMENT_SUCCESS,
                message=f"Enrôlement biométrique réussi (face: {face_quality:.2f}, voice: {voice_quality:.2f})",
                face_score=face_quality,
                voice_score=voice_quality
            )
            db.add(log)
            
            await db.commit()
            
            return True, "Enrôlement biométrique réussi"
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enrôlement: {e}")
            return False, f"Erreur lors de l'enrôlement: {str(e)}"
    
    async def verify_user(
        self,
        db: AsyncSession,
        user_id: int,
        face_image_base64: Optional[str] = None,
        voice_audio_base64: Optional[str] = None
    ) -> Tuple[bool, float, float, float, str]:
        """
        Vérifier l'identité d'un utilisateur
        Returns:
            Tuple (is_verified, face_score, voice_score, combined_score, message)
        """
        try:
            # Récupérer les données biométriques stockées
            result = await db.execute(
                select(BiometricData).where(BiometricData.user_id == user_id)
            )
            biometric = result.scalar_one_or_none()
            
            if biometric is None:
                return False, 0.0, 0.0, 0.0, "Utilisateur non enrôlé"
            
            face_score = 0.0
            voice_score = 0.0
            
            logger.info(f"=== VÉRIFICATION BIOMÉTRIQUE pour user_id={user_id} ===")
            logger.info(f"Face image fournie: {bool(face_image_base64)}, Voice audio fourni: {bool(voice_audio_base64)}")
            logger.info(f"Face encoding stocké: {bool(biometric.face_encoding)}, Voice encoding stocké: {bool(biometric.voice_encoding)}")
            
            # Déchiffrer les données biométriques stockées
            encryption = get_encryption_service()
            
            # Vérification faciale
            if face_image_base64 and biometric.face_encoding:
                # Déchiffrer l'encoding facial
                decrypted_face = encryption.decrypt(biometric.face_encoding)
                _, face_score = face_service.verify_face(
                    decrypted_face,
                    face_image_base64
                )
                logger.info(f"Score facial: {face_score:.4f}")
            else:
                logger.warning("Vérification faciale NON effectuée - données manquantes")
            
            # Vérification vocale
            if voice_audio_base64 and biometric.voice_encoding:
                # Déchiffrer l'encoding vocal
                decrypted_voice = encryption.decrypt(biometric.voice_encoding)
                _, voice_score = voice_service.verify_voice(
                    decrypted_voice,
                    voice_audio_base64
                )
                logger.info(f"Score vocal: {voice_score:.4f}")
            else:
                logger.warning("Vérification vocale NON effectuée - données manquantes")
            
            # Calcul du score combiné (fusion multimodale)
            if face_image_base64 and voice_audio_base64:
                # Les deux modalités présentes
                combined_score = (
                    self.face_weight * face_score +
                    self.voice_weight * voice_score
                )
            elif face_image_base64:
                # Seulement le visage
                combined_score = face_score
            elif voice_audio_base64:
                # Seulement la voix
                combined_score = voice_score
            else:
                return False, 0.0, 0.0, 0.0, "Aucune donnée biométrique fournie"
            
            logger.info(f"Score combiné: {combined_score:.4f} (seuil multimodal: {self.threshold})")
            
            # Décision - IMPORTANT: Chaque modalité doit atteindre son seuil minimum
            # Cela empêche un imposteur avec une voix similaire (ex: frère) de passer
            individual_checks_passed = True
            rejection_reason = ""
            
            if face_image_base64:
                logger.info(f"Vérification seuil facial: {face_score:.4f} >= {self.min_face_score} ?")
                if face_score < self.min_face_score:
                    individual_checks_passed = False
                    rejection_reason = f"Score facial insuffisant ({face_score:.2f} < {self.min_face_score})"
                    logger.warning(f"❌ REJET: {rejection_reason}")
            
            if voice_audio_base64:
                logger.info(f"Vérification seuil vocal: {voice_score:.4f} >= {self.min_voice_score} ?")
                if voice_score < self.min_voice_score:
                    individual_checks_passed = False
                    rejection_reason = f"Score vocal insuffisant ({voice_score:.2f} < {self.min_voice_score}). Voix non reconnue comme appartenant à l'utilisateur."
                    logger.warning(f"❌ REJET: {rejection_reason}")
            
            # Les deux conditions doivent être vraies:
            # 1. Chaque modalité fournie doit passer son seuil individuel
            # 2. Le score combiné doit atteindre le seuil multimodal
            is_verified = individual_checks_passed and (combined_score >= self.threshold)
            logger.info(f"=== RÉSULTAT: {'✅ ACCEPTÉ' if is_verified else '❌ REFUSÉ'} ===")
            
            # Logger la vérification
            log_type = LogType.LOGIN_SUCCESS if is_verified else LogType.LOGIN_FAILED
            log = SecurityLog(
                user_id=user_id,
                log_type=log_type,
                message=f"Vérification biométrique: {'réussie' if is_verified else 'échouée'}",
                face_score=face_score,
                voice_score=voice_score,
                combined_score=combined_score
            )
            db.add(log)
            await db.commit()
            
            # Message détaillé pour l'utilisateur
            if is_verified:
                message = "Vérification réussie"
            elif rejection_reason:
                message = f"Vérification échouée: {rejection_reason}"
            else:
                message = f"Vérification échouée: score combiné insuffisant ({combined_score:.2f} < {self.threshold})"
            
            return is_verified, face_score, voice_score, combined_score, message
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification: {e}")
            return False, 0.0, 0.0, 0.0, f"Erreur: {str(e)}"
    
    async def check_face(
        self,
        db: AsyncSession,
        user_id: int,
        exam_session_id: int,
        face_image_base64: str
    ) -> Tuple[bool, float]:
        """
        Vérification faciale pendant l'examen (surveillance continue)
        """
        try:
            # Récupérer les données biométriques
            result = await db.execute(
                select(BiometricData).where(BiometricData.user_id == user_id)
            )
            biometric = result.scalar_one_or_none()
            
            if biometric is None or biometric.face_encoding is None:
                return False, 0.0
            
            # Déchiffrer l'encoding facial
            encryption = get_encryption_service()
            decrypted_face = encryption.decrypt(biometric.face_encoding)
            
            # Vérifier le visage
            is_match, score = face_service.verify_face(
                decrypted_face,
                face_image_base64
            )
            
            # Logger
            log_type = LogType.FACE_CHECK_SUCCESS if is_match else LogType.FACE_CHECK_FAILED
            log = SecurityLog(
                user_id=user_id,
                exam_session_id=exam_session_id,
                log_type=log_type,
                message=f"Vérification faciale: score={score:.2f}",
                face_score=score
            )
            db.add(log)
            await db.commit()
            
            return is_match, score
            
        except Exception as e:
            logger.error(f"Erreur vérification faciale: {e}")
            return False, 0.0
    
    async def check_voice(
        self,
        db: AsyncSession,
        user_id: int,
        exam_session_id: int,
        voice_audio_base64: str
    ) -> Tuple[bool, float]:
        """
        Vérification vocale pendant l'examen (surveillance continue)
        """
        try:
            # Récupérer les données biométriques
            result = await db.execute(
                select(BiometricData).where(BiometricData.user_id == user_id)
            )
            biometric = result.scalar_one_or_none()
            
            if biometric is None or biometric.voice_encoding is None:
                return False, 0.0
            
            # Déchiffrer l'encoding vocal
            encryption = get_encryption_service()
            decrypted_voice = encryption.decrypt(biometric.voice_encoding)
            
            # Vérifier la voix
            is_match, score = voice_service.verify_voice(
                decrypted_voice,
                voice_audio_base64
            )
            
            # Logger
            log_type = LogType.VOICE_CHECK_SUCCESS if is_match else LogType.VOICE_CHECK_FAILED
            log = SecurityLog(
                user_id=user_id,
                exam_session_id=exam_session_id,
                log_type=log_type,
                message=f"Vérification vocale: score={score:.2f}",
                voice_score=score
            )
            db.add(log)
            await db.commit()
            
            return is_match, score
            
        except Exception as e:
            logger.error(f"Erreur vérification vocale: {e}")
            return False, 0.0


# Instance globale
biometric_service = BiometricService()
