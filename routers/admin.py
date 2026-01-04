"""
Routes d'administration
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr

from app.database import get_db
from app.schemas.user import UserResponse, UserUpdate
from app.models.user import User, UserRole
from app.models.exam import Exam, ExamSession, SessionStatus
from app.models.security_log import SecurityLog, LogType
from app.models.biometric import BiometricData
from app.routers.auth import get_current_admin
from app.services.auth_service import get_password_hash
from app.services.biometric_service import biometric_service


class AssignCandidatRequest(BaseModel):
    """Requête pour assigner un candidat à un examen"""
    user_id: int
    exam_id: int


class CreateCandidatWithBiometricRequest(BaseModel):
    """Requête pour créer un candidat avec données biométriques"""
    nom: str
    prenom: str
    email: EmailStr
    password: str
    face_image_base64: str
    voice_audio_base64: str


router = APIRouter(prefix="/admin", tags=["Administration"])


@router.post("/create-candidate", response_model=UserResponse)
async def create_candidate_with_biometric(
    data: CreateCandidatWithBiometricRequest,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Créer un candidat avec ses données biométriques (visage + voix)"""
    # Vérifier si l'email existe déjà
    result = await db.execute(select(User).where(User.email == data.email))
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cet email est déjà utilisé"
        )
    
    # Créer l'utilisateur
    user = User(
        email=data.email,
        hashed_password=get_password_hash(data.password),
        nom=data.nom,
        prenom=data.prenom,
        role=UserRole.CANDIDAT,
        is_active=True,
        is_enrolled=False  # Sera mis à True après l'enrôlement
    )
    db.add(user)
    await db.flush()  # Pour obtenir l'ID
    
    # Enrôler les données biométriques
    success, message = await biometric_service.enroll_user(
        db,
        user.id,
        data.face_image_base64,
        data.voice_audio_base64
    )
    
    if not success:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Erreur lors de l'enrôlement biométrique: {message}"
        )
    
    await db.commit()
    await db.refresh(user)
    
    return user


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    role: Optional[UserRole] = None,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Lister tous les utilisateurs"""
    query = select(User)
    if role:
        query = query.where(User.role == role)
    
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Récupérer un utilisateur"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Mettre à jour un utilisateur"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    if user_data.nom is not None:
        user.nom = user_data.nom
    if user_data.prenom is not None:
        user.prenom = user_data.prenom
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    
    await db.commit()
    await db.refresh(user)
    
    return user


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Supprimer un utilisateur"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vous ne pouvez pas vous supprimer vous-même"
        )
    
    await db.delete(user)
    await db.commit()
    
    return {"message": "Utilisateur supprimé"}


@router.post("/assign-candidate")
async def assign_candidate_to_exam(
    data: AssignCandidatRequest,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Assigner un candidat à un examen"""
    # Vérifier que l'utilisateur existe
    result = await db.execute(select(User).where(User.id == data.user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    if user.role != UserRole.CANDIDAT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Seuls les candidats peuvent être assignés à des examens"
        )
    
    # Vérifier que l'examen existe
    result = await db.execute(select(Exam).where(Exam.id == data.exam_id))
    exam = result.scalar_one_or_none()
    
    if not exam:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Examen non trouvé"
        )
    
    # Vérifier si le candidat est déjà assigné
    result = await db.execute(
        select(ExamSession).where(
            ExamSession.user_id == data.user_id,
            ExamSession.exam_id == data.exam_id
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ce candidat est déjà assigné à cet examen"
        )
    
    # Créer la session d'examen
    session = ExamSession(
        user_id=data.user_id,
        exam_id=data.exam_id,
        status=SessionStatus.PENDING
    )
    
    db.add(session)
    await db.commit()
    await db.refresh(session)
    
    return {
        "message": f"Candidat {user.prenom} {user.nom} assigné à l'examen {exam.title}",
        "session_id": session.id
    }


@router.get("/exam-sessions/{exam_id}")
async def get_exam_sessions(
    exam_id: int,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Récupérer les sessions d'un examen"""
    result = await db.execute(
        select(ExamSession, User)
        .join(User, ExamSession.user_id == User.id)
        .where(ExamSession.exam_id == exam_id)
    )
    
    sessions = []
    for session, user in result:
        sessions.append({
            "session_id": session.id,
            "user_id": user.id,
            "user_name": f"{user.prenom} {user.nom}",
            "user_email": user.email,
            "status": session.status.value,
            "score": session.score,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "anomaly_count": session.anomaly_count
        })
    
    return sessions


@router.get("/security-logs")
async def get_security_logs(
    user_id: Optional[int] = None,
    log_type: Optional[LogType] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Récupérer les journaux de sécurité"""
    query = select(SecurityLog)
    
    if user_id:
        query = query.where(SecurityLog.user_id == user_id)
    if log_type:
        query = query.where(SecurityLog.log_type == log_type)
    
    query = query.order_by(SecurityLog.created_at.desc()).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "exam_session_id": log.exam_session_id,
            "log_type": log.log_type.value,
            "message": log.message,
            "face_score": log.face_score,
            "voice_score": log.voice_score,
            "combined_score": log.combined_score,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat()
        }
        for log in logs
    ]


@router.get("/statistics")
async def get_statistics(
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """Obtenir les statistiques générales"""
    # Nombre d'utilisateurs
    users_count = await db.execute(select(func.count(User.id)))
    total_users = users_count.scalar()
    
    # Candidats enrôlés
    enrolled_count = await db.execute(
        select(func.count(User.id)).where(User.is_enrolled == True)
    )
    total_enrolled = enrolled_count.scalar()
    
    # Examens
    exams_count = await db.execute(select(func.count(Exam.id)))
    total_exams = exams_count.scalar()
    
    # Sessions complétées
    sessions_count = await db.execute(
        select(func.count(ExamSession.id)).where(
            ExamSession.status == SessionStatus.COMPLETED
        )
    )
    completed_sessions = sessions_count.scalar()
    
    # Score moyen
    avg_score = await db.execute(
        select(func.avg(ExamSession.score)).where(
            ExamSession.status == SessionStatus.COMPLETED
        )
    )
    average_score = avg_score.scalar() or 0
    
    # Anomalies totales
    anomalies = await db.execute(
        select(func.sum(ExamSession.anomaly_count))
    )
    total_anomalies = anomalies.scalar() or 0
    
    # Statistiques de la semaine
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    weekly_sessions = await db.execute(
        select(func.count(ExamSession.id)).where(
            ExamSession.created_at >= week_ago
        )
    )
    sessions_this_week = weekly_sessions.scalar()
    
    weekly_logs = await db.execute(
        select(func.count(SecurityLog.id)).where(
            SecurityLog.created_at >= week_ago,
            SecurityLog.log_type.in_([
                LogType.FACE_CHECK_FAILED,
                LogType.VOICE_CHECK_FAILED,
                LogType.ABSENCE_DETECTED
            ])
        )
    )
    alerts_this_week = weekly_logs.scalar()
    
    return {
        "total_users": total_users,
        "total_enrolled": total_enrolled,
        "total_exams": total_exams,
        "completed_sessions": completed_sessions,
        "average_score": round(average_score, 2),
        "total_anomalies": total_anomalies,
        "sessions_this_week": sessions_this_week,
        "alerts_this_week": alerts_this_week
    }


@router.get("/biometric-metrics")
async def get_biometric_metrics(
    current_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtenir les métriques biométriques FAR/FRR
    
    FAR (False Acceptance Rate) = Imposteurs acceptés / Total tentatives imposteurs
    FRR (False Rejection Rate) = Légitimes rejetés / Total tentatives légitimes
    """
    # Statistiques faciales
    face_success = await db.execute(
        select(func.count(SecurityLog.id)).where(
            SecurityLog.log_type == LogType.FACE_CHECK_SUCCESS
        )
    )
    face_success_count = face_success.scalar() or 0
    
    face_failed = await db.execute(
        select(func.count(SecurityLog.id)).where(
            SecurityLog.log_type == LogType.FACE_CHECK_FAILED
        )
    )
    face_failed_count = face_failed.scalar() or 0
    
    # Statistiques vocales
    voice_success = await db.execute(
        select(func.count(SecurityLog.id)).where(
            SecurityLog.log_type == LogType.VOICE_CHECK_SUCCESS
        )
    )
    voice_success_count = voice_success.scalar() or 0
    
    voice_failed = await db.execute(
        select(func.count(SecurityLog.id)).where(
            SecurityLog.log_type == LogType.VOICE_CHECK_FAILED
        )
    )
    voice_failed_count = voice_failed.scalar() or 0
    
    # Login stats (pour FAR/FRR globaux)
    login_success = await db.execute(
        select(func.count(SecurityLog.id)).where(
            SecurityLog.log_type == LogType.LOGIN_SUCCESS
        )
    )
    login_success_count = login_success.scalar() or 0
    
    login_failed = await db.execute(
        select(func.count(SecurityLog.id)).where(
            SecurityLog.log_type == LogType.LOGIN_FAILED
        )
    )
    login_failed_count = login_failed.scalar() or 0
    
    # Scores moyens
    avg_face_success = await db.execute(
        select(func.avg(SecurityLog.face_score)).where(
            SecurityLog.log_type == LogType.FACE_CHECK_SUCCESS,
            SecurityLog.face_score.isnot(None)
        )
    )
    avg_face_success_score = avg_face_success.scalar() or 0
    
    avg_face_failed = await db.execute(
        select(func.avg(SecurityLog.face_score)).where(
            SecurityLog.log_type == LogType.FACE_CHECK_FAILED,
            SecurityLog.face_score.isnot(None)
        )
    )
    avg_face_failed_score = avg_face_failed.scalar() or 0
    
    avg_voice_success = await db.execute(
        select(func.avg(SecurityLog.voice_score)).where(
            SecurityLog.log_type == LogType.VOICE_CHECK_SUCCESS,
            SecurityLog.voice_score.isnot(None)
        )
    )
    avg_voice_success_score = avg_voice_success.scalar() or 0
    
    avg_voice_failed = await db.execute(
        select(func.avg(SecurityLog.voice_score)).where(
            SecurityLog.log_type == LogType.VOICE_CHECK_FAILED,
            SecurityLog.voice_score.isnot(None)
        )
    )
    avg_voice_failed_score = avg_voice_failed.scalar() or 0
    
    # Calcul des taux
    total_face = face_success_count + face_failed_count
    total_voice = voice_success_count + voice_failed_count
    total_login = login_success_count + login_failed_count
    
    # FRR estimé = échecs / total (approximation basée sur l'hypothèse que 
    # la majorité des tentatives sont légitimes)
    face_frr = (face_failed_count / total_face * 100) if total_face > 0 else 0
    voice_frr = (voice_failed_count / total_voice * 100) if total_voice > 0 else 0
    login_frr = (login_failed_count / total_login * 100) if total_login > 0 else 0
    
    # Taux de réussite
    face_success_rate = (face_success_count / total_face * 100) if total_face > 0 else 0
    voice_success_rate = (voice_success_count / total_voice * 100) if total_voice > 0 else 0
    
    return {
        "face": {
            "total_checks": total_face,
            "success": face_success_count,
            "failed": face_failed_count,
            "success_rate": round(face_success_rate, 2),
            "frr_estimate": round(face_frr, 2),
            "avg_success_score": round(avg_face_success_score, 3),
            "avg_failed_score": round(avg_face_failed_score, 3)
        },
        "voice": {
            "total_checks": total_voice,
            "success": voice_success_count,
            "failed": voice_failed_count,
            "success_rate": round(voice_success_rate, 2),
            "frr_estimate": round(voice_frr, 2),
            "avg_success_score": round(avg_voice_success_score, 3),
            "avg_failed_score": round(avg_voice_failed_score, 3)
        },
        "login": {
            "total_attempts": total_login,
            "success": login_success_count,
            "failed": login_failed_count,
            "frr_estimate": round(login_frr, 2)
        },
        "thresholds": {
            "face": 0.5,
            "voice": 0.55,
            "multimodal": 0.65
        },
        "explanation": {
            "frr": "False Rejection Rate - % d'utilisateurs légitimes rejetés",
            "far": "False Acceptance Rate - % d'imposteurs acceptés (nécessite tests avec imposteurs)",
            "note": "Les valeurs FRR sont estimées. Pour FAR précis, des tests avec imposteurs connus sont nécessaires."
        }
    }
