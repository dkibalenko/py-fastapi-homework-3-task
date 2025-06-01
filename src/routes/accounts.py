from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    try:
        query = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(query)
        db_user = result.scalar_one_or_none()

        if db_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} "
                        "already exists."
            )

        db_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=1
        )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)

        return db_user
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
    user_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    query = (
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    query = (
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == db_user.id)
    )
    token_result = await db.execute(query)
    user_activation_token = token_result.scalar_one_or_none()

    if user_activation_token:
        expires_at = cast(
            datetime, user_activation_token.expires_at
        ).replace(tzinfo=timezone.utc)

    if (
        not user_activation_token
        or expires_at < datetime.now(timezone.utc)
        or user_activation_token.token != user_data.token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    db_user.is_active = True
    await db.execute(
        delete(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == db_user.id)
    )
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )
