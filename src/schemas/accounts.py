from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.email_validator(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attritues=True)
