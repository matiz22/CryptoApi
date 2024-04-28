from pydantic import BaseModel, Field


class AsymmetricKeys(BaseModel):
    public_key: str = Field(..., example="public key HEX")
    private_key: str = Field(..., example="private key HEX")


class Message(BaseModel):
    message: str = Field(..., example="message")


class SignedMessage(BaseModel):
    message: str = Field(..., example="message")
    signature: str = Field(..., example="Signature in HEX")


class EncryptedMessage(BaseModel):
    encrypted_message: str
