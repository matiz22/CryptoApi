from pydantic import BaseModel


class Key(BaseModel):
    symmetric_key: str


class EncryptedMessage(BaseModel):
    encrypted_message: str
