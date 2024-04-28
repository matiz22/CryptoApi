from fastapi import APIRouter
from cryptography.fernet import Fernet
from symmetric.model import Key
from symmetric import state

symmetric_router = APIRouter()


@symmetric_router.get("/symmetric/key", tags=["Symmetric keys"])
async def generate_key():
    """
    Generates a symmetric key for encryption using the Fernet algorithm.

    Returns:
        A dictionary containing the generated symmetric key.
    """
    state.symmetric_key = Fernet.generate_key().decode()
    return {"symmetric_key": state.symmetric_key}


@symmetric_router.post("/symmetric/key", tags=["Symmetric keys"])
async def set_symmetric_key(key: Key):
    """
    Sets the provided symmetric key.

    Parameters:
        - key (Key): Object containing the symmetric key.

    Returns:
        A dictionary confirming the successful setting of the symmetric key.
    """
    state.symmetric_key = key.symmetric_key
    return {"message": "Symmetric key has been set successfully."}
