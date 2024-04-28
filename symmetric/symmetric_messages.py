from fastapi import HTTPException, Body, APIRouter
from cryptography.fernet import Fernet
from symmetric import state

symmetric_messages_router = APIRouter()


@symmetric_messages_router.post("/symmetric/encode", tags=["Encode symmetric"])
async def encode_message(message: str = Body(..., embed=True)):
    """
    Encodes a message using symmetric encryption.

    Parameters:
        - message (str): The message to be encoded.

    Returns:
        A dictionary containing the encoded message.
    """
    if not state.symmetric_key:
        raise HTTPException(status_code=400, detail="Symmetric key is not set.")
    fernet = Fernet(state.symmetric_key)
    encoded_message = fernet.encrypt(message.encode())
    return {"encoded_message": encoded_message.decode()}


@symmetric_messages_router.post("/symmetric/decode", tags=["Encode symmetric"])
async def decode_message(encoded_message: str = Body(..., embed=True)):
    if not state.symmetric_key:
        raise HTTPException(status_code=400, detail="Symmetric key is not set.")
    fernet = Fernet(state.symmetric_key)
    try:
        decoded_message = fernet.decrypt(encoded_message.encode()).decode()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to decrypt the message.")
    return {"decoded_message": decoded_message}
