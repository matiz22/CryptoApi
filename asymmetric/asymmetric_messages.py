from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from fastapi import APIRouter, HTTPException
from asymmetric.models import Message, SignedMessage, EncryptedMessage
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from asymmetric.state import keys

asymmetric_messages_router = APIRouter()


@asymmetric_messages_router.post("/asymmetric/verify", tags=["Asymmetric messages"])
async def sign_message(message: Message):
    """
    Signs a message using the private key.

    Parameters:
        - message (Message): The message to be signed.

    Returns:
        A dictionary containing the signed message in hexadecimal format.
    """
    if keys["private_key"] is None:
        raise HTTPException(status_code=404, detail="Private key has not been set.")

    private_key_bytes = bytes.fromhex(keys["private_key"])
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )

    signed_message = private_key.sign(
        message.message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return {"signed_message": signed_message.hex()}


@asymmetric_messages_router.post("/asymmetric/sign", tags=["Asymmetric messages"])
async def verify_signed_message(data: SignedMessage):
    """
        Verifies the signature of a signed message using the public key.

        Parameters:
            - data (SignedMessage): The signed message data containing the original message and signature.

        Returns:
            A dictionary indicating whether the signature is valid or not.
    """
    if keys["public_key"] is None:
        raise HTTPException(status_code=404, detail="Public key has not been set.")

    public_key_bytes = bytes.fromhex(keys["public_key"])
    public_key = serialization.load_ssh_public_key(
        public_key_bytes
    )

    original_message_bytes = data.message.encode()
    signed_message_bytes = bytes.fromhex(data.signature)

    try:
        public_key.verify(
            signed_message_bytes,
            original_message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"message": "Signature is valid."}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Signature verification failed.")


@asymmetric_messages_router.post("/asymmetric/encode", tags=["Asymmetric messages"])
async def encrypt_message(data: Message):
    """
       Encrypts a message using the recipient's public key.

       Parameters:
           - data (Message): The message to be encrypted.

       Returns:
           A dictionary containing the encrypted message in hexadecimal format.
   """
    if keys["public_key"] is None:
        raise HTTPException(status_code=404, detail="Public key has not been set.")

    public_key_bytes = bytes.fromhex(keys["public_key"])
    public_key = serialization.load_ssh_public_key(
        public_key_bytes
    )

    try:
        encrypted_message = public_key.encrypt(
            data.message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"encrypted_message": encrypted_message.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error encrypting message: {str(e)}")


@asymmetric_messages_router.post("/asymmetric/decode", tags=["Asymmetric messages"])
async def decrypt_message(data: EncryptedMessage):
    """
       Decrypts an encrypted message using the recipient's private key.

       Parameters:
           - data (EncryptedMessage): The encrypted message to be decrypted.

       Returns:
           A dictionary containing the decrypted message.
   """
    if keys["private_key"] is None:
        raise HTTPException(status_code=404, detail="Private key has not been set.")

    private_key_bytes = bytes.fromhex(keys["private_key"])
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

    try:
        encrypted_message_bytes = bytes.fromhex(data.encrypted_message)
        decrypted_message = private_key.decrypt(
            encrypted_message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"decrypted_message": decrypted_message.decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error decrypting message: {str(e)}")
