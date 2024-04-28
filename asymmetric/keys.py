from fastapi import APIRouter
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from asymmetric.models import AsymmetricKeys
from asymmetric.state import keys

asymmetric_router = APIRouter()


@asymmetric_router.get("/asymmetric/key/ssh", tags=["Asymmetric keys"])
async def generate_asymmetric_keys_ssh():
    """
        Generates RSA asymmetric key pair (public and private keys) in SSH format.

        Returns:
            A dictionary containing the generated SSH public key and private key (in PEM format).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()

    public_key_ssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).hex()

    keys.update({"public_key": public_key_ssh, "private_key": private_key_pem})

    return {"public_key_ssh": public_key_ssh, "private_key_pem": private_key_pem}


@asymmetric_router.post("/asymmetric/key", tags=["Asymmetric keys"])
async def set_asymmetric_keys(passed_keys: AsymmetricKeys):
    """
        Sets the provided public and private keys.

        Parameters:
            - passed_keys (AsymmetricKeys): Object containing the public and private keys.

        Returns:
            A dictionary confirming the successful setting of keys.
    """
    keys["public_key"] = passed_keys.public_key
    keys["private_key"] = passed_keys.private_key
    return {"message": "Keys have been set successfully."}
