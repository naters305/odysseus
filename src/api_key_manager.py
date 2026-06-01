import os
import json
import logging
from typing import Dict
from cryptography.fernet import Fernet

from core.atomic_io import atomic_write_json

logger = logging.getLogger(__name__)

class APIKeyManager:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.api_keys_file = os.path.join(data_dir, "api_keys.json")
        self.key_file = os.path.join(data_dir, ".key")

    def get_or_create_key(self) -> bytes:
        """Get or create encryption key for API keys"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key

    def encrypt_api_key(self, api_key: str) -> str:
        """Encrypt an API key"""
        if not api_key:
            return ""
        f = Fernet(self.get_or_create_key())
        return f.encrypt(api_key.encode()).decode()

    def decrypt_api_key(self, encrypted_key: str) -> str:
        """Decrypt an API key"""
        if not encrypted_key:
            return ""
        f = Fernet(self.get_or_create_key())
        return f.decrypt(encrypted_key.encode()).decode()

    def save(self, provider: str, api_key: str):
        """Save encrypted API key to file.

        Written atomically: a crash or OOM mid-write must not truncate
        api_keys.json and wipe every stored provider key at once. The
        whole dict is read-modify-written, so a partial write here is a
        total-loss event without atomicity.
        """
        keys = self._load_encrypted()
        keys[provider] = self.encrypt_api_key(api_key)
        atomic_write_json(self.api_keys_file, keys)

    def _load_encrypted(self) -> Dict[str, str]:
        """Return the raw encrypted key dict, WITHOUT decrypting.

        save() must merge into this, not into load()'s decrypted output —
        otherwise every other provider's key gets written back in
        plaintext and the next load() raises trying to decrypt it.
        """
        if not os.path.exists(self.api_keys_file):
            return {}
        try:
            with open(self.api_keys_file, 'r', encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(
                "api_keys.json is unreadable (%s); refusing to overwrite it. "
                "Restore from backup or delete it to reset stored keys.", e
            )
            raise

    def load(self) -> Dict[str, str]:
        """Load and decrypt API keys. A corrupt file degrades to an empty
        set rather than propagating an exception into every caller."""
        try:
            encrypted_keys = self._load_encrypted()
        except (json.JSONDecodeError, OSError):
            return {}
        out = {}
        for provider, key in encrypted_keys.items():
            try:
                out[provider] = self.decrypt_api_key(key)
            except Exception as e:
                # One bad/legacy-plaintext entry shouldn't sink the rest.
                logger.warning("Skipping undecryptable key for %r: %s", provider, e)
        return out
