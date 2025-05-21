from cryptography.fernet import Fernet
import json
import keyring
import bcrypt
import os
from auth.config import get_env_var
from pathlib import Path
from auth.auth_logging import setup_logging

class SecureLayer:
    """
    SecureLayer handles encryption, decryption, and secure storage
    of user credentials using Fernet symmetric encryption and bcrypt hashing.
    It manages two Fernet keys (parent and child) stored in the OS keyring,
    and saves encrypted user data in a secure local file.
    """


    def __init__(self):
        
        """
        Initialize SecureLayer:
        - Setup logger
        - Setup encryption ciphers
        - Setup file path to store encrypted data
        """
        
        self.logger = setup_logging()
        self.setup_cipher()        
        self.user_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs", "CryptVault")
        os.makedirs(self.user_path, exist_ok=True)
        self.data_file = os.path.join(self.user_path, get_env_var('DATA_PATH'))
    
    def setup_cipher(self):
        """
        Setup Fernet cipher instances for parent and child keys.
        - Retrieves keys from keyring, generates and stores new keys if missing.
        - Logs errors if key setup fails.
        """
        
        try:
            self.key = keyring.get_password(get_env_var('APP_NAME'), get_env_var('USERNAME_CHILD'))
            if self.key is None:
                self.key = Fernet.generate_key()
                keyring.set_password(get_env_var('APP_NAME'), get_env_var('USERNAME_CHILD'), self.key.decode())
            self.cipher_child = Fernet(self.key)
            
        except Exception as e:
            self.logger.error(f"Exception While Cipher Setup - {e}")
    
        try:
            key = keyring.get_password(get_env_var('APP_NAME'), get_env_var('USERNAME_PARENT'))
            if key is None:
                key = Fernet.generate_key()
                keyring.set_password(get_env_var('APP_NAME'), get_env_var('USERNAME_PARENT'), key.decode())
            self.cipher_parent = Fernet(key)
            
        except Exception as e:
            self.logger.error(f"Exception While Cipher Setup - {e}")
    
    def chk_if_exists(self)->bool:
        """
        Check if the encrypted data file exists.

        Returns:
            bool: True if file exists, False otherwise.
        """
        
        return os.path.exists(self.data_file)
    
    def save_data(self, data)->bool:
        """
        Save encrypted data to the data file.

        Args:
            data (bytes): Encrypted data bytes.

        Returns:
            bool: True if save successful, False otherwise.
        """
        
        try:
            with open(self.data_file, 'w') as file:
                file.write(data.decode())
            return True
        except Exception as e:
            self.logger.error(f"Can't save encrypted data: {e}")
            return False
    
    def encrypt_data(self, name:str, email:str, password:str)->bool:
        """
        Encrypt and save user credentials securely.

        Args:
            name (str): Username.
            email (str): User email.
            password (str): Plaintext password.

        Returns:
            bool: True if encryption and save succeed, False otherwise.
        """
        
        try:
            password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            user = [name, email, password.decode()]
            
            user_bytes = json.dumps(user).encode()
            
            encrypted_child = self.cipher_child.encrypt(user_bytes)
            encrypted = self.cipher_parent.encrypt(encrypted_child)
            
            self.save_data(encrypted)
            return True
            
        except Exception as e:
            self.logger.error(f"Error While Encrypting Data: {e}")
            return False
    
    def load_data(self)->str|bool:
        """
        Load the encrypted data from file.

        Returns:
            str: Encrypted data as string if file exists.
            bool: False if file missing or error occurs.
        """
        
        if self.chk_if_exists():
            try:
                with open(self.data_file, 'r') as file:
                    encrypted_data = file.read()
                return encrypted_data
            except Exception as e:
                self.logger.error(f"Error While Loading Encrypted Data: {e}")
                return False
        else:
            self.logger.error("No File Exists!")
            return False
        
    def decrypt_data(self)->dict|str:
        """
        Decrypt the stored encrypted user data.

        Returns:
            dict or str: Decrypted user data list [name, email, hashed_password] if successful.
                         Logs error and returns None if failure.
        """
        
        encrypted_data = self.load_data().encode()
        try:
            user_bytes = self.cipher_parent.decrypt(encrypted_data)
            user_bytes = self.cipher_child.decrypt(user_bytes)
            user = json.loads(user_bytes)           
            return user        
            
        except Exception as e:
            self.logger.error(f"Error Occured-{e}")
            
    def validate_user(self, name:str, password:str)->bool:
        """
        Validate user credentials against the stored encrypted data.

        Args:
            name (str): Username to validate.
            password (str): Plaintext password to validate.

        Returns:
            bool: True if credentials match, False otherwise.
        """
        
        try:
            user = self.decrypt_data()
            
            if user[0] ==name:
                if bcrypt.checkpw(password.encode(), user[2].encode()):
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Error While Validating User:{e}")
