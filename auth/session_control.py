# session_control.py
import uuid
import time

class SessionManager:
    """
    Manages user sessions with timeout-based expiration using UUIDs.
    Sessions are stored at the class level and shared across instances.
    """
    sessions = {}  # <--- Class-level variable, shared by all instances

    def __init__(self, timeout=3600):
        """
        Initialize a SessionManager instance.

        Args:
            timeout (int): Session timeout in seconds. Default is 3600 (1 hour).
        """
        
        self.timeout = timeout

    def create_session(self, username) -> str:
        """
        Create a new session for a user.

        Args:
            username (str): The username for which the session is created.

        Returns:
            str: The generated session ID.
        """
        
        session_id = str(uuid.uuid4())
        SessionManager.sessions[session_id] = {
            "username": username,
            "created_at": time.time(),
            "expires_at": time.time() + self.timeout
        }
        return session_id

    def is_session_valid(self, session_id) -> bool:
        """
        Check if a session is valid and not expired.

        Args:
            session_id (str): The session ID to validate.

        Returns:
            bool: True if session is valid, False otherwise.
        """
        
        session = SessionManager.sessions.get(session_id)
        if session and time.time() < session["expires_at"]:
            return True
        else:
            SessionManager.sessions.pop(session_id, None)
            return False

    def get_user(self, session_id):
        """
        Retrieve the username associated with a valid session.

        Args:
            session_id (str): The session ID to retrieve the user from.

        Returns:
            str or None: Username if session is valid, None otherwise.
        """
        
        if self.is_session_valid(session_id):
            return SessionManager.sessions[session_id]["username"]
        return None

    def destroy_session(self, session_id):
        """
        Explicitly destroy a session.

        Args:
            session_id (str): The session ID to be removed.
        """
        
        SessionManager.sessions.pop(session_id, None)
