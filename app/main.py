from auth.session_control import SessionManager
from app.app import PasswordManager

class App():
    """
    Application wrapper class that initializes the Password Manager GUI
    after validating the user session.
    """
    
    def __init__(self,session_id, logger):
        """
        Initialize the App with a session ID and a logger.

        Args:
            session_id (str): The session identifier to validate.
            logger: Logger instance to log info and errors.
        """
        
        self.logger = logger
        self.sm = SessionManager()
        self.session_id = session_id
        self.app =PasswordManager(self.logger)
        self.app.mainloop()
        

def main(session_id, logger):
    """
    Main entry point of the application which validates the session
    and launches the Password Manager GUI if session is valid.

    Args:
        session_id (str): The session ID to validate.
        logger: Logger instance for logging purposes.
    """
    
    logging = logger
    sm = SessionManager()
    try:
        if sm.is_session_valid(session_id):            
            obj =App(session_id, logging)
            logging.info("Session Found")
            
        else:
            logging.error("Session is not valid")
    except Exception as e:
        logging.error(e)
    