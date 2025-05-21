from auth.SecureLayer import SecureLayer
from auth.auth_logging import setup_logging
from auth.onboarding import Setup
from auth.login import Login
import os

class Directer:
    
    def __init__(self):
        """
        Initializes the Directer class, sets up encryption layer, paths, and logger.
        Automatically calls the direct() method to route to login or onboarding.
        """
        
        self.enc = SecureLayer()
        self.user_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs", "DarkCrypt")
        self.logger = setup_logging()
        self.logger.info("App Started")
        self.direct()
        self.logger.info("App Closed")
        self.logger.info("="*50)
        
    def direct(self):
        """
        Checks if encrypted data file exists.
        If yes, launches login.
        If no, attempts to backup any existing data file and launches onboarding.
        """
        
        try:
            if self.enc.chk_if_exists():
                self.logger.info("Found User Data, Opening Login")
                login = Login()
                login.mainloop()
                
            else:
                try:
                    os.rename(os.path.join(self.user_path, "data.enc"), "backup.enc")
                except:
                    self.logger.error("No Records Found")
                self.logger.info("Opening First time setup")
                setup = Setup()
                setup.mainloop()
        except Exception as e:
            self.logger.error("Error while directing to authentication")
    
    
def main():
    """ Entry point to launch the Directer app controller. """
    Directer()
    
if __name__ == "__main__":
    main()
    