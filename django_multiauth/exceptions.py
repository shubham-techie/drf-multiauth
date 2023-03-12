class IdentityModelObjectError(Exception):
    """
    Exception raised when Identity model object is created.
    """
    

class NoPrimaryIdentity(Exception):
    """
    Exception raised when user do not have any primary email or phoneNumber set.
    """


class AuthenticationFailed(Exception):
    """
    Exception raised when login failed in case of following conditions : 
        1. invalid credentials
        2. invalid OTP/link
        3. expired OTP/link
    """
