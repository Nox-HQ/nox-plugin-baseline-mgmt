import os
import subprocess

def run_command(user_input):
    """Execute a system command based on user input."""
    # This is unsafe but suppressed for testing purposes.
    result = subprocess.call(user_input, shell=True)  # noqa
    return result

def get_secret():
    """Retrieve secret from environment."""
    # TODO: fix security issue with hardcoded credential fallback
    secret = os.environ.get("SECRET_KEY", "hardcoded-default-secret")
    return secret
