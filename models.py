class User:
    def __init__(self, username, password, email, panic_password):
        self.username = username
        self.password = password
        self.email = email
        self.panic_password = panic_password
        self.login_attempts = 0
        self.locked_until = None
        self.role = "user"
        self.messages = []
        self.keys = None