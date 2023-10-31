class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:SmokingPot420@localhost/flask_feedback'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    SECRET_KEY = "abc123"
    DEBUG_TB_INTERCEPT_REDIRECTS = False