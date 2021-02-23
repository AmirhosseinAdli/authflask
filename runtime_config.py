import os

class ConfigServer():
    #DB_URL = "192.168.1.106"
    DB_URL = os.environ.get("DB_URL", "localhost")
    #DB_USERNAME = "root"
    DB_USERNAME = os.environ.get("DB_USERNAME", "amirhosseinadli")
    DB_SCHEMA = os.environ.get("DB_SCHEMA", "myflask")
    #DB_PASSWORD = "root"
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "Bbbb1374")
    DB_PORT = os.environ.get("DB_PORT", "3306")
