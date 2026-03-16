"""Database configuration from environment variables."""
import os
from dotenv import load_dotenv

load_dotenv()


def get_db_config():
    """Build MySQL connection config from environment."""
    return {
        # 'host': os.environ.get('MYSQL_HOST', '34.60.195.24'),
        # 'user': os.environ.get('MYSQL_USER', 'maximus'),
        # 'password': os.environ.get('MYSQL_PASSWORD', 'Maximus@123'),
        # 'database': os.environ.get('MYSQL_DATABASE', 'vapt_db'),
        'host': os.environ.get('MYSQL_HOST', 'localhost'),
        'user': os.environ.get('MYSQL_USER', 'root'),
        'password': os.environ.get('MYSQL_PASSWORD', ''),
        'database': os.environ.get('MYSQL_DATABASE', 'vapt_db'),
        'autocommit': False,
        'pool_name': 'vapt_pool',
        'pool_size': 5,
        'pool_reset_session': True,
    }
