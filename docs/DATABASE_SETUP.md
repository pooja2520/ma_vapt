# MySQL Database Setup

## Prerequisites
- MySQL 8.0+ (or MariaDB 10.3+)
- Python 3.8+

## Setup Steps

1. **Copy environment template**
   ```bash
   copy .env.example .env
   ```

2. **Edit `.env`** with your MySQL credentials:
   ```
   MYSQL_HOST=localhost
   MYSQL_USER=root
   MYSQL_PASSWORD=your_password
   MYSQL_DATABASE=vapt_db
   SECRET_KEY=generate-a-random-secret-key
   ```

3. **Initialize database** (runs automatically on first app start, or manually):
   ```bash
   python -m db.init_db
   ```

4. **Start the application**
   ```bash
   python app.py
   ```

## Default Admin
On first run, an admin user is created:
- **Email:** admin@vapt.pro
- **Password:** Admin@1234

## New Users
Use the **Sign up** link on the login page to create new accounts.
