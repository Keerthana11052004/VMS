# VMS Pro Database Setup Guide

## Overview
The VMS Pro application supports multiple database types:
- **SQLite** (default, file-based)
- **MySQL** (recommended for production)
- **PostgreSQL** (alternative for production)

## Database Configuration

### Environment Variables
The application uses environment variables to configure the database connection:

```bash
# Database Type (sqlite, mysql, postgresql)
DB_TYPE=mysql

# Database Connection URL
DATABASE_URL=mysql+pymysql://root:Violin%4012@localhost/vms_pro
```

### Configuration Files
- `config.py` - Main configuration file
- `.env` - Environment variables (optional)
- `init_db.py` - Database initialization script

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Database Setup

#### Option A: MySQL (Recommended)
```bash
# Set environment variables
$env:DB_TYPE="mysql"

# Initialize database
python init_db.py

# Run application
python run_mysql.py
```

#### Option B: SQLite (Default)
```bash
# Run with default SQLite
python app.py
```

## Database Connection Details

### MySQL Configuration
- **Host**: localhost
- **Port**: 3306 (default)
- **Database**: vms_pro
- **Username**: root
- **Password**: Violin@12

### Database Schema

#### Users Table
```sql
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(120) NOT NULL,
    role VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    department VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### Visitors Table
```sql
CREATE TABLE visitor (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120),
    mobile VARCHAR(20) NOT NULL,
    purpose TEXT NOT NULL,
    host_id INTEGER NOT NULL,
    id_proof_path VARCHAR(200),
    status VARCHAR(20) DEFAULT 'pending',
    check_in_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    check_out_time DATETIME,
    qr_code VARCHAR(200),
    created_by INTEGER NOT NULL,
    FOREIGN KEY (host_id) REFERENCES user(id),
    FOREIGN KEY (created_by) REFERENCES user(id)
);
```

## Default Users

The system creates these default users automatically:

| Username | Password | Role | Department |
|----------|----------|------|------------|
| root | Violin@12 | admin | IT |
| admin | admin123 | admin | IT |
| security | security123 | security | Security |
| employee | employee123 | employee | Sales |

## Running the Application

### Method 1: Using run_mysql.py (Recommended)
```bash
python run_mysql.py
```

### Method 2: Manual Environment Setup
```bash
# Set environment variables
$env:DB_TYPE="mysql"
$env:DATABASE_URL="mysql+pymysql://root:Violin%4012@localhost/vms_pro"

# Run application
python app.py
```

### Method 3: Using .env file
```bash
# Create .env file with:
DB_TYPE=mysql
DATABASE_URL=mysql+pymysql://root:Violin%4012@localhost/vms_pro

# Run application
python app.py
```

## Database Operations

### Creating New Users
When you add users through the web interface, they are automatically stored in the database.

### Creating New Visitors
When you register visitors through the web interface, they are automatically stored in the database.

### Data Persistence
All data (users, visitors, approvals, etc.) is stored in the MySQL database and persists between application restarts.

## Troubleshooting

### MySQL Connection Issues
1. **Check MySQL Service**: Ensure MySQL is running
2. **Verify Credentials**: Check username/password
3. **Check Port**: Default MySQL port is 3306
4. **Network Access**: Ensure localhost access is allowed

### Common Errors
- **"Can't connect to MySQL server"**: MySQL service not running
- **"Access denied"**: Wrong username/password
- **"Database doesn't exist"**: Run `python init_db.py` first

### Reset Database
```bash
# Drop and recreate database
python init_db.py
```

## Production Deployment

For production environments:
1. Use strong passwords
2. Configure proper MySQL security
3. Set up database backups
4. Use environment variables for sensitive data
5. Consider using connection pooling

## Support

If you encounter issues:
1. Check the application logs
2. Verify database connectivity
3. Ensure all dependencies are installed
4. Check environment variable configuration

