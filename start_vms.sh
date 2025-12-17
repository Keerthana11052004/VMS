#!/bin/bash

# VMS Pro - Visitor Management System Startup Script
# For Linux and macOS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "============================================================"
echo "    VMS Pro - Visitor Management System"
echo "============================================================"
echo -e "${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 is not installed${NC}"
    echo "Please install Python 3.7 or higher"
    echo "Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "macOS: brew install python3"
    exit 1
fi

echo -e "${GREEN}Checking Python version...${NC}"
python3 --version

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create virtual environment${NC}"
        exit 1
    fi
fi

# Activate virtual environment
echo -e "${GREEN}Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to install dependencies${NC}"
        exit 1
    fi
fi

# Create uploads directory if it doesn't exist
if [ ! -d "uploads" ]; then
    echo -e "${YELLOW}Creating uploads directory...${NC}"
    mkdir uploads
fi

echo -e "${BLUE}"
echo "============================================================"
echo "    Starting VMS Pro Server..."
echo "============================================================"
echo -e "${NC}"

echo -e "${GREEN}Default Login Credentials:${NC}"
echo "  Admin: admin / admin123"
echo "  Security: security / security123"
echo "  Employee: employee / employee123"
echo ""
echo -e "${GREEN}Access URL:${NC} http://localhost:5002"
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""

# Start the application
python3 run.py

