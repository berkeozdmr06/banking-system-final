# Use official Python lightweight image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from the backend folder
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code into respective directories
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Move into backend to run main.py
WORKDIR /app/backend

# Render dynamic port and run
CMD ["python", "main.py"]
