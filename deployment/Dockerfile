# Privatus-chat Docker Image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY launch_gui.py ./
COPY pyproject.toml ./
COPY README.md ./

# Create data directory
RUN mkdir -p /app/data

# Create non-root user
RUN useradd --create-home --shell /bin/bash privatus
RUN chown -R privatus:privatus /app
USER privatus

# Expose port for P2P networking (if needed)
EXPOSE 8000-9000

# Set data directory environment variable
ENV PRIVATUS_DATA_DIR=/app/data

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.path.append('.'); from src.main import main; print('Health check passed')" || exit 1

# Default command
CMD ["python", "launch_gui.py"]