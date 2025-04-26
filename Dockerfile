FROM python:3.8-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    libmodsecurity3 \
    modsecurity-crs \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/
COPY logs/ /app/logs/

# Configure Nginx and ModSecurity
COPY config/nginx/default.conf /etc/nginx/conf.d/
COPY config/modsecurity/modsecurity.conf /etc/modsecurity.d/

# Create necessary directories
RUN mkdir -p /var/log/nginx /var/log/modsecurity

# Set up logging
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# Expose ports
EXPOSE 80 443

# Start services
CMD ["gunicorn", "--bind", "0.0.0.0:80", "src.main:app"] 