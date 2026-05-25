# DNS Shield - Production Dockerfile
# Multi-stage build for optimized container size

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application files
COPY new_app.py .
COPY src/ ./src/
COPY models/ ./models/
COPY feature_mapper.py .

# Create output directories
RUN mkdir -p /app/logs /app/data

# Expose Flask port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/stats || exit 1

# Set environment variables
ENV FLASK_APP=new_app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app:/app/src"
# Run the application
CMD ["python", "new_app.py"]