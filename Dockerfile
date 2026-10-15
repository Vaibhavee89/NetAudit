# Use official Python image
FROM python:3.10-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install only required system dependencies and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy all files
COPY . .

# Run the Flask web application
EXPOSE 5000
CMD ["python", "webapp.py"]
