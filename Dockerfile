FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/groups/*

# Install Python requirements
COPY frontend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project code, model, and SQLite database
COPY . .

# Expose Hugging Face default port 7860
EXPOSE 7860

# Launch server
CMD ["uvicorn", "frontend.server:app", "--host", "0.0.0.0", "--port", "7860"]
