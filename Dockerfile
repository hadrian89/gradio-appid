FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy and install requirements
# Copy requirement files and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code AFTER model download
COPY ./app ./app

# Expose port
# EXPOSE 8000

# Set the entrypoint
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# docker build -t gradio-appid .
# docker run -p 8000:8000 gradio-appid