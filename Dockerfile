# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port that your Python app will use
EXPOSE 5010

# Command to run the Python app (replace app.py with your main Python file)
CMD ["python", "main.py"]
