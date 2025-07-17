FROM docker.io/python:3.12-slim-bookworm

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install curl for healthchecks
RUN apt-get update && apt-get install -y curl

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Run the application when the container launches
CMD ["python", "-u", "oxidized_inventory_api.py"]
