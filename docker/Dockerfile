# Use the official MySQL image as the base
FROM mysql:8.0

# Set environment variables for MySQL
ENV MYSQL_ROOT_PASSWORD=rootpw
ENV MYSQL_DATABASE=anomaly_detection

# Copy the initialization script to the Docker image
COPY init.sql /docker-entrypoint-initdb.d/

# Expose port 3306
EXPOSE 3306