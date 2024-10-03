-- Use the specified database
USE anomaly_detection;

-- Create the 'anomalies' table
CREATE TABLE IF NOT EXISTS anomalies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user VARCHAR(255),
  event_source VARCHAR(255),
  event_name VARCHAR(255),
  source_ip VARCHAR(50),
  aws_region VARCHAR(50),
  risk VARCHAR(10)
);