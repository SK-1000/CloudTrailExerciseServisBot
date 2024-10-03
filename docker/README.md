
# MySQL Anomaly Detection

## Pre-requisites
- Docker installed on your machine

## Build the docker image

```
docker build -t mysql-anomaly-detection .
```

- -t mysql-anomaly-detection: Tags the image with the name mysql-anomaly-detection.
- .: Specifies the current directory as the build contex

## Run the docker container

```
docker run -d \
  --name mysql-container \
  -p 3306:3306 \
  mysql-anomaly-detection
```

- -d: Runs the container in detached mode.
- --name mysql-container: Names the container mysql-container.
- -p 3306:3306: Maps port 3306 on the host to port 3306 in the container.


If you plan on importing data using docker exec (assuming your ata is in a file called anomalies.sql, use the command
```
docker exec -i mysql-container mysql -uroot -prootpw anomaly_detection < anomalies.sql
``` 

## Connect to the MySQL container 
### OPTION 1 - using Docker exec

```
docker exec -it mysql-container mysql -uroot -prootpw
```

- -it: Starts an interactive terminal.
- mysql -uroot -prootpw: Connects to the MySQL server as the root user with the password rootpw.


### OPTION 2 - using MySQL client

```
mysql -h 127.0.0.1 -P 3306 -uroot -prootpw
```

## Verify the MySQL database and table
```
SHOW DATABASES;
USE anomaly_detection;
SHOW TABLES;
DESCRIBE anomalies;
```


## Clean up
```
docker stop mysql-container
docker rm mysql-container
docker rmi mysql-anomaly-detection
```