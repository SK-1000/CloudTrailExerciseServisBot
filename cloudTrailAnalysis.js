// Cloudtrail Technical Exercise for ServisBot
// Author Sheila Kirwan
// This script parses the provided CloudTrail logs and identifies potential anomalies, rating them as low, medium, or high risk. The script outputs the results to a CSV file. 
require('dotenv').config()

//Libraries
const fs = require('fs'); 
const path = require('path');
const { createObjectCsvWriter } = require('csv-writer');
const ip = require('ip');
const nodemailer = require('nodemailer');


// Configuration
const folderPath = './cloudtrail_logs';  //Path to the folder containing CloudTrail log files.
const csvOutputPath = 'cloudTrailOutput.csv'; //Path to the output CSV file that stores the anomalies found.
//his sets up the email transport service using Gmail. Authentication credentials (email and password) are retrieved from environment variables.
const transporter = nodemailer.createTransport({
  service: 'Gmail', 
  auth: {
    user: process.env.USER,
    pass: process.env.EMAIL_PASSWORD // Please ensure to add your Gmail password here when testing
  }
});

// CSV Writer setup
const csvWriter = createObjectCsvWriter({
  path: csvOutputPath,
  header: [
    { id: 'eventID', title: 'Event Id' },
    { id: 'eventTime', title: 'Event Time' },
    { id: 'eventName', title: 'Event Name' },
    { id: 'riskRating', title: 'Risk Rating' },
    { id: 'details', title: 'Details' },
    { id: 'sourceIPAddress', title: 'Source IP Address' },
    { id: 'awsRegion', title: 'AWS Region' },
    { id: 'eventSource', title: 'Event Source' },
    { id: 'userIdentityType', title: 'User Identity Type' },
    { id: 'reason', title: 'Reason' },
  ],
});

// Function to send email alert
const sendEmailAlert = (subject, message) => {
  const mailOptions = {
    from: process.env.USER,
    to: process.env.RECEIVER,
    subject: subject,
    text: message
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

// Function to determine risk rating and reason
// Define high-risk AWS regions, approved services, and check for risky events.
// Assign risk based on criteria like IP address, AWS region, IAM policy changes, etc.
// Add relevant reasons for the risk rating to an array and log corresponding alerts.
const rateRisk = (event, isIpValid, failedLoginAttempts, alerts) => {
  const usEuRegions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-south-1', 'eu-west-3', 'eu-south-2', 'eu-north-1', 'eu-central-2'];
  const approvedServices = ['lambda.amazonaws.com', 'dynamodb.amazonaws.com', 's3.amazonaws.com', 'cloudwatch.amazonaws.com', 'secretsmanager.amazonaws.com', 'ecs.amazonaws.com'];

  let riskRating = 'Low';
  let reason = [];

  //this might be temporary.
  const setRisk = (newRisk, newReason) => {
    if (newRisk === 'High' || (newRisk === 'Medium' && riskRating === 'Low')) {
      riskRating = newRisk;
      reason.push(newReason);
    }
  };

   // Check for manual deletion
  const isManualDeletion = /Delete/i.test(event.eventName) && 
                           (event.userIdentity?.type === 'IAMUser' || event.userIdentity?.type === 'Root');

  if (isManualDeletion) {
    // riskRating = 'High';
    reason.push('HIGH RISK: Manual Deletion may have occurred; investigation required,');
    alerts.push(`HIGH RISK: Manual deletion detected by ${event.userIdentity.arn} on ${event.eventName}. Event ID: ${event.eventID}.`);
  }

  // Check for IAM policy creation - forbidden
  const isIamPolicyCreation = event.eventSource === 'iam.amazonaws.com' && event.eventName === 'CreatePolicy';

  if (isIamPolicyCreation) {
    const userName = event.userIdentity?.userName || 'Unknown User';
    alerts.push(`HIGH RISK: User (${userName}) created a new IAM policy. Event ID: ${event.eventID}.`);
    // riskRating = 'High';
    reason.push(`HIGH RISK: User has illegally created a new IAM policy: ${userName},`);
  }

  // Check for IAM policy changes
  const iamChangeActions = [
    'DeletePolicy',
    'AttachUserPolicy',
    'DetachUserPolicy',
    'AttachGroupPolicy',
    'DetachGroupPolicy',
    'PutUserPolicy',
    'DeleteUserPolicy',
    'PutGroupPolicy',
    'DeleteGroupPolicy'
  ];

  const isIamPolicyChange = event.eventSource === 'iam.amazonaws.com' && iamChangeActions.includes(event.eventName);

    // Check for IP validity
  if (!isIpValid) {
    // riskRating = 'Medium';
    setRisk('Medium', 'MEDIUM RISK: IP address is outside the allowed ranges' )
    reason.push('MEDIUM RISK: IP address is outside the allowed ranges,');
    alerts.push(`MEDIUM RISK: Event ID ${event.eventID} from outside allowed IP ranges: ${event.sourceIPAddress}.`);
  }

  // Check region validity
  if (!usEuRegions.includes(event.awsRegion)) {
    // riskRating = 'Medium';
    setRisk('Medium', 'MEDIUM RISK: Event from an unsupported AWS region' )
    reason.push(`MEDIUM RISK: Event from an unsupported AWS region: ${event.awsRegion},`);
    alerts.push(`MEDIUM RISK: Event ID ${event.eventID} detected in unsupported AWS region: ${event.awsRegion}.`);
  }

  if (!approvedServices.includes(event.eventSource)) {
    // riskRating = 'Medium';
    setRisk('Medium', 'Event using unapproved service' )
    reason.push(`MEDIUM RISK: Event using unapproved service: ${event.eventSource},`);
    alerts.push(`MEDIUM RISK: Event ID ${event.eventID} is using a service outside approved services: ${event.eventSource}.`);
  }

  if (isIamPolicyChange) {
    const userName = event.userIdentity?.userName || 'Unknown User';
    alerts.push(`HIGH RISK: User (${userName}) changed IAM policy. Event ID: ${event.eventID}.`);
    // riskRating = 'High';
    setRisk('High', 'User has made changes to IAM policies' )
    reason.push(`HIGH RISK: User has made changes to IAM policies: ${userName},`);
  }

  // Check for high-risk operations on production resources
  const isProductionTaggedEC2 = event.eventSource === 'ec2.amazonaws.com' && 
    (event.requestParameters?.tagSet?.some(tag => tag.Key === 'Environment' && tag.Value === 'production') || 
    event.requestParameters?.instancesSet?.items?.some(item => 
      item.instanceId?.includes('prod') || 
      item.instanceId?.includes('production')));

  const isHighRiskOperation = /Delete|delete|modif/i.test(event.eventName);
  const isProductionTagBucketS3 = event.eventSource === 's3.amazonaws.com' && event.requestParameters?.bucketName?.includes('prod');

  if ((isProductionTagBucketS3 || isProductionTaggedEC2) && isHighRiskOperation) {
    // riskRating = 'High';
    setRisk('High', 'Deletion or modification of production resource' )
    reason.push('HIGH RISK: Deletion or modification of production resource; review required,');
    alerts.push(`HIGH RISK: Deletion/modification in production resource detected. Event ID: ${event.eventID}.`);
  }

  // Compliance checks
  const isS3WithEncryption = event.eventSource === 's3.amazonaws.com' && event.requestParameters?.ServerSideEncryption === 'aws:kms';
  const isRDSWithEncryption = event.eventSource === 'rds.amazonaws.com' && event.requestParameters?.StorageEncrypted;
  const isEncryptedFileSystem = event.eventSource === 'elasticfilesystem.amazonaws.com' && event.requestParameters?.Encrypted;

  if (isS3WithEncryption || isRDSWithEncryption || isEncryptedFileSystem) {
    // riskRating = 'High';
    setRisk('High', 'Event does not meet compliance requirements for encryption' )
    reason.push('HIGH RISK: Event does not meet compliance requirements for encryption,');
    alerts.push(`HIGH RISK: Event ID ${event.eventID} does not meet compliance requirements for encryption.`);
  }

  

  if (event.userIdentity?.type === 'Root') {
    // riskRating = 'High';
    setRisk('High', 'Root user usage is strictly forbidden' )
    reason.push('HIGH RISK: Root user usage is strictly forbidden,');
    alerts.push(`HIGH RISK: Event ID ${event.eventID} detected from Root user: ${event.userIdentity.arn}.`);
  }

  // Check for multiple failed login attempts
  const isFailedLogin = event.eventSource === 'signin.amazonaws.com' && event.responseElements?.ConsoleLogin === 'Failure';

  if (isFailedLogin) {
    failedLoginAttempts.push(event); // Store the failed login attempt

    // Check if there are multiple failed login attempts
    if (failedLoginAttempts.length >= 5) { // Threshold for multiple attempts
      // riskRating = 'High';
      setRisk('High', 'Multiple failed login attempts require review' )
      reason.push('High RISK: Multiple failed login attempts require review,');
      alerts.push(`High RISK: User ${event.userIdentity.arn} has multiple failed login attempts.`);
    }
  }


  return { riskRating, reason: reason.join(' ') };
};

// Function to check if an IP is within specified ranges
const isIpInRange = (ipAddress) => {
  const ranges = ['192.168.1.0/24', '10.0.0.0/16'];
  return ranges.some(range => ip.cidrSubnet(range).contains(ipAddress));
};



const analyzeLogs = () => {
    const anomalies = [];
    const alerts = [];
    let totalEvents = 0;
    let highRiskCount = 0;
    let mediumRiskCount = 0;
    let lowRiskCount = 0;
    let failedLoginAttempts = [];
  
    fs.readdir(folderPath, (err, files) => {
      if (err) throw err;
  
      const jsonFiles = files.filter(file => path.extname(file) === '.json');
  
      // Use Promise.all to ensure all files are processed before proceeding
      const fileProcessingPromises = jsonFiles.map(file => {
        const filePath = path.join(folderPath, file);
  
        return new Promise((resolve, reject) => {
          fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) return reject(err);
  
            const jsonData = JSON.parse(data);
            const eventsArray = jsonData.Records || []; 
  
            eventsArray.forEach(event => {
              totalEvents++;
              const isIpValid = isIpInRange(event.sourceIPAddress);
              const { riskRating, reason } = rateRisk(event, isIpValid, failedLoginAttempts, alerts);
  
              // Count risks by category
              if (riskRating === 'High') {
                highRiskCount++;
              } else if (riskRating === 'Medium') {
                mediumRiskCount++;
              } else {
                lowRiskCount++;
              }
  
              if (riskRating !== 'Low') {
                anomalies.push({
                  eventID: event.eventID,
                  eventTime: event.eventTime,
                  eventName: event.eventName,
                  userIdentity: event.userIdentity?.arn || event.userIdentity?.principalId || 'Unknown',
                  userIdentityType: event.userIdentity?.type || 'Unknown',
                  riskRating,
                  details: JSON.stringify(event.requestParameters || {}),
                  sourceIPAddress: event.sourceIPAddress,
                  awsRegion: event.awsRegion,
                  eventSource: event.eventSource,
                  reason
                });
              }
            });
            resolve(); // Resolve the promise after processing the file
          });
        });
      });
  
      // Once all files are processed, write to CSV and send email if needed
      Promise.all(fileProcessingPromises).then(() => {
        csvWriter.writeRecords(anomalies)
          .then(() => {
            console.log(`Anomalies have been written to ${csvOutputPath}.`);
            console.log(`Total events processed: ${totalEvents}`);
            console.log(`High risk events: ${highRiskCount}`);
            console.log(`Medium risk events: ${mediumRiskCount}`);
            console.log(`Low risk events: ${lowRiskCount}`);
  
            // Send a single email with all alerts
            if (alerts.length > 0) {
              const subject = 'CloudTrail Log Alerts';
              const message = alerts.join('\n'); // Join alerts for the email body
              sendEmailAlert(subject, message);
            }
          })
          .catch(err => {
            console.error('Error writing to CSV:', err);
          });
      }).catch(err => {
        console.error('Error processing files:', err);
      });
    });
  };
  
  // Run the log analysis
  analyzeLogs();
