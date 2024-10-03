# README

## Exercise: Anomaly Detection and Risk Assessment in AWS CloudTrail Logs

### **Objective**

You are tasked with analyzing [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) logs to detect anomalous activities within our organization's AWS environment. Your analysis should be guided by the **Company Security Policy** provided. The goal is to:

- **Develop a javascript script** to parse the CloudTrail logs and identify potential anomalies.
- **Assign a risk score** (Low, Medium, High) to each detected anomaly based on potential impact.
- **Generate an executive report** summarizing your findings for C-level executives.
- **Document your approach** in a `solution.md` file, including your methodology, assumptions, and risk scoring reasoning.
- **Stretch Goal (Optional)**: Export the anomalies to a MySQL database and provide SQL queries demonstrating how a business analyst can further explore the findings.

---

### **Deliverables**

1. **Anomaly Detection Script** (`detectAnomalies.js` or `mjs`):

   - Parses the provided CloudTrail logs.
   - Identifies potential anomalies based on the security policy.
   - Outputs anomalies to a `report.json` or `report.csv` file.

2. **Executive Report** (`ExecutiveReport.md` or `.pdf`):

   - High-level single page summary aimed at C-level executives.
   - Highlights the level of risk in the company based on your findings.
   - Can include graphs or visualizations (optional).

3. **Solution Documentation** (`solution.md`):

   - Very briefly describes your approach to the problem.
   - Details your risk scoring methodology.
   - Lists any assumptions or considerations made during your analysis.

4. **Stretch Goal (Optional)**:

   - Exports anomalies to a MySQL database using the provided schema.
   - Includes sample SQL queries for business analysts.
   - Provides instructions for setting up the database and importing the data.

---

### **Instructions**

1. **Read the Company Security Policy** carefully.

2. **Identify Anomalies**:

   - Based on the provided security policy, determine which types of events constitute anomalies.
   - Based on the capabilities of CloudTrail logs, identify patterns that indicate potential risks. Not everything listed in the policy can be detected using CloudTrail logs.
   - Pick 2 or 3 types of anomalies to focus on.

3. **Develop the Script**:

   - Use the provided CloudTrail logs in the `synthetic_cloudtrail_logs` directory.
   - Script should be javascript based, and should be deterministic. 
   - Ensure the script efficiently parses the logs and detects anomalies. 
   - Assign a risk score to each anomaly based on potential impact (optional)

4. **Generate the Report**:

   - The script should output anomalies to a `report.json` or `report.csv` file.
   - Include relevant details:

     - User Identity (e.g., `userName`, `userType`)
     - Event Id
     - Event Source
     - Event Name
     - AWS Region
     - Source IP address
     - Geolocation (optional)
     - Risk level (optional)

5. **Create the Executive Report**:

   - Summarize your findings in a concise, high-level manner suitable for executives.
   - Highlight key risks and potential impacts on the organization.
   - Use visualizations if they add value, feel free to use something like Google Sheets to generate charts, they do not need to be programmatic. (optional)

6. **Document Your Solution**:

   - In `solution.md`, explain your methodology, reasoning, and any assumptions.

7. **Stretch Goal (Optional)**:

   - Export anomalies to a MySQL database.
   - Use the provided docker image or create a local mysql database using the the provided schema as a guideline.
   - Provide SQL queries that demonstrate how a business analyst can explore the data.
   - Include instructions for setting up the database and importing the data.

---

### **MySQL Schema for Stretch Goal**

```sql
CREATE TABLE anomalies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user VARCHAR(255),
  event_source VARCHAR(255),
  event_name VARCHAR(255),
  source_ip VARCHAR(50),
  aws_region VARCHAR(50),
  risk VARCHAR(10)
);
```

### **Additional Notes**

- **Focus on Quality Over Quantity**:

  - It is better to thoroughly analyze a few types of anomalies than to superficially cover many.

- **Assumptions**:

  - Document any assumptions you make during the exercise.

- **Clarity and Professionalism**:

  - Ensure your code is well-organized and your report is clear and concise.

---

### **Time Estimate**

- **Core Tasks**: Approximately 2-3 hours.
- **Stretch Goal**: Additional ~1 hour (if time permits).

---

### **Getting Started**

1. **Set Up Environment**:

   - Ensure you have access to the necessary programming tools and environments.
   - Install any required libraries or dependencies.
   - Note: The script should be written in javascript.
   - Note: Docker or MySQL setup is required for the optional stretch goal.

2. **Data Files**:

   - The CloudTrail logs are provided in the `cloudtrail_logs` directory.
   - Ensure your script can access and process these logs.

3. **Hints**:

    - Take some time looking at the logs to understand the structure.
    - How can you identify all the unique users, event sources, event names, etc? Maybe this will help you to choose anomalies to focus on.
    - Consider the potential impact of each anomaly on the organization when assigning risk scores.
    - Think about how you can present the data in a clear and concise manner. A single paragraph summary and a barchart can often be more effective than a page of text.

4. **Questions**:

   - If you have any questions or need clarification, please reach out promptly.

---

**We look forward to reviewing your submission. Good luck!**