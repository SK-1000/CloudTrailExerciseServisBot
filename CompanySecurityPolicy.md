### **Company Security Policy**
---

#### **Introduction**

This policy outlines the security standards and procedures for protecting the company's assets, data, and IT infrastructure. All employees, contractors, and third-party users must adhere to these policies to ensure the confidentiality, integrity, and availability of company resources.

#### **Access Control**

- **User Authentication**:

  - All users must have unique login credentials.
  - Multi-Factor Authentication (MFA) is mandatory for all remote access.
  - Use of shared accounts is strictly prohibited.

- **Password Policy**:

  - Passwords must be at least 12 characters long and include a mix of uppercase letters, lowercase letters, numbers, and special characters.
  - Passwords must be changed every 90 days.
  - Reuse of the last five passwords is prohibited.

- **Account Lockout**:

  - Accounts will be locked out after five unsuccessful login attempts.
  - Locked accounts can only be reset by contacting the IT Support Team.

#### **Network Security**

- **Approved IP Ranges**:

  - Access to company resources is permitted only from the following IP ranges:

    - Headquarters VPN: `192.168.1.0/24`
    - Remote Offices VPN: `10.0.0.0/16`

- **VPN Usage**:

  - All remote connections must be made via an approved VPN.
  - Split tunneling is not allowed.
  - VPN clients must be kept up to date.

- **Geographical Access Restrictions**:

  - Employees are based in the United States and Ireland.
  - Access from other countries requires prior approval from the Security Team.

#### **Data Handling**

- **Data Classification**:

  - **Public**: Information intended for public dissemination.
  - **Internal**: Information intended for internal use within the company.
  - **Confidential**: Sensitive information requiring strict access controls, such as customer data, financial records, and proprietary code.

- **Data Storage**:

  - Confidential data must be stored in encrypted form.
  - Approved storage services include:

    - AWS S3 with server-side encryption
    - AWS RDS with encryption at rest
    - Encrypted file systems on approved servers

- **Data Transfer**:

  - Confidential data must not be transferred via unencrypted channels.
  - Use secure protocols like SFTP, HTTPS, or VPN.

#### **AWS Usage Policies**

- **Approved AWS Services**:

  - The following AWS services are approved for use:

    - AWS Lambda
    - Amazon DynamoDB
    - Amazon S3 (Bucket deletion or duplication in production is strictly prohibited without prior approval)
    - Amazon CloudWatch
    - AWS Secrets Manager (Extra caution should be taken with this service, employees should not fetch sensitive data from this service without prior approval) 
    - AWS ECS

  - Use of any AWS services not listed requires a security review and written approval from the Security Team.

- **IAM Policies and Permissions**:

  - All IAM policies must follow the principle of least privilege.
  - Changes to IAM policies require approval from the Security Team.
  - Creation of IAM users is strictly forbidden. IAM Roles should be used instead.
  - Use of AWS root account is strictly prohibited.

- **Resource Management**:

  - **Resource Naming Conventions**:

    - Production resources must have names starting with `prod-`.
    - Resources must be tagged appropriately with:

      - `Environment`: `Production`, `Staging`, `Development`
      - `Owner`: Team or individual responsible
      - `Project`: Project name

  - **Critical Resources**:

    - Deletion or modification of critical resources (e.g., S3 buckets with the prefix `prod-`, EC2 instances tagged as `Environment: Production`) must be logged and reviewed.
    - Manual deletions are rare and require documented approval.

#### **Monitoring and Logging**

- **Logging Requirements**:

  - AWS CloudTrail must be enabled in all regions and for all accounts.
  - Logs must be stored centrally and retained for a minimum of one year.
  - Access to logs is restricted to the Security Team.

- **Anomaly Detection and Alerts**:

  - Regular audits must be conducted to detect unauthorized or anomalous activities.
  - Automated alerts must be set up for:

    - Access from unapproved IP addresses or countries
    - Use of unapproved AWS services
    - Changes to IAM policies or roles
    - Creation or deletion of IAM users
    - Deletion or modification of production resources
    - Multiple failed login attempts

#### **Incident Response**

- **Reporting Incidents**:

  - All security incidents must be reported immediately to the Security Team via the incident reporting system.
  - An initial incident report must be filed within 24 hours.

- **Incident Handling Procedures**:

  - The Security Team will assess the incident severity and coordinate the response.
  - Steps may include:

    - Containing the incident
    - Eradicating the threat
    - Recovering affected systems
    - Conducting a post-incident review

#### **Physical Security**

- **Office Access**:

  - Access to company offices requires a valid access badge.
  - Visitors must sign in, wear a visitor badge, and be escorted at all times.

- **Equipment Security**:

  - Company laptops and mobile devices must be encrypted and have up-to-date security software.
  - Lost or stolen devices must be reported immediately to the IT Support Team.

#### **Compliance**

- **Regulatory Requirements**:

  - The company must comply with all applicable laws and regulations, including:

    - General Data Protection Regulation (GDPR)
    - Health Insurance Portability and Accountability Act (HIPAA)
    - Payment Card Industry Data Security Standard (PCI DSS)

  - Regular compliance audits will be conducted.

#### **Acceptable Use**

- **Internet and Email Usage**:

  - Internet access is provided for business purposes.
  - Personal use must not interfere with work responsibilities.
  - Accessing inappropriate or illegal content is strictly prohibited.

- **Software Installation**:

  - Only approved software may be installed on company devices.
  - Installation of unauthorized software is prohibited and may result in disciplinary action.

#### **Training and Awareness**

- **Mandatory Training**:

  - All employees must complete annual security awareness training.
  - Specialized training is required for roles with elevated privileges or access to sensitive data.

- **Security Awareness Communications**:

  - The Security Team will provide regular updates on security best practices and emerging threats.

#### **Enforcement**

- **Policy Violations**:

  - Violations of this policy may result in disciplinary action, up to and including termination of employment.
  - The company reserves the right to monitor and audit compliance with this policy.

---