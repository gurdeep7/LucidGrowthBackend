# Backend API for SSL Certificate Checker

## Overview

This is a backend server built using Node.js and Express to provide SSL certificate information. The API endpoint processes requests for SSL certificate details and responds with structured information about the certificate's validity, issuer, subject, and more.

## Technology Stack

- **Node.js (v18.7+)**: Provides a runtime environment for executing JavaScript code server-side.
- **Express.js**: A web framework for Node.js that simplifies the creation of server-side applications and APIs.
- **node-forge**: A library for handling SSL/TLS certificates and cryptographic operations.

## API Endpoint

### `/api/ssl-info`

**Method**: POST

**Description**: Retrieves SSL certificate information for a given domain.

**Request Body**:

```json
{
  "domain": "example.com"
}
```

**Response**:

```json
{
  "validity": {
    "valid": "Valid",
    "validFrom": "2024-01-01T00:00:00.000Z",
    "validTo": "2024-12-31T23:59:59.999Z"
  },
  "issuer": "CN: Issuer Name, O: Organization, C: Country",
  "subject": "CN: example.com, O: Organization, C: Country",
  "validForDomain": "Yes",
  "caValid": "Valid",
  "selfSigned": "No",
  "revoked": "Not Revoked",
  "daysRemaining": 100
}
```

**Fields**:

- `validity.valid`: Indicates whether the certificate is currently valid (`Valid` or `Invalid`).
- `validity.validFrom`: ISO 8601 formatted date when the certificate is valid from.
- `validity.validTo`: ISO 8601 formatted date when the certificate is valid until.
- `issuer`: Issuer details of the certificate.
- `subject`: Subject details of the certificate.
- `validForDomain`: Indicates if the certificate is valid for the input domain (`Yes` or `No`).
- `caValid`: CA validity status (`Valid` or `Invalid`).
- `selfSigned`: Indicates if the certificate is self-signed (`Yes` or `No`).
- `revoked`: Status of certificate revocation (`Revoked` or `Not Revoked`).
- `daysRemaining`: Number of days remaining until the certificate expires.

## Running the Project

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Start the Server**:
   ```bash
   npm start
   ```

4. **Access the API**:
   The server will be running on `http://localhost:3001`. Use tools like Postman or cURL to interact with the `/api/ssl-info` endpoint.

## Technology Choices

**Node.js**: Chosen for its asynchronous capabilities and vast ecosystem. It allows handling multiple simultaneous connections efficiently.

**Express.js**: Provides a minimalistic and flexible framework for building web applications and APIs. It simplifies routing and middleware management.

**node-forge**: Used for parsing and handling SSL certificates. It provides functions to work with various aspects of certificates.

## Assumptions and Design Decisions

- The server assumes that the input domain is correctly formatted and reachable.
- For simplicity, error handling is basic. In a production environment, more comprehensive error handling and logging would be needed.
- CA validity and certificate revocation status are determined based on current implementations. For more accurate results, additional checks might be necessary.

## Known Limitations and Areas for Improvement

- **Domain Validation**: The domain validation regex is basic and may need enhancements for edge cases.
- **Error Handling**: The current error handling is minimal. It could be improved to handle various error scenarios more gracefully.
- **Performance**: The performance of certificate checks can be improved, especially for high traffic scenarios. Caching or asynchronous processing might be considered.
