# OpenSecOps Documentation

This repository contains comprehensive documentation for the OpenSecOps platform, including installation guides, technical design specifications, and standard operating procedures for Foundation and SOAR products.

## Documentation Structure

The documentation is organized by product family:

### Foundation Documentation
- [Installation Manual](./docs/Foundation/OpenSecOps%20Foundation%20Installation%20Manual.docx.pdf) - Complete deployment guide
- [Technical Design Specification](./docs/Foundation/OpenSecOps%20Foundation%20TDS.docx.pdf) - Architecture details
- [Standard Operating Procedures](./docs/Foundation/OpenSecOps%20Foundation%20Account%20Properties%20SOP.docx.pdf) - Day-to-day management

### SOAR Documentation
- [Installation Manual](./docs/SOAR/OpenSecOps%20SOAR%20-%20Installation%20Manual.docx.pdf) - Step-by-step deployment
- [Technical Design Specification](./docs/SOAR/OpenSecOps%20SOAR%20-%20TDS.docx.pdf) - Architecture and design
- [Standard Operating Procedures](./docs/SOAR/OpenSecOps%20SOAR%20-%20SOP.docx.pdf) - Operational tasks
- Component-specific SOPs:
  - [DynamoDB Tables SOP](./docs/SOAR/OpenSecOps%20SOAR%20DynamoDB%20Tables%20-%20SOP.docx.pdf)
  - [KMS Keys SOP](./docs/SOAR/OpenSecOps%20SOAR%20KMS%20Keys%20-%20SOP.docx.pdf)
  - [S3 Buckets SOP](./docs/SOAR/OpenSecOps%20SOAR%20S3%20Buckets%20-%20SOP.docx.pdf)

## About OpenSecOps

OpenSecOps provides enterprise-grade security automation for AWS environments through two main product families:

### Foundation
**Cloud infrastructure foundation** implementing AWS best practices with features including:
- AWS Control Tower integration
- Centralized logging and archival
- Text-based AWS configuration management
- Single Sign-On (SSO) with multi-factor authentication
- Just-In-Time (JIT) elevated access management

### SOAR (Security Orchestration, Automation, and Response)
**Security automation platform** with serverless architecture including:
- AWS Security Hub integration
- Automated incident response with predefined playbooks
- Forensic analysis capabilities
- Ticketing system integration (Jira, ServiceNow)
- AI-powered security reporting

## Getting Started

To install OpenSecOps, clone the [Installer repository](https://github.com/OpenSecOps-Org/Installer) and follow the instructions in its README.

## Community Resources

- [Code of Conduct](https://github.com/OpenSecOps-Org/.github/blob/main/profile/CODE_OF_CONDUCT.md) - Our community standards
- [Contributing Guidelines](https://github.com/OpenSecOps-Org/.github/blob/main/profile/CONTRIBUTING.md) - How to contribute to OpenSecOps
- [Security Policy](https://github.com/OpenSecOps-Org/.github/blob/main/profile/SECURITY.md) - Reporting security vulnerabilities

## Website

Visit our website at [https://opensecops.org](https://opensecops.org) for additional information, including technical details and stakeholder-focused material.