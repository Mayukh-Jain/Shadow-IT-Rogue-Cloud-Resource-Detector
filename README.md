# 🛡️ Shadow IT / Rogue Cloud Resource Detector

<p align="center">

  <img src="https://img.shields.io/badge/AWS-Cloud%20Security-orange?style=for-the-badge&logo=amazon-aws" />
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Machine%20Learning-scikit--learn-green?style=for-the-badge&logo=scikit-learn" />
  <img src="https://img.shields.io/badge/GenAI-LLM-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Slack-Human--in--the--Loop-4A154B?style=for-the-badge&logo=slack" />
  <img src="https://img.shields.io/badge/Streamlit-Dashboard-red?style=for-the-badge&logo=streamlit" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />

</p>

<p align="center">
  <b>AI-Augmented Cloud Security Platform for Detecting, Scoring, Explaining, and Managing Shadow IT Resources</b>
</p>

---

## 🚨 The Problem

Modern cloud environments can quickly become difficult to govern.

Developers and teams may create cloud resources outside official provisioning processes — forgotten EC2 instances, publicly accessible S3 buckets, idle databases, improperly tagged resources, or infrastructure without clear ownership.

These resources become **Shadow IT**.

They can introduce:

- 🔓 Security vulnerabilities
- 💰 Unnecessary cloud expenditure
- 🌐 Accidental public exposure
- 🏚️ Forgotten or abandoned infrastructure
- 🏷️ Missing ownership and compliance metadata
- ⚠️ Excessive permissions
- 🔍 Poor visibility across cloud environments

Manually discovering these resources becomes increasingly difficult as an organization grows.

### 💡 Our Solution

**Shadow IT / Rogue Cloud Resource Detector** is an AI-augmented cloud security platform that automatically:

```text
AWS Resources
      │
      ▼
┌──────────────────────┐
│  Resource Detection  │
│      AWS + boto3     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│    ML Risk Scoring   │
│   Risk Score 0-100   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  LLM Explainability  │
│ Risk + Remediation   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Slack Alerting     │
│ Approve / Reject /   │
│       Snooze         │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Security Dashboard   │
│ Trends + Audit Trail │
└──────────────────────┘
