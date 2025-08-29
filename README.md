Project Guardian 2.0 — PII Detector & Redactor

I built this project to detect and redact PII from a CSV file that contains JSON data. I wanted to keep things straightforward, so I only used Python’s standard library — nothing fancy.

Input Format

The input is a CSV file with two columns:


How to Run:-

To run my script, I use:

python3 detector_Azimusshan_Khan.py iscp_pii_dataset.csv


If I want to save the output with a custom name, I can do:

python3 detector_Azimusshan_Khan.py iscp_pii_dataset.csv redacted_Azimusshan_Khan.csv

Output:

By default, the script creates a file called redacted_output_Azimusshan_khan.csv.
This file has three columns:

record_id

redacted_data_json

is_pii (True or False)

What the Script Does

It goes through each record and checks if there’s any PII.

It looks for two categories:

Standalone PII

Phone numbers (10-digit)

Aadhaar numbers (12-digit)

Passport numbers

UPI IDs (like user@upi or 9876543210@ybl)

Combinatorial PII

Full name (first and last together)

Email address

Physical address (street + city + pin)

Device ID or IP (when linked with a user)

When it finds PII, it redacts it:

Phone → 98XXXXXX10

Email → ab****@domain

Aadhaar → XXXXXXXX1234

Device ID/IP → [REDACTED_PII]

Addresses → digits masked in the street, but city, state, and pin are kept as they are
