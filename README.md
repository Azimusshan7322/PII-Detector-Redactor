# Project Guardian 2.0 — PII Detector & Redactor

This is the project I built for detecting and redacting PII from a CSV of JSON rows. I kept it simple and used only the Python standard library.

## Input Format
The input is just a CSV file with:
- `record_id`
- `Data_json` (this is basically a stringified JSON object)

## To Run It
So to run my code, I just do:
```bash
python3 detector_Azimusshan_Khan.py iscp_pii_dataset.csv
```

If I want to give my own output file name, I do:
```bash
python3 detector_Azimusshan_Khan.py iscp_pii_dataset.csv redacted_Azimusshan_Khan.csv
```

## What It Gives Back
By default, it creates a file called `redacted_output_candidate_full_name.csv`.
This file has three columns:
- `record_id`
- `redacted_data_json`
- `is_pii` (which is either True or False)

## What the Script Actually Does
- I used only Python’s standard libraries, no fancy dependencies.
- It can catch PII in two ways:
  - **Standalone stuff** like:
    - 10-digit phone numbers
    - Aadhaar (12 digits)
    - Passport numbers
    - UPI IDs (like `user@upi` or `9876543210@ybl`)
  - **Combinatorial stuff** like:
    - Full names
    - Email addresses
    - Physical address (street + city + pin together)
    - Device IDs or IPs when combined with user context
- For redaction, here’s how I did it:
  - Phone numbers become something like `98XXXXXX10`
  - Emails become something like `ab****@domain`
  - Aadhaar gets turned into `XXXXXXXX1234`
  - Device IDs and IPs are replaced with `[REDACTED_PII]`
  - Addresses: I mask the digits in the street part, but I keep the city, state, and pin visible

# Thank you 

