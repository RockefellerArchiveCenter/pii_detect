# Detect PII in OCR'd PDF Files

Uses pdfminer.six and AWS Comprehend to scan pdf files for SSN matches and writes matches to a report. 


## Requirements

The entire suite has the following system dependencies:
- Python 3 (tested on Python 3.7)
- Boto3
- pdfminer.six

## Configuration

This script requires a `local_settings.cfg` file. For an example of the sections and keys required, see [local_settings.cfg.example](local_settings.cfg.example) in this repository

## Quick start

After cloning this repository and creating `local_settings.cfg`, run `detectPII.py` with the directory containing PDF files and a directory to save the CSV results file to.. E.g.,

```
$ python detectPII.py /path/to/PDF/files /path/to/report
