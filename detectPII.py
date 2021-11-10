import argparse
import csv
import logging

import boto3
from botocore.exceptions import ClientError

from configparser import ConfigParser

from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
from io import StringIO
from pprint import pprint
from pathlib import Path

from textwrap import wrap

logger = logging.getLogger(__name__)

class PDFProcess:
    def __init__(self):
        rsrcmgr = PDFResourceManager()
        self.retstr = StringIO()
        codec = 'utf-8'
        laparams = LAParams()
        self.device = TextConverter(rsrcmgr, self.retstr, codec=codec, laparams=laparams)
        self.interpreter = PDFPageInterpreter(rsrcmgr, self.device)
        self.password = ""
        self.maxpages = 0
        self.caching = True
        self.pagenos=set()

    def get_pdf_text(self, path):
        """
        Extracts text from a pdf and stores the text as a string element in a list.

        path (path object): Path object of a pdf file.

        returns (list): The list of page strings.
        """
        pages = []
        file = Path(path)
        fp = open(file, 'rb')
        for page in PDFPage.get_pages(fp, self.pagenos, maxpages=self.maxpages, password=self.password, caching=self.caching, check_extractable=True):
            self.interpreter.process_page(page)
            text = self.retstr.getvalue()
            pages.append(text)
            self.retstr.truncate(0)
            self.retstr.seek(0)
        fp.close()
        self.device.close()
        self.retstr.close()
        return pages

class ComprehendDetect:
    """Encapsulates Comprehend detection functions."""
    def __init__(self):
        """
        comprehend_client: A Boto3 Comprehend client.
        """
        self.config = ConfigParser()
        self.config.read("/Users/pgalligan/Documents/GitHub/local_settings.cfg")
        session = boto3.session.Session(aws_access_key_id=self.config.get('AWS', 'ACCESS_KEY_ID'),
                                        aws_secret_access_key=self.config.get('AWS', 'SECRET_ACCESS_KEY'),
                                        region_name=self.config.get('AWS', 'REGION'))
        self.comprehend_client = session.client('comprehend')

    def detect_pii(self, text, language_code, filename):
        """
        Detects personally identifiable information (PII) in a document. PII can be
        things like names, account numbers, or addresses.

        text (string): The document to inspect.
        language_code (string): The language of the document.
        filename (path object): Path object of a pdf file.

        returns (list): The list of PII entities along with their confidence scores.
        """
        entities = []
        try:
            response = self.comprehend_client.detect_pii_entities(
                Text=text, LanguageCode=language_code)
            for entity in response['Entities']:
                if entity['Type'] == 'SSN':
                    matching_text = text[entity['BeginOffset']:entity['EndOffset']]
                    entity['string'] = matching_text
                    entity['filename'] = filename.name
                    entities.append(entity)
        except ClientError:
            logger.exception("Couldn't detect PII entities.")
            raise
        else:
            return entities

def main():
    parser = argparse.ArgumentParser(
        description='Use pdminer.six and AWS Comprehend to extract text from PDF files and scan for PII.')
    parser.add_argument('pdf_dir',
        help='A directory containing PDF files for scanning.')
    parser.add_argument('report_dir',
        help='A directory path and filename to save the csv report to.')
    args = parser.parse_args()

    matches =[]
    extract_text = PDFProcess()
    comp_detect = ComprehendDetect()
    report = Path(args.report_dir).joinpath('PII_Matches.csv')
    pdf_files = Path(args.pdf_dir)
    report_columns = ['Score', 'Type', 'BeginOffset', 'EndOffset', 'string', 'filename']

    if Path(args.pdf_dir).is_dir() and Path(args.report_dir).is_dir():
        for file in pdf_files.iterdir():
            if not file.stem.startswith('.'):
                text = extract_text.get_pdf_text(file)
                for item in text:
                    pii = comp_detect.detect_pii(item, 'en', file)
                    if len(pii) > 0:
                        matches.append(pii)

        with open(report, 'w') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames = report_columns)
                writer.writeheader()
                for match in matches:
                    for response in match:
                        writer.writerow(response)
    else:
        raise Exception("Invalid directory path entered for PDF or Report directory.")
    if len(matches) == 0:
        print('No SSN matches found.')

if __name__ == "__main__":
    main()
