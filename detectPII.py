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
        self.device = TextConverter(rsrcmgr, self.retstr, codec='utf-8', laparams=LAParams())
        self.interpreter = PDFPageInterpreter(rsrcmgr, self.device)

    def get_pdf_text(self, path):
        """
        Extracts text from a pdf and stores the text as a string element in a list.

        path (path object): Path object of a pdf file.

        returns (list): The list of page strings.
        """
        fp = open(path, 'rb')
        PDF_PAGE_SETTINGS = {'maxpages':0, 'password':'', 'caching':True, 'pagenos':set()}
        pages = (self.interpreter.process_page(page) for page in PDFPage.get_pages(fp,
                                      PDF_PAGE_SETTINGS['pagenos'],
                                      PDF_PAGE_SETTINGS['maxpages'],
                                      PDF_PAGE_SETTINGS['password'],
                                      PDF_PAGE_SETTINGS['caching'],
                                      check_extractable=True))
        text = (self.retstr.getvalue() for page in pages)
        #for page in PDFPage.get_pages(fp,
                                      #PDF_PAGE_SETTINGS['pagenos'],
                                      #PDF_PAGE_SETTINGS['maxpages'],
                                      #PDF_PAGE_SETTINGS['password'],
                                      #PDF_PAGE_SETTINGS['caching'],
                                      #check_extractable=True):
            #self.interpreter.process_page(page)
            #text = self.retstr.getvalue()
            #self.retstr.truncate(0)
            #self.retstr.seek(0)
            #print(text)
        fp.close()
        self.device.close()
        self.retstr.close()

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

    def detect_pii(self, text, language_code, filename, csv_writer):
        """
        Detects personally identifiable information (PII) in a document. PII can be
        things like names, account numbers, or addresses.

        text (string): The document to inspect.
        language_code (string): The language of the document.
        filename (path object): Path object of a pdf file.
        csv_writer (class): A DictWriter class object.

        returns (list): The list of PII entities along with their confidence scores.
        """
        try:
            response = self.comprehend_client.detect_pii_entities(
                Text=text, LanguageCode=language_code)
            for entity in response['Entities']:
                if entity['Type'] == 'SSN':
                    matching_text = text[entity['BeginOffset']:entity['EndOffset']]
                    entity['string'] = matching_text
                    entity['filename'] = filename.name
                    csv_writer.writerow(entity)
        except ClientError:
            logger.exception("Couldn't detect PII entities.")
            raise

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
    columns = ['Score', 'Type', 'BeginOffset', 'EndOffset', 'string', 'filename']
    pdf_files = Path(args.pdf_dir)
    #file = Path('/Users/pgalligan/Documents/OCR_PDF/FA386a_S205D_B13_F191.pdf')
    with open(report, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames = columns)
        writer.writeheader()
        #pii = comp_detect.detect_pii('social security 678-56-2365', 'en', file, writer)
        if Path(args.pdf_dir).is_dir() and Path(args.report_dir).is_dir():
            for file in pdf_files.iterdir():
                if not file.stem.startswith('.'):
                    text = extract_text.get_pdf_text(file)
                    #for item in text:
                        #pii = comp_detect.detect_pii(item, 'en', file, writer)
                        #if len(pii) > 0:
                            #matches.append(pii)

        #else:
            #raise Exception("Invalid directory path entered for PDF or Report directory.")
        #if len(matches) == 0:
            #print('No SSN matches found.')

if __name__ == "__main__":
    main()
