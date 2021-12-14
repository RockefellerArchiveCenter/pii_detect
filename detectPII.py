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
from pathlib import Path

logger = logging.getLogger('PDFProcess')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('PII_Logging.log')
fh.setLevel(logging.INFO)
logger.addHandler(fh)


class PDFProcess:
    def __init__(self):
        rsrcmgr = PDFResourceManager()
        self.retstr = StringIO()
        self.device = TextConverter(rsrcmgr, self.retstr, codec='utf-8', laparams=LAParams())
        self.interpreter = PDFPageInterpreter(rsrcmgr, self.device)

    def get_page_text(self, page):
        """
        Gets page text from a PDF page. Truncates open file's size and moves it back to beginning.

        page (object): A pdfminer PDFPage object.

        returns (string): PDF page text.
        """
        self.interpreter.process_page(page)
        page_text = self.retstr.getvalue()
        self.retstr.truncate(0)
        self.retstr.seek(0)
        return page_text

    def get_pdf_text(self, path):
        """
        Extracts text from a pdf and stores the text as a string element in a list.

        path (path object): Path object of a pdf file.

        returns (list): The list of page strings.
        """
        page_number = 0
        pdf_pages = []
        with open(path, 'rb') as fp:
            PDF_PAGE_SETTINGS = {'maxpages': 0, 'password': '', 'caching': True, 'pagenos': set()}
            for page in PDFPage.get_pages(fp,
                                          PDF_PAGE_SETTINGS['pagenos'],
                                          PDF_PAGE_SETTINGS['maxpages'],
                                          PDF_PAGE_SETTINGS['password'],
                                          PDF_PAGE_SETTINGS['caching'],
                                          check_extractable=True):
                page_number = page_number + 1
                if 'Font' in page.resources.keys():
                    page_text = self.get_page_text(page)
                    pdf_pages.append(page_text)
                else:
                    logger.info('No searchable text on page {} of {}.'.format(page_number, str(path)))
            return pdf_pages

    def cleanup(self):
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

    def detect_pii(self, text, language_code, filename):
        """
        Detects personally identifiable information (PII) in a document. PII can be
        things like names, account numbers, or addresses.

        text (string): The document to inspect.
        language_code (string): The language of the document.
        filename (path object): Path object of a pdf file.

        yields: PII entities with a type of 'SSN'.
        """
        try:
            response = self.comprehend_client.detect_pii_entities(
                Text=text, LanguageCode=language_code)
            entity_types = (entity['Type'] for entity in response['Entities'])
            if 'SSN' not in entity_types:
                return dict()
            else:
                for entity in response['Entities']:
                    if entity['Type'] == 'SSN':
                        matching_text = text[entity['BeginOffset']:entity['EndOffset']]
                        entity['String'] = matching_text
                        entity['Filename'] = filename.name
                        yield entity
        except ClientError as error:
            raise error

def process_text(text, pdf_file, csv_writer):
    comp_detect = ComprehendDetect()
    if len(list(text)) == 0:
        logger.info('No OCR text in {}.'.format(str(pdf_file)))
    else:
        for pdf_page in text:
            if len(pdf_page.encode('utf-8')) > 5000:
                page_parts = [pdf_page[:len(pdf_page)//2]] + [pdf_page[len(pdf_page)//2:]]
                for part in page_parts:
                    for result in comp_detect.detect_pii(part, 'en', pdf_file):
                        csv_writer.writerow(result)
            else:
                for result in comp_detect.detect_pii(pdf_page, 'en', pdf_file):
                    csv_writer.writerow(result)


def main():
    parser = argparse.ArgumentParser(
        description='Use pdminer.six and AWS Comprehend to extract text from PDF files and scan for PII.')
    parser.add_argument('pdf_target',
                        help='A pdf file or directory containing PDF files for scanning.')
    parser.add_argument('report_dir',
                        help='A directory path and filename to save the csv report to.')
    parser.add_argument('--single',
                        help='Option to run the script on a single PDF file.',
                        action='store_true')
    args = parser.parse_args()

    extract_text = PDFProcess()

    if Path(args.report_dir).is_dir() and Path(args.report_dir).exists():
        report = Path(args.report_dir).joinpath('PII_Matches.csv')
    else:
        raise Exception("Invalid directory path entered for Report directory.")
    columns = ['Score', 'Type', 'BeginOffset', 'EndOffset', 'String', 'Filename']
    pdf_target = Path(args.pdf_target)
    with open(report, 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=columns)
        writer.writeheader()
        if Path(pdf_target).is_file() and Path(pdf_target).exists() and args.single:
            print(str(pdf_target))
            try:
                pdf_text = extract_text.get_pdf_text(pdf_target)
            except struct.error as e:
                logger.info('%f failed with %e.' % (str(pdf_target), e))
            process_text(pdf_text, pdf_target, writer)
            extract_text.cleanup()
        elif Path(pdf_target).is_dir() and Path(pdf_target).exists() and not args.single:
            pdf_files = (file for file in pdf_target.glob('**/*.pdf'))
            for file in pdf_files:
                print(str(file))
                try:
                    pdf_text = extract_text.get_pdf_text(file)
                except struct.error as e:
                    logger.info('%f failed with %e.' % (str(file), e))
                    continue
                process_text(pdf_text, file, writer)
            extract_text.cleanup()
        elif Path(pdf_target).is_dir() and Path(pdf_target).exists() and args.single:
            print('Please target a single PDF file when running with the --single option.')
        else:
            raise Exception("Invalid directory or file path entered for PDF location.")


if __name__ == "__main__":
    main()
