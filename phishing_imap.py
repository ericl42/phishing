#!/usr/bin/python3.6

import traceback
import requests
import getpass
import json
import requests.packages.urllib3
import imaplib
import base64
import os
import email
import re
import sys
import hashlib
import smtplib
import subprocess
import logging
import logging.handlers
import posixpath as path
from urllib.parse import urlparse, parse_qs, urlunparse
from email.header import Header, decode_header, make_header
from pprint import pprint
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Define variables. Some need to be blank incase they do not match in the email, so I can still call that variable without errors.
vt_api = 'XXXXXXXXXXXXXXXX'
server = 'XXXXXXXXXXXXXXXX'
email_user = 'XXXXXXXXXXXXXXXX'
email_pass = 'XXXXXXXXXXXXXXXX'
output_dir = '/tmp/'
link_output = []
link_list_output = []
decoded_url_output = []
link_str_output = ''
attachment_output = []
attachment_list_output = []
attachment_str_output = ''
hash_output = []
hash_list_output = []
hash_str_output = ''
vt_list_url_results = []
vt_list_file_results = []
vt_url = ''
vt_url_results = ''
vt_file_results = ''

# Function for Virustotal file lookup
def vt_file_lookup(vt_file):
    if len(vt_file) != 0:
        vt_file_headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username" }
        vt_file_params = {'apikey': vt_api, 'resource': vt_file}
        vt_file_request = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=vt_file_params, headers=vt_file_headers) # Add error handling if API limit or VT is down
        vt_file_json_dict = vt_file_request.json()

        if vt_file_json_dict['response_code'] == 0:
            print('There are no results') # If there are no results, I will need to set a default variable here.
        else:
            vt_file_sha256 = (vt_file_json_dict['sha256'])
            vt_file_date = (vt_file_json_dict['scan_date'])
            vt_file_positives = (vt_file_json_dict['positives'])
            vt_file_permalink = (vt_file_json_dict['permalink'])
            #print('SHA256: ' + vt_file_sha256)
            #print('Scan date: ' + vt_file_date)
            #print('Positive hits: ' + str(vt_file_positives))
            #print('Link to results: ' + vt_file_permalink)
            return(vt_file_sha256, vt_file_date, vt_file_positives, vt_file_permalink)

# Function for Virustotal URL lookup
def vt_url_lookup(vt_url):
    if len(vt_url) != 0:
        vt_url_headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username" }
        vt_url_params = {'apikey': vt_api, 'resource':vt_url}
        vt_url_request = requests.post('https://www.virustotal.com/vtapi/v2/url/report',  params=vt_url_params, headers=vt_url_headers) # Add error handling if API limit or VT is down
        vt_url_json_dict = vt_url_request.json()

        if vt_url_json_dict['response_code'] == 0:
            #print('There are no results') # If there are no results, I will need to set a default variable here.
            vt_url_results = 'There are no VT url results'
            return vt_url_results
        else:
            vt_url_url = 'URL: ' + (vt_url_json_dict['url'])
            vt_url_date = 'Scan Date: ' + (vt_url_json_dict['scan_date'])
            vt_url_positives = 'Positive Hits: ' + str((vt_url_json_dict['positives']))
            vt_url_permalink = ('Link to Results: ' + vt_url_json_dict['permalink'])
            #print('URL: ' + vt_url_url)
            #print('Scan date: ' + vt_url_date)
            #print('Positive hits: ' + str(vt_url_positives))
            #print('Link to results: ' + vt_url_permalink)
            return(vt_url_url, vt_url_date, vt_url_positives, vt_url_permalink)

# Function to get a token for ServiceNow  API (utilizing internal third party tool to proxy SN requests)
def query_snapi():
    auth_url = "XXXXXXXXXXXXXXXX"
    login_data = { 'username': 'XXXXXXXXXXXXXXXX', 'password': 'XXXXXXXXXXXXXXXX' }

    session = requests.session()

    try:
        r = session.post(auth_url, json=login_data, verify=False)
        web_token = r.text
        r.raise_for_status()
    except Exception as e:
        print(e)
        print(r.text)
        print(r.status_code)
        sys.exit()

    parsed_token = web_token.split('"')[3]
    headers = {'Authorization': 'Bearer ' + parsed_token, 'Content-Type': 'application/json'}
    return headers

# Function to send error emails if needed
def errorEmail():
    fromaddr = "XXXXXXXXXXXXXXXX"
    toaddr = "XXXXXXXXXXXXXXXX"
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = "Phishing Automation Error"

    body = "The phishing automation script failed to process correctly due to the following error:\n\n" + traceback.format_exc() + "\n\nPlease review."
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('XXXXXXXXXXXXXXXX', 25)
    server.starttls()
    text = msg.as_string()
    server.sendmail(fromaddr, toaddr, text)
    server.quit()

# Function to pull down all email attachments
def get_attachments(msg):
    for part in msg.walk():
        if part.get_content_maintype()=='multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        fileName = part.get_filename()
        if bool(fileName):
            filePath = os.path.join(output_dir, fileName)
            with open(filePath,'wb') as f:
                f.write(part.get_payload(decode=True))

# Logging statement to send all output to /var/log/messages.
my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address = '/dev/log')
my_logger.addHandler(handler)

# Connect to the IMAP inbox and pull down unread messages
mail = imaplib.IMAP4_SSL(server)
mail.login(email_user, email_pass)
mail.select('INBOX')
result, data = mail.search(None, 'UNSEEN')
mail_ids = data[0]
id_list = mail_ids.split()
#print(id_list) # Only here for troubleshooting

# Verify email exists before continuing
if len(id_list) == 0:
    sys.exit('There is no new email')

try:
    # Format the email in a way we can read it below
    result, data = mail.fetch(id_list[0], '(RFC822)')
    raw = email.message_from_bytes(data[0][1])
    get_attachments(raw)
    #print(raw) # Turn on for troubleshooting to see the full message

    # Pull header information from the email that was received. Do this outside of the if statement since we base that logic on the subject
    header_from = mail.fetch(id_list[0], "(BODY[HEADER.FIELDS (FROM)])")
    #print(str(header_from))
    header_from_str = str(header_from) # Have to convert to string before you regex match it
    mail_from = re.search('From:\s.+<(\S+)>', header_from_str)
    from_address = mail_from.group(1)

    header_to = mail.fetch(id_list[0], "(BODY[HEADER.FIELDS (TO)])")
    #print(str(header_to))
    header_to_str = str(header_to) # Have to convert to string before you regex match it
    mail_to = re.search('To:\s.+<(\S+)>', header_to_str)
    to_address = mail_to.group(1)

    header_subject = mail.fetch(id_list[0], "(BODY[HEADER.FIELDS (SUBJECT)])")
    #print(str(header_subject))
    header_subject_str = str(header_subject) # Have to convert to string before you regex match it
    mail_subject = re.search('Subject:\s(.+)\'\)', header_subject_str)
    email_subject = mail_subject.group(1)

    # Walk the email and pull out all relevant information depending on the subject
    if 'User Submission:' in email_subject:
        for part in raw.walk():
            if part.get_content_type() == 'message/rfc822':
                part_string = str(part)
                #print(part_string) # Easy way to see the full message for this part if you need to

                try:
                    # Pulling the full email header of the attachment and then decoding it so I can truly get the to, from, and subject without formatting issues
                    # I had to pull a lot larger section because the email header format/order varied on me
                    attachment_header = re.search('(Content-Disposition:\sattachment;(.*?(\n))+.*?)MIME-Version:', part_string)
                    coded_header = attachment_header.group(1)
                    decoded_header = make_header(decode_header(coded_header))
                    #print(decoded_header)

                    original_from = re.search('\sFrom:\s(.+?)\n?(\S+:)', str(decoded_header))
                    original_to = re.search('\sTo:\s(.+?)\n?(\S+:)', str(decoded_header))
                    original_subject = re.search('Subject:\s(.+?)\n?(\w+\-\w+:|From:\s|To:\s|Type:\s|Date:\s|References:\s)', str(decoded_header))

                    from_address =  original_from.group(1)
                    to_address = original_to.group(1)
                    email_subject = original_subject.group(1)

                # I need to clean this up. Right now if one fails, they all fail
                except AttributeError:
                    from_address = 'Parsing error'
                    to_address = 'Parsing error'
                    email_subject = 'Parsing error'

            if part.get_content_type() != 'message/rfc822' and part.get_content_disposition() == 'attachment':
                part_string = str(part)
                #print(part_string) # Easy way to see the full message for this part if you need to
                file_name = re.search('filename="(.+)"(;|\n)?', part_string)
                if file_name is not None:
                    attachment = file_name.group(1)
                    attachment_output.append(attachment)
                    with open('/tmp/' + attachment, 'rb') as f:
                        bytes = f.read()
                        readable_hash = hashlib.sha256(bytes).hexdigest()
                        hash_output.append(readable_hash)

            if part.get_content_type() == 'text/html' or part.get_content_type() == 'text/plain':
                content = part.get_payload(decode=True)
                #print(content) # Easy way to see the full message for this part if you need to
                soup = BeautifulSoup(content, 'html.parser')
                html_output = str(soup)
                html_output2 = soup.get_text()
                for link in soup.find_all('a'):
                    links = link.get('href')
                    link_output.append(links)
                    if links and 'mailto' not in links:
                        if 'safelink' in links:
                            # Decode safelinks
                            target = parse_qs(urlparse(links).query)['url'][0]
                            p = urlparse(target)
                            q = p._replace(path=path.join(path.dirname(path.dirname(p.path)), path.basename(p.path)))
                            decoded_url = urlunparse(q)
                            decoded_url_output.append(decoded_url) # List version to call VT and other APIs
                        else:
                            link_str_output = links + "\n" + link_str_output  # Pretty format for SN ticket
                            decoded_url_output.append(links) # List version to call VT and other APIs

                dedup_decoded_url = list(set(decoded_url_output))
                link_str_convert = dedup_decoded_url[0:]
                link_str_output = "\n".join(link_str_convert) # String version to pretty print it in SN ticket

    # This part of the code does a similar function of parsing out data for emails that were forwarded to the inbox vs. using the report phishing button
    else:
        for part in raw.walk():
            if part.get_content_type() != 'message/rfc822' and part.get_content_disposition() == 'attachment':
                part_string = str(part)
                file_name = re.search('filename="(.+)";', part_string)
                if file_name is not None:
                    attachment = file_name.group(1)
                    attachment_output.append(attachment)
                    with open('/tmp/' + attachment, 'rb') as f:
                        bytes = f.read()
                        readable_hash = hashlib.sha256(bytes).hexdigest()
                        hash_output.append(readable_hash)

            if part.get_content_type() == 'text/html':
                content = part.get_payload(decode=True)
                soup = BeautifulSoup(content, 'html.parser')
                html_output = str(soup)
                for link in soup.find_all('a'):
                    links = link.get('href')
                    link_output.append(links)
                    if 'mailto' not in links:
                        if 'safelink' in links:
                            # Decode safelinks
                            target = parse_qs(urlparse(links).query)['url'][0]
                            p = urlparse(target)
                            q = p._replace(path=path.join(path.dirname(path.dirname(p.path)), path.basename(p.path)))
                            decoded_url = urlunparse(q)
                            decoded_url_output.append(decoded_url) # List version to call VT and other APIs
                        else:
                            link_str_output = links + "\n" + link_str_output  # Pretty format for SN ticket
                            decoded_url_output.append(links) # List version to call VT and other APIs

                dedup_decoded_url = list(set(decoded_url_output))
                link_str_convert = dedup_decoded_url[0:]
                link_str_output = "\n".join(link_str_convert) # String version to pretty print it in SN ticket

    try:
        # Perform VT lookup
        for i in dedup_decoded_url[:4]:
            vt_url = vt_url_lookup(i)
            vt_url_results = str(vt_url) + '\n' + str(vt_url_results)
    except NameError:
        print('No links found')

    # Code block to iterate through all attachments
    try:
        attachment
        for line in attachment_output:
            attachment_str_output = line + "\n" + attachment_str_output
            attachment_list_output.append(line)
        #print(attachment_str_output)
    except NameError:
        print('No attachments found')

    # Code block to iterate through all hashes and perform hash lookups
    try:
        readable_hash
        for line in hash_output[:4]:
            hash_str_output = line + "\n" + hash_str_output
            hash_list_output.append(line)
        #print(hash_str_output)
        # Perform VT lookup
        for i in hash_list_output:
            vt_file_results = vt_file_lookup(i)
    except NameError:
        print('No hashes found')

    # Create the SN ticket
    sn_headers = query_snapi()

    # Hardcoded variables
    sn_input = {
        "reported_by": "XXXXXXXXXXXXXXXX",
        "assignment_group": "XXXXXXXXXXXXXXXX",
        "severity": "3",
        "contact_type": "External System",
        "classification": "Access & Security",
        "group_list": "XXXXXXXXXXXXXXXX"  }

    # Dynamic variables
    sn_input['short_summary'] = "Phishing Incident - " + email_subject
    sn_input['description'] = "Email Information \n\nFrom:\n" + from_address + "\n\nTo:\n" + to_address + "\n\nSubject:\n" + email_subject + "\n\nLinks (if applicable):\n" + link_str_output + "\nAttachments (if applicable):\n" + attachment_str_output + "\nSHA256 (if applicable):\n" + hash_str_output + "\n########################################\n\nVirus Total Results (If there are no results, then these files were not in the database)\n\n" + str(vt_url_results) + str(vt_file_results)

    # Submit the SN ticket
    resp = requests.post("XXXXXXXXXXXXXXXX", headers=sn_headers, data=json.dumps(sn_input), verify=False)

    if resp.text:
        print(resp.text)

    json_dict = resp.json()
    sn_ticket = (json_dict['number'])

    # Log the response to syslog
    my_logger.info('automation: Phishing Alert - ' + sn_ticket + ' has been created to investigate the phishing email ' + email_subject)

except Exception as e:
    exception_error = str(e)
    my_logger.info('automation: Phishing Alert failed to process correctly due to ' + exception_error + '. An email has been sent to InfoSec to review.')
    errorEmail()

    print(traceback.format_exc())
