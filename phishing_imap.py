#!/usr/bin/python3.6

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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Define variables. Some need to be blank incase they do not match in the email, so I can still call that variable without errors.
vt_api = 'XXXXXX'
server = 'XXXXXX'
email_user = 'XXXXXX'
email_pass = 'XXXXXX'
output_dir = '/tmp/attachments/'
link_output = []
link_list_output = []
link_str_output = ''
attachment_output = []
attachment_list_output = []
attachment_str_output = ''
hash_output = []
hash_list_output = []
hash_str_output = ''
vt_list_url_results = []
vt_str_url_results = ''
vt_str_url_results2 = ''
vt_list_file_results = []
vt_str_file_results2 = ''

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
            vt_url_results = 'There are VT url no results'
            return vt_url_results
        else:
            vt_url_url = (vt_url_json_dict['url'])
            vt_url_date = (vt_url_json_dict['scan_date'])
            vt_url_positives = (vt_url_json_dict['positives'])
            vt_url_permalink = (vt_url_json_dict['permalink'])
            return(vt_url_url, vt_url_date, vt_url_positives, vt_url_permalink)

# Function to get a token for internal SN API
def query_snapi():
    auth_url = "XXXXXX"
    login_data = { 'username': 'XXXXXX', 'password': 'XXXXXX' }

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
    fromaddr = "XXXXXX"
    toaddr = "XXXXXX"
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = "Phishing Automation Error"

    body = "There was an error with the code. Please review."
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('XXXXXX', 25)
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

# Format the email in a way we can read it below
result, data = mail.fetch(id_list[0], '(RFC822)')
raw = email.message_from_bytes(data[0][1])
get_attachments(raw)
#print(raw) # Turn on for troubleshooting to see the full message

# Pull header information from the email that the inbox received. Do this outside of the if statement since we base that logic on the subject
header_from = mail.fetch(id_list[0], "(BODY[HEADER.FIELDS (FROM)])")
header_from_str = str(header_from) # Have to convert to string before you regex match it
mail_from = re.search('From:\s.+<(\S+)>', header_from_str)
from_address = mail_from.group(1)

header_to = mail.fetch(id_list[0], "(BODY[HEADER.FIELDS (TO)])")
header_to_str = str(header_to) # Have to convert to string before you regex match it
mail_to = re.search('To:\s.+<(\S+)>', header_to_str)
to_address = mail_to.group(1)

header_subject = mail.fetch(id_list[0], "(BODY[HEADER.FIELDS (SUBJECT)])")
header_subject_str = str(header_subject) # Have to convert to string before you regex match it
mail_subject = re.search('Subject:\s(.+)\'\)', header_subject_str)
email_subject = mail_subject.group(1)

# Walk the email and pull out all relevant information depending on the subject
if 'User Submission:' in email_subject:
    print('User submitted file via phishing button (has .msg file attached)') # Remove later, only here for troubleshooting

    for part in raw.walk():
        if part.get_content_type() == 'message/rfc822':
            part_string = str(part)
            #print(part_string) # Easy way to see the full message for this part if you need to
            original_from = re.search('From:\s(.+)\n', part_string)
            original_to = re.search('(?<!Reply-)To:\s(.+)\n', part_string)
            original_subject = re.search('Subject:\s(.+)\n', part_string)
            if original_from is not None:
                from_address =  original_from.group(1)
            else:
                from_address = 'Parsing error'

            if original_to is not None:
                to_address = original_to.group(1)
            else:
                to_address = 'Parsing error'

            if original_subject is not None:
                email_subject = original_subject.group(1)
            else:
                email_subject = 'Parsing error'

        if part.get_content_type() != 'message/rfc822' and part.get_content_disposition() == 'attachment':
            part_string = str(part)
            #print(part_string) # Easy way to see the full message for this part if you need to
            file_name = re.search('filename="(.+)";', part_string)
            if file_name is not None:
                attachment = file_name.group(1)
                attachment_output.append(attachment)
                with open('/tmp/attachments/' + attachment, 'rb') as f:
                    bytes = f.read()
                    readable_hash = hashlib.sha256(bytes).hexdigest()
                    hash_output.append(readable_hash)

        if part.get_content_type() == 'text/html' and part.get_content_charset() == 'utf-8':
            content = part.get_payload(decode=True)
            #print(content) # Easy way to see the full message for this part if you need to
            soup = BeautifulSoup(content, 'html.parser')
            for link in soup.find_all('a'):
                links = link.get('href')
                link_output.append(links)
                if 'mailto' not in links:
                    dedup_link_output = list(set(link_output))

else:
    print('User did not submit via phishing button (no .msg file attached') # Remove later, only here for troubleshooting

    for part in raw.walk():
        if part.get_content_type() != 'message/rfc822' and part.get_content_disposition() == 'attachment':
            part_string = str(part)
            file_name = re.search('filename="(.+)";', part_string)
            if file_name is not None:
                attachment = file_name.group(1)
                attachment_output.append(attachment)
                with open('/tmp/attachments/' + attachment, 'rb') as f:
                    bytes = f.read()
                    readable_hash = hashlib.sha256(bytes).hexdigest()
                    hash_output.append(readable_hash)

        if part.get_content_type() == 'text/html':
            content = part.get_payload(decode=True)
            soup = BeautifulSoup(content, 'html.parser')
            for link in soup.find_all('a'):
                links = link.get('href')
                link_output.append(links)
                if 'mailto' not in links:
                    dedup_link_output = list(set(link_output))

try:
    dedup_link_output
except NameError:
    print('No links found')
else:
    for line in dedup_link_output:
        if 'mailto' not in line:
            link_str_output = line + "\n" + link_str_output # String version to pretty print in SN ticket
            link_list_output.append(line) # List version to call VT and other APIs
    print(link_str_output)
# Perform VT lookup
    for i in link_list_output[:4]:
        vt_url_results = vt_url_lookup(i)
        vt_list_url_results.append(vt_url_results)
    vt_str_url_results2 = json.dumps(vt_list_url_results, indent=4) # Making the VT results prettier for SN ticket

try:
    attachment
except NameError:
    print('No attachments found')
else:
    for line in attachment_output:
        attachment_str_output = line + "\n" + attachment_str_output
        attachment_list_output.append(line)
    print(attachment_str_output)

try:
    readable_hash
except NameError:
    print('No hashes found')
else:
    for line in hash_output[:4]:
        hash_str_output = line + "\n" + hash_str_output
        hash_list_output.append(line)
    print(hash_str_output)
# Perform VT lookup
    for i in hash_list_output:
        vt_file_results = vt_file_lookup(i)
        vt_list_file_results.append(vt_file_results)
        print(vt_list_file_results)
    vt_str_file_results2 = json.dumps(vt_list_file_results, indent=4)

# Create the SN ticket
sn_headers = query_snapi()

# Hardcoded variables
sn_input = {
    "reported_by": "XXXXXX",
    "assignment_group": "XXXXXX",
    "severity": "3",
    "contact_type": "XXXXXX",
    "classification": "Access & Security",
    "group_list": "XXXXXX"  }

# Dynamic variables
sn_input['short_summary'] = "Phishing Incident - " + email_subject
sn_input['description'] = "Email Information \n \n From: \n" + from_address + "\n \nTo: \n" + to_address + "\n \nSubject: \n" + email_subject + "\n \nLinks (if applicable): \n" + link_str_output + "\nAttachments (if applicable): \n" + attachment_str_output + "\nSHA256 (if applicable): \n" + hash_str_output + "\n ######################################## \n \n Virus Total Results (max 4 due to API limitations) \n \n" + vt_str_url_results2 + vt_str_file_results2

resp = requests.post("https://service-now-api-server/incidents", headers=sn_headers, data=json.dumps(sn_input), verify=False)

if resp.text:
    print(resp.text)
