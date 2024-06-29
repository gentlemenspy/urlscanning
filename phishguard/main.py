import imaplib
import email
import hashlib
import socket
import re
import file_hash_analysis
import urlscan
import domain
from cred import IMAP_SERVER, USERNAME, PASSWORD, vt_api_key

def resolve_ip(domain):
    """Resolve IP address from domain."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def subject_analysis(subject):
    """Analyze email subject for suspicious content."""
    suspicious_keywords = ['urgent', 'important', 'account', 'verify', 'password', 'alert', 'warning', 'update', 'suspend']
    suspicious_patterns = ['!!!', '???', 'click', 'link', 'action required']
    suspicious = False
    reasons = []
    
    for keyword in suspicious_keywords:
        if keyword.lower() in subject.lower():
            suspicious = True
            reasons.append(f"Keyword '{keyword}' found")

    for pattern in suspicious_patterns:
        if pattern.lower() in subject.lower():
            suspicious = True
            reasons.append(f"Pattern '{pattern}' found")
    
    return suspicious, reasons

def analyze_attachment(part):
    """Analyze email attachment and return its MD5 hash."""
    attachment = part.get_payload(decode=True)
    md5_hash = hashlib.md5(attachment).hexdigest()
    return md5_hash

def process_attachment(md5_hash, api_key):
    """Process the attachment using VirusTotal API."""
    analysis_result = file_hash_analysis.analyze_file(api_key, md5_hash)
    print(f"Attachment analysis result: {analysis_result}")

def extract_urls(text):
    """Extract URLs from text."""
    url_regex = r'(https?://\S+)'
    return re.findall(url_regex, text)

def process_email(email_id, email_data, api_key, processed_ids):
    """Process an individual email."""
    raw_email = email_data[0][1]
    msg = email.message_from_bytes(raw_email)
    sender = msg['From']
    receiver = msg['To']
    subject = msg['Subject']
    date = msg['Date']
    sender_name, sender_email = email.utils.parseaddr(sender)
    sender_domain = sender_email.split('@')[-1]
    sender_ip = resolve_ip(sender_domain)
    receiver_name, receiver_email = email.utils.parseaddr(receiver)
    receiver_domain = receiver_email.split('@')[-1]

    content = ""
    attachment_md5 = None
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))
        if content_type == 'text/plain' and 'attachment' not in content_disposition:
            email_body = part.get_payload(decode=True).decode()
            content += email_body
        elif 'attachment' in content_disposition:
            attachment_md5 = analyze_attachment(part)
    
    is_suspicious, reasons = subject_analysis(subject)
    is_content_suspicious, content_reasons = subject_analysis(content)
    
    if is_suspicious:
        print(f"\nSuspicious Subject: {subject}")
        print(f"Reasons: {', '.join(reasons)}")
        
    if is_content_suspicious:
        print("\nSuspicious Content found.")
        print(f"Reasons: {', '.join(content_reasons)}")

    urls = extract_urls(content)
    unique_urls = set(urls)  # Use a set to remove duplicates
    for url in unique_urls:
        url_analysis = urlscan.run(api_key, url)
        print(f"\nURL Analysis for {url}: {url_analysis}")

    if attachment_md5:
        process_attachment(attachment_md5, api_key)

    domain_analysis = domain.run(api_key, sender_domain)
    if domain_analysis:
        print(f"\nDomain Analysis for {sender_domain}: {domain_analysis}")

    processed_ids.add(email_id.decode())
    with open('processed_ids.txt', 'a') as f:
        f.write(email_id.decode() + '\n')

def load_processed_ids(filename):
    """Load processed email IDs from file."""
    try:
        with open(filename, 'r') as f:
            return set(f.read().splitlines())
    except FileNotFoundError:
        return set()

def main():
    api_key = vt_api_key
    processed_ids = load_processed_ids('processed_ids.txt')

    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(USERNAME, PASSWORD)
    mail.select('INBOX')
    status, email_ids = mail.search(None, 'ALL')

    if status == 'OK':
        for email_id in email_ids[0].split():
            if email_id.decode() in processed_ids:
                continue

            status, email_data = mail.fetch(email_id, '(RFC822)')
            if status == 'OK':
                process_email(email_id, email_data, api_key, processed_ids)
        
    mail.close()
    mail.logout()

if __name__ == "__main__":
    main()
