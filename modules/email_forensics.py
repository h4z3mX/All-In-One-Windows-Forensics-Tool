import mailbox
import os
import csv
from email.utils import parsedate_tz, mktime_tz

def process_email_forensics(mbox_file_path, output_dir='attachments', csv_file='email_data.csv'):
    # Create the directory for attachments if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Open the .mbox file
    mbox = mailbox.mbox(mbox_file_path)

    # Prepare a CSV file for output
    with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['From', 'To', 'Subject', 'Date', 'CC', 'BCC', 'Body', 'Attachments']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Iterate through each email in the .mbox file
        for idx, email_message in enumerate(mbox):
            # Extract headers and basic email information
            email_data = {
                'From': email_message['From'],
                'To': email_message['To'],
                'Subject': email_message['Subject'],
                'Date': parse_date(email_message['Date']),
                'CC': email_message.get('Cc', ''),
                'BCC': email_message.get('Bcc', ''),
                'Body': extract_email_body(email_message),
                'Attachments': extract_attachments(email_message, output_dir)  # Collect attachments
            }

            # Write the email data to CSV
            writer.writerow(email_data)

            print(f"--- Email {idx + 1} processed")

    return f"Email forensics completed. Data saved to {csv_file}."


def parse_date(date_str):
    """Parse the email date and return a human-readable format."""
    if date_str:
        date_tuple = parsedate_tz(date_str)
        if date_tuple:
            return f"{mktime_tz(date_tuple)}"  # Convert to Unix timestamp or human-readable
    return "Unknown Date"


def extract_email_body(email_message):
    """Extract the plain text or HTML body from the email."""
    body = ""
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))
            if 'attachment' not in content_disposition:  # Skip attachments
                if content_type == 'text/plain' or content_type == 'text/html':
                    body = part.get_payload(decode=True)
                    if body:
                        body = body.decode('utf-8', errors='ignore')
                        break
    else:
        body = email_message.get_payload(decode=True)
        if body:
            body = body.decode('utf-8', errors='ignore')

    return body


def extract_attachments(email_message, output_dir):
    """Extract attachments from the email and save them to the specified directory."""
    attachments = []
    for part in email_message.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get('Content-Disposition'))
        if 'attachment' in content_disposition:
            filename = part.get_filename()
            if filename:
                file_path = os.path.join(output_dir, filename)
                with open(file_path, 'wb') as file:
                    file.write(part.get_payload(decode=True))
                attachments.append(filename)
                print(f"  Attachment saved as: {file_path}")
    
    # Return a string of attachment filenames or "None" if no attachments
    return ", ".join(attachments) if attachments else "None"

# Example usage
# mbox_file_path = 'sample.mbox'
# result = process_email_forensics(mbox_file_path)
