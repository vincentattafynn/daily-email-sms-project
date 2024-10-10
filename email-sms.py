import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import date, timedelta
import base64
from bs4 import BeautifulSoup


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def extract_email_content(email_html):
    soup = BeautifulSoup(email_html, 'html.parser')

    email_text = soup.get_text(separator=' ',strip=True)

    short_text = email_text[:160] + "..." if len(email_text) > 160 else email_text

    return short_text

def get_important_unread_messages(creds):
    prev_date = date.today() - timedelta(days=1)
    prev_date.strftime("%Y-%m-%d").replace("-", "/")

    service = build("gmail", "v1", credentials=creds)

    results = service.users().messages().list(userId='me', labelIds=['INBOX'], q=f"after:{prev_date}").execute()

    messages = results.get('messages', [])

    email_list = []

    if not messages:
        print("No emails found")
    else:
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            email_data = msg['payload']['headers']
            for values in email_data:
                if values["name"] == "From":
                    from_name = values['value']
                    

                   
                    if 'parts' in msg['payload']:
                        for part in msg['payload']['parts']:
                            if part['mimeType'] == 'text/html':
                                data = part['body']['data']
                                byte_code = base64.urlsafe_b64decode(data)
                                text = byte_code.decode("utf-8")
                                email_text = extract_email_content(text)
                                email_list.append(f"From: {from_name} + {email_text}")
                    else:
                        
                        body = msg['payload'].get('body', {}).get('data')
                        if body:
                            byte_code = base64.urlsafe_b64decode(body)
                            text = byte_code.decode("utf-8")
                            email_text = extract_email_content(text)
                            email_list.append(f"From: {from_name} + {email_text}")

    return email_list



def main():
    creds = None

    
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        
        
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        email_list = get_important_unread_messages(creds)
        for email in email_list:
            print(email)

    except HttpError as error:
        print(f"An error occurred: {error}")

if __name__ == "__main__":
    main()
