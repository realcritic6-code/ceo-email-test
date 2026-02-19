from flask import Flask, render_template, request, redirect
import base64
import os
from datetime import datetime

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

app = Flask(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']


def get_gmail_service():
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)


def get_body(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data')
                if data:
                    return base64.urlsafe_b64decode(data).decode(errors="ignore")
    else:
        data = payload['body'].get('data')
        if data:
            return base64.urlsafe_b64decode(data).decode(errors="ignore")
    return ""


def categorize(labels):
    if "IMPORTANT" in labels:
        return "urgent"
    if "CATEGORY_PROMOTIONS" in labels:
        return "promotion"
    return "normal"


@app.route("/")
def index():
    service = get_gmail_service()

    results = service.users().threads().list(
        userId='me',
        maxResults=25
    ).execute()

    threads = results.get('threads', [])
    emails = []

    for thread in threads:
        thread_data = service.users().threads().get(
            userId='me',
            id=thread['id']
        ).execute()

        messages = thread_data['messages']
        latest = messages[-1]

        headers = latest['payload']['headers']
        labels = latest.get('labelIds', [])

        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), '')
        unread = any('UNREAD' in m.get('labelIds', []) for m in messages)

        category = categorize(labels)

        emails.append({
            "id": thread['id'],
            "subject": subject,
            "sender": sender,
            "unread": unread,
            "category": category
        })

    # SORT: urgent → promotion → normal
    order = {"urgent": 0, "promotion": 1, "normal": 2}
    emails.sort(key=lambda x: order[x["category"]])

    return render_template("index.html", emails=emails)


@app.route("/email/<thread_id>")
def email_detail(thread_id):
    service = get_gmail_service()

    thread = service.users().threads().get(
        userId='me',
        id=thread_id
    ).execute()

    emails = []
    last_message_id = None
    last_sender = ""
    last_subject = ""

    for msg in thread['messages']:
        headers = msg['payload']['headers']

        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), '')

        body = get_body(msg['payload'])

        emails.append({
            "subject": subject,
            "sender": sender,
            "body": body
        })

        last_message_id = msg['id']
        last_sender = sender
        last_subject = subject

    # mark latest message as read
    service.users().messages().modify(
        userId='me',
        id=last_message_id,
        body={'removeLabelIds': ['UNREAD']}
    ).execute()

    return render_template(
        "detail.html",
        emails=emails,
        thread_id=thread_id,
        reply_to=last_sender,
        subject=last_subject
    )

@app.route("/generate_reply")
def generate_reply():
    return "Thank you for your message. We will get back to you shortly."


@app.route("/send_reply", methods=["POST"])
def send_reply():
    service = get_gmail_service()

    to = request.form["to"]
    subject = request.form["subject"]
    message_text = request.form["message"]

    message = f"To: {to}\r\nSubject: Re: {subject}\r\n\r\n{message_text}"
    raw = base64.urlsafe_b64encode(message.encode()).decode()

    service.users().messages().send(
        userId="me",
        body={"raw": raw}
    ).execute()

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
