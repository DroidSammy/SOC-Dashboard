import imaplib
import email
from email.header import decode_header
import json

def fetch_recent_emails(username, app_password, max_emails=50):
    """
    Connects to Gmail via IMAP using an App Password.
    Fetches the latest `max_emails` and extracts the subject and body.
    """
    try:
        # Create an IMAP4 class with SSL 
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(username, app_password)
        
        # Select the mailbox you want to check
        mail.select("inbox")
        
        # Search for all emails
        status, messages = mail.search(None, "ALL")
        if status != "OK":
            return {"error": "Failed to search inbox"}
            
        email_ids = messages[0].split()
        
        if not email_ids:
            return {"error": "IMAP connected successfully, but the INBOX is empty. Please send a test email to this account."}
            
        # Get the latest max_emails
        latest_ids = email_ids[-max_emails:]
        latest_ids.reverse() # Newest first
        
        results = []
        
        for e_id in latest_ids:
            res, msg = mail.fetch(e_id, "(RFC822)")
            if res != "OK":
                continue
                
            parsed = False
            for response_part in msg:
                if isinstance(response_part, tuple):
                    try:
                        msg_obj = email.message_from_bytes(response_part[1])
                        
                        # Decode subject
                        subject = "No Subject"
                        if msg_obj["Subject"]:
                            subj_decode = decode_header(msg_obj["Subject"])[0]
                            subject, encoding = subj_decode
                            if isinstance(subject, bytes):
                                subject = subject.decode(encoding if encoding else "utf-8", errors="ignore")
                        else:
                            subject = str(subject)
                                
                        from_ = msg_obj.get("From", "Unknown Sender")
                        
                        body = ""
                        if msg_obj.is_multipart():
                            for part in msg_obj.walk():
                                if part.get_content_type() == "text/plain":
                                    try:
                                        body = part.get_payload(decode=True).decode(errors="ignore")
                                        break
                                    except:
                                        pass
                        else:
                            try:
                                body = msg_obj.get_payload(decode=True).decode(errors="ignore")
                            except:
                                body = "Could not decode body"
                                
                        if not body:
                            body = "(Empty Body)"
                            
                        results.append({
                            "subject": subject,
                            "sender": from_,
                            "body": body[:1000]
                        })
                        parsed = True
                    except Exception as parse_e:
                        print("Failed to parse email:", str(parse_e))
                        
            if not parsed:
                results.append({
                    "subject": "Unparseable Email",
                    "sender": "Unknown",
                    "body": "This email could not be parsed by the IMAP client."
                })
                    
        mail.logout()
        return {"emails": results}
        
    except imaplib.IMAP4.error as e:
        return {"error": f"IMAP Authentication failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Error fetching emails: {str(e)}"}
