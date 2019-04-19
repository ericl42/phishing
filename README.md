# Phishing Inbox Monitor
**Disclaimer:** This is my first real Python program that I've written so I'm sure there are a lot of items that I could/should have handled differently. I'm always open for suggestions on how to make it better.

This script will monitor an inbox and pull out all relevant information for a SecOps team to review.

# Workflow
1. Script runs via a cronjob that monitors an inbox for unread messages every minute.
 - If there are multiple messages, it will only pull one at a time to help spread out the VirusToal API calls as well as to simplify the amount of variables that are being pulled in.
 - It will pull in emails with .msg files attached to it or basic forwarded messages.
2. Depending on the content of the email message, it will SHA256 the attachment and look it up via VirusTotal as well as lookup the URL if there is one.
3. Once it gets all of the relevant information, it will then create a ServiceNow ticket.
 - Note: This is for our internal process only. You will need to substitute your own ticketing API call here.
 4. The ticket contents will show the basic email information at the top and then any VT information below.
 - The format of the results are
   - URL or SHA256 Scanned
   - Date Scanned
   - Amount of positive hits
   - Link to the scan results.
 - If there there are no results, it will either show up as empty, null, or say there are no results. This slightly varies depending on if it's a file or URL.
 - The free VT API only allows 4 API calls per minute. So if there is an email with more than 4 calls, it will only lookup the first 4.

# To Do
1. Better error handling around the initial VT query on if the service is down or we've met our threshold.
2. Better error handling around VT results. Since there are quite a few items that can come back, I haven't seen them all yet.
3. Fix some formatting issues on the subject if the message is forwarded to the inbox.
4. Make the SN description field "prettier".
5. Add other reputation lookups so additional information is in the initial ticket.
6. If positives is greater than X, automatically block via security tools.
