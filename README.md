# Telstra Cybersecurity Job Simulation – Spring4Shell Incident Response

This repository contains my solution for the **Telstra Cybersecurity Job Simulation** hosted on Forage. The simulation focused on detecting, analyzing, and mitigating a malware attack exploiting the **Spring4Shell vulnerability (CVE-2022-22965)** targeting critical infrastructure — specifically, the NBN Connection service.

---

## Table of Contents

- [Project Overview](#project-overview)  
- [Tasks Completed](#tasks-completed)  
  - [Task 1: Threat Triage & Infrastructure Notification](#task-1-threat-triage--infrastructure-notification)  
  - [Task 2: Attack Pattern Analysis & Network Team Communication](#task-2-attack-pattern-analysis--network-team-communication)  
  - [Task 3: Technical Mitigation via Python Firewall Server](#task-3-technical-mitigation-via-python-firewall-server)  
  - [Task 4: Incident Postmortem Documentation](#task-4-incident-postmortem-documentation)  
- [Code](#code)  
  - [`firewall_server.py`](#firewall_serverpy)  
  - [`test_requests.py`](#test_requestspy)  
- [Key Learnings](#key-learnings)  
- [How to Run](#how-to-run)  
- [References](#references)  
- [Contact](#contact)  

---

## Project Overview

This simulation was designed to emulate a realistic cybersecurity incident response scenario involving a Spring4Shell exploitation attempt on a critical infrastructure service (NBN Connection).

It required working through multiple stages:

- Log analysis and triage to identify the affected infrastructure and threat severity.  
- Drafting clear and concise communication to infrastructure and network teams.  
- Writing a Python-based firewall server to block malicious requests.  
- Documenting the incident with a detailed postmortem report.

The goal was to build practical skills in threat detection, communication, incident response, and technical mitigation.


[Firewall Log file](Firewall_log.xlsx)

---

## Task 1
### Here is your task
Your task is to triage the current malware threat and figure out which infrastructure is affected.

First, find out which key infrastructure is currently under attack. Note the priority of the affected infrastructure to the company - this will determine who is the respective team to notify.

After, draft an email to the respective team alerting them of the current attack so that they can begin an incident response. Make sure to include the timestamp of when the incident occurred. Make it concise and contextual.

The purpose of this email is to ensure the respective team is aware of the ongoing incident and to be prepared for mitigation advice.

Estimated time for task completion: 30 minutes depending on your learning style.

```plaintext
From: Telstra Security Operations  
To: NBN Team (nbn@gmail)  
Subject: Malware Activity Detected – Immediate Attention Required on NBN Connection Infrastructure  

Hello NBN Team,

At 2022-03-20T03:21:00Z, we detected a malware exploitation attempt targeting your critical infrastructure, NBN Connection. The attacker sent a crafted POST request to /tomcatwar.jsp on nbn.external.network, attempting to deploy a JSP-based web shell via ClassLoader abuse, exploiting the Spring Framework (version 5.3.0).

The request originated from IPs ranging from attacker.ip.address.network1 to network499, with the action marked as bypass, indicating the threat was not blocked by the firewall.

Please initiate incident response procedures immediately to assess for compromise and begin mitigation.

For any questions or issues, don’t hesitate to reach out to us.

Kind regards,  
Telstra Security Operations
```
---

## Task 2

Here is the background information on your task
Now that you have notified the infrastructure owner of the current attack, analyse the firewall logs to find the pattern in the attacker’s network requests. You won’t be able to simply block IP addresses, because of the distributed nature of the attack, but maybe there is another characteristic of the request that is easy to block.

An important responsibility of an information security analyst is the ability to work across disciplines with multiple teams, both technical and non-technical.

In the resources section, we have attached a proof of concept payload that may be of interest in understanding how the attacker scripted this attack.

-----------------
Here is your task
First, analyse the firewall logs in the resources section.

Next, identify what characteristics of the Spring4Shell vulnerability have been used.

Finally, draft an email to the networks team with your findings. Make sure to be concise, so that they can develop the firewall rule to mitigate the attack. You can assume the recipient is technical and has dealt with these types of requests before.

Estimated time for task completion: 30-60 minutes depending on your learning style.


Plaintext
```
From: Telstra Security Operations  
To: Networks Team (networks@telstra.com)  
Subject: Create Firewall Rule – Spring4Shell Exploit Blocking  

Hello Networks Team,

We would like to request the creation of a firewall rule and provide you more information about the ongoing attack.

We’ve identified a series of POST-based attacks leveraging the Spring4Shell vulnerability. The attacker is attempting to drop a malicious JSP web shell by injecting Java code through Spring’s class loader properties.

We recommend blocking POST requests to .jsp paths that include suspicious headers or payload patterns:

Headers like c1=Runtime, c2=<%, or suffix=%>//

Payload parameters using class.module.classLoader.resources.context.parent.pipeline.first.*

Suspicious values such as .getRuntime().exec( or request.getParameter("cmd")

These indicators are consistent with known Spring4Shell exploit chains and were observed in recent logs affecting our critical infrastructure.

For any questions or issues, don’t hesitate to reach out to us.

Kind regards,  
Telstra Security Operations

```
## Task 3
(Technical) Mitigate the malware attack
Using the patterns you’ve identified, use Python to write a firewall rule to technically mitigate the malware from spreading.

------------------

Here is the background information on your task
Work with the networks team to implement a firewall rule using the Python scripting language. Python is a common scripting language used across both offensive and defensive information security tasks.

In this task, we will simulate the firewall’s scripting language by using an HTTP Server. You can assume this HTTP Server has no computational requirements and has the sole purpose of filtering incoming traffic.

In the starter codebase, you will find a test script that you can use to simulate the malicious requests to the server.

You can check out the Readme file in the starter codebase for more information on how to get started.

--------------
Here is your task
Use Python to develop a firewall rule to mitigate the attack. Develop this rule in `firewall_server.py` and only upload this file back here.

You may use `test_requests.py` to test your code whilst the firewall HTTP server is running.

Estimated time for task completion: 60-90 minutes depending on your learning style.

```python
# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

host = "localhost"
port = 8000

# Blocking the request and printing a log message
def block_request(self):
    print("Blocking suspicious request from", self.client_address[0])
    self.send_response(403)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request blocked due to suspicious activity"}')

# Allowing the request to response by sending 200 OK
def allow_request(self):
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request allowed"}')

# To Analyze if the request matches the exploit pattern
def is_suspicious(self):
    # We Only interested in the POST requests
    if self.command != "POST":
        return False

    # Parse path, block if it contains .jsp
    parsed_path = urlparse(self.path)
    if ".jsp" not in parsed_path.path:
        return False

    # Checking suspicious headers
    headers = self.headers
    if not (headers.get("c1") == "Runtime" and headers.get("c2") == "<%" and headers.get("suffix") == "%>//"):
        return False

    # Read content length and parse POST data
    content_length = int(headers.get('Content-Length', 0))
    post_data = self.rfile.read(content_length).decode('utf-8')

    # Check payload patterns
    suspicious_patterns = [
        "class.module.classLoader.resources.context.parent.pipeline.first.",
        ".getRuntime().exec(",
        'request.getParameter("cmd")'
    ]

    for pattern in suspicious_patterns:
        if pattern in post_data:
            return True

    return False

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        allow_request(self)

    def do_POST(self):
        if is_suspicious(self):
            block_request(self)
        else:
            allow_request(self)

if __name__ == "__main__":        
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s, %s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)

```
## Task 4
Incident Postmortem
Now that the incident has been resolved, create a postmortem to reflect on the details of the incident.

--------------------

Here is the background information on your task
The firewall rule worked in stopping the malware attack, 2 hours after the attack began.

After an incident has occurred, it’s best practice to document and record what has happened. A common report written after an incident is a postmortem, which covers a timeline of what has occurred, who was involved in responding to the incident, a root cause analysis and any actions which have taken place.

The purpose of the postmortem is to provide a ‘paper trail’ of what happened, which may be used in future governance, risk, or compliance audits, but also to educate the team on what went down, especially for those on the team who weren’t involved.

In the resources section, you will find some educational content about what is an incident postmortem and why it’s important to create one.

--------------

Here is your task
For this task, create an incident postmortem of the malware attack, covering the details you have picked up in the previous tasks.

Make sure to include when the incident started and the root cause. Remember, the more detail the better.

Estimated time for task completion: 30 minutes depending on your learning style.
---------------------
[Download the Incident Postmortem Word Document](Task-4.docx)

