# IP Block Bypass Payload Generator for Burp Intruder

A Python script that generates payload lists for **Burp Suite Intruder** to bypass IP‑based rate limiting during brute‑force attacks.

> **Educational use only.** Use this tool only on systems you own or have explicit written permission to test. Unauthorized testing is illegal.

---

## What Problem Does This Solve?

Many web applications protect login pages by limiting failed attempts per IP address. For example, after 5 failed logins, the IP is blocked for 15 minutes.

However, some applications **reset the failed‑attempt counter after any successful login** from that same IP. An attacker with a valid account can exploit this by:

1. Making **N‑1 failed attempts** against a victim account.
2. Logging in successfully with **their own valid account**.
3. The IP counter resets to zero.
4. Repeating the process indefinitely.

This allows the attacker to brute‑force the victim’s password without ever being blocked.

---

## How This Script Helps

This script generates two payload lists:

- **Username list:** alternates between the "victim real username" and the attacker’s valid username.
- **Password list:** alternates between "victim password guesses" and the attacker’s valid password.

When used in Burp Intruder’s **Pitchfork** attack, each request uses one username and one password from the corresponding position. The interleaved successful logins keep the IP counter below the block threshold.

---

## Requirements

- Python 3
- Burp Suite (Community or Professional)

---

## Usage

### 1. Create a password wordlist (optional)

Create a file named `passwords.txt` with one password guess per line:



### 2. Run the script

```bash
python3 ReganIpBlockBypass.py


3. Copy the output

The script prints two lists:

· Username List
· Password List

4. Configure Burp Intruder

1. Capture the login request in Burp Proxy.
2. Send to Intruder.
3. Set attack type to Pitchfork.
4. Set payload position 1 on the username parameter.
5. Set payload position 2 on the password parameter.
6. In Payloads:
   · Paste the username list into Payload Set 1.
   · Paste the password list into Payload Set 2.
7. Set Resource Pool → Maximum concurrent requests to 1.
8. Start the attack.

5. Identify success

Look for:

· A 302 redirect to a dashboard or account page.
· A different status code.
· A different response length.

The password that produces one of these differences is the correct victim password.

Limitations

· Works only if the application resets the IP failure counter on any successful login.
· Does not bypass per‑account lockouts.
· If the counter is cumulative (not reset by success), this technique will not work.
· The application must trust the actual source IP (this script does not rotate X-Forwarded-For).

---

Contributing

Pull requests and improvements are welcome. Please ensure any changes maintain the educational purpose of this tool.

---

License

This project is licensed under the MIT License – see the LICENSE file for details.

```
