import requests

TARGET_URL = ".../login/" #e.g https://orlantech.com/login


def simulate_attack():
    client = requests.session()
    client.get(TARGET_URL)
    csrftoken = client.cookies.get('csrftoken', '')

    for i in range(1, 10):
        # Sending a fake POST request (Login Attempt)
        data = {
            'username': 'attacker_admin',
            'password': 'wrong_password_123',
            'csrfmiddlewaretoken': csrftoken
        }

        response = client.post(TARGET_URL, data=data, headers=dict(Referer=TARGET_URL))

        if response.status_code == 403:
            print(f"[{i}] 🛡️ SENTINEL TRIGGERED: Banned.")
            break
        else:
            print(f"[{i}] Attempting login...")


simulate_attack()