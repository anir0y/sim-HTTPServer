import requests
import random


# print flag{pass-rand}
rand = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=9))
user_random = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=3))
# Function to simulate HTTP login
def simulate_http_login(url, username, password):
    """
    Simulates an HTTP login by sending a POST request with credentials.
    :param url: The login endpoint URL
    :param username: Username for login
    :param password: Password for login
    """
    try:
        print("Attempting HTTP login")
        payload = {
            "username": username,
            "password": password
        }
        response = requests.post(url, data=payload)

        if response.status_code == 200:
            print("Login successful!")
            print(f'{username} and {password}')
            print(f"Response: {response.text}")
            return True
        else:
            print(f"Login failed with status code {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"Error during HTTP login: {e}")
        return False


if __name__ == "__main__":
    # HTTP login simulation
    login_url = "http://localhost/login"  # Replace with the actual login URL
    username = f"user_{user_random}"                # Replace with your username
    password = rand            # Replace with your password
  

    # add repeat count of sending cred
    num_attempts = 5  # You can change this number to control how many attempts
    print(f"\nStarting multiple login attempts ({num_attempts} times)...")
    for i in range(num_attempts):
        print(f"\nAttempt {i+1}/{num_attempts}")
        new_user_random = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=3))
        new_password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=9))
        simulate_http_login(login_url, f"user_{new_user_random}", new_password)

