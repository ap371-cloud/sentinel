import requests

url = "https://www.wikipedia.org/"

response = requests.get(url)

if response.status_code == 200:
    data = response.json()
    print(data["extract"])
else:
    print("Error:", response.status_code)