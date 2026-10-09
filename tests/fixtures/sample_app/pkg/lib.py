import requests


class Client:
    def fetch(self, url):
        return requests.get(url)


def public_api(url):
    client = Client()
    return client.fetch(url)


def unused_api(url):
    return requests.post(url)
