import requests
import click


def read_file_contents(path):
    with open(path) as fh:
        return fh.read().strip()


class ApiAuth(requests.auth.AuthBase):

    session = requests.Session()
    session.headers = {'Content-Type': 'application/json'}

    def __init__(self, api_url, username, password):
        self.api_url = api_url
        self.username = username
        self.password = password
        self.token = None
        try:
            self.token = read_file_contents('token')
        except FileNotFoundError:
            self.token = self.login()
        finally:
            self.session.headers.update(
                {'Authentication-Token': self.token}
            )

    def login(self):
        r = requests.get(
            '{0}/account/login'.format(self.api_url),
            headers=self.session.headers,
            auth=(self.username, self.password)
        )
        r.raise_for_status()
        token = r.json()['token']

        # save token
        with open('token', 'w') as fh:
            fh.write(token)

        return r.json()['token']

    def __call__(self, r):
        r.headers = self.session.headers
        return r


@click.command()
@click.option('--api-url', required=True)
@click.option('--username', required=True)
@click.option('--password', required=True)
def test_auth(api_url, username, password):
    r = requests.get(
        '{0}/account/info'.format(api_url),
        auth=ApiAuth(api_url, username, password)
    )
    if r.ok:
        print("Success.")
    else:
        print("Failed to login.")

if __name__ == '__main__':
    test_auth()
