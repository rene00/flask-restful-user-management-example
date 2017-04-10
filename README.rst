=======================================
Flask-RESTful user registration example
=======================================

-----
What?
-----

A proof of concept user registration API service that uses Flask-RESTful aswell
as bits of Flask-Security and friends.

Users are able to sign up, confirm, authenticate and view a URL which requires
an authenticated session.

----
Why?
----

I wanted to build an HTTP API service which allows for clients to perform user
registration and management. First though, I needed to build a proof of
concept.

----
How?
----

**Server**

Build the virtualenv::

    $ make build

Run the service::

    $ make run

The API server will be listening on 127.0.0.1:5000. Ensure you have an SMTP
server listening on localhost:25.


**Client**

Register an account::

    $ curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:5000/account/register -d '{"email": "your_email@example.org", "password": "s3cr3t"}'

Click on confirmation link that is sent to your_email@example.org.

Login and generate an authentication token::

    $ curl -X GET -H 'Content-Type: application/json' http://127.0.0.1:5000/account/login -u 'your_email@example.org:s3cr3t'

Use the token to authenticate and view account/info::

    $ curl -X GET -H 'Content-Type: application/json'  -H "Authentication-Token: TOKEN" http://127.0.0.1:5000/account/info

client.py has an ApiAuth class which uses requests to perform the initial basic
authentication, store the token to disk and access account/info::

    $ venv/bin/python client.py --api-url=http://127.0.0.1:5000 --username=your_email@example.org --password=s3cr3t
