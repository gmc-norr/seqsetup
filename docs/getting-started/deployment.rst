Deployment
==========

SeqSetup can be deployed using Docker containers. This guide covers various
deployment scenarios from development to production.

Container Architecture
----------------------

SeqSetup uses a two-container architecture:

- **App container**: The SeqSetup Python application
- **MongoDB container**: The database (or external MongoDB service)

.. note::

   Keep MongoDB in a separate container (or use an external service). This
   allows independent scaling, easier backups, and database persistence
   across application updates.

Quick Start with Docker Compose
-------------------------------

The simplest way to run SeqSetup is with Docker Compose, which starts both
the application and MongoDB. First copy ``.env.example`` to ``.env`` and fill
it in: ``docker compose`` refuses to start while a required value is missing,
``SEQSETUP_HTTPS_ONLY`` among them (see :ref:`port-and-https`).

.. code-block:: bash

   # Your settings (once), then fill in .env
   cp .env.example .env

   # Build and start both containers
   docker compose up --build

   # Run in background (detached)
   docker compose up -d

   # View logs
   docker compose logs -f

   # Stop containers
   docker compose down

   # Stop and remove data volume (destroys all data!)
   docker compose down -v

The application will be available at http://localhost:5001 on the server
itself; other machines reach it through your TLS proxy (see
:ref:`port-and-https`).

.. _port-and-https:

Port and HTTPS
~~~~~~~~~~~~~~

``docker-compose.yml`` publishes the app's port 5001 on ``127.0.0.1`` only:
the server itself, and a TLS proxy running on it, can reach the app; other
machines cannot. When the proxy runs on another machine, set
``SEQSETUP_PUBLISH_ADDRESS`` in ``.env`` to this server's address on the
network the proxy uses (``0.0.0.0`` for every interface). A proxy that itself
runs in a container cannot use ``127.0.0.1``, which inside its container is its
own: run it in this Compose project (for example as a service in a
``docker-compose.override.yml``), point it at ``http://app:5001``, and leave
``SEQSETUP_PUBLISH_ADDRESS`` unset.

.. important::

   This needs **Docker Engine 28.0.0 or newer**. In older releases, machines
   on the same network switch can reach ports published to ``127.0.0.1``
   (Docker's own warning; moby/moby#45610). Check the version with
   ``docker version --format '{{.Server.Version}}'``, and upgrade an older
   engine before installing SeqSetup. A host firewall such as ufw is no
   substitute: Docker routes published ports before ufw's rules apply (Docker's
   page "Packet filtering and firewalls"). The same holds when
   ``SEQSETUP_PUBLISH_ADDRESS`` opens the port: ufw rules on this server do not
   limit who reaches it.

``.env`` must set ``SEQSETUP_HTTPS_ONLY``; ``docker compose`` refuses to start
without it. Set it to ``1`` when users reach SeqSetup over HTTPS: the session
cookie is marked ``Secure`` (browsers send it only over HTTPS), and every
answer carries HSTS (``Strict-Transport-Security: max-age=63072000;
includeSubDomains``), which tells browsers to use only HTTPS for this host
name. Set it to ``0`` only for a trial over plain HTTP. ``1``, ``true`` and
``yes`` mean on, ``0``, ``false`` and ``no`` off, in any case; any other value
stops SeqSetup at start and says so.

.. note::

   ``includeSubDomains``: once a browser has seen HSTS from SeqSetup's host
   name, that name, on every port, and every name under it
   (``x.seqsetup.example.com``) work only over HTTPS in that browser, for two
   years. Give SeqSetup a host name of its own, with no plain-HTTP service on
   another port; names beside it (``other.example.com``) are not affected.

Building the Docker Image
-------------------------

To build the SeqSetup image separately:

.. code-block:: bash

   docker build -t seqsetup .

The image uses the Pixi package manager to install dependencies and runs
the application on port 5001.

Connecting to External MongoDB
------------------------------

If you have an existing MongoDB instance (self-hosted or cloud service),
run only the application container. As with Docker Compose, publish the port
on ``127.0.0.1`` and set ``SEQSETUP_HTTPS_ONLY`` (see :ref:`port-and-https`):

.. code-block:: bash

   docker run -d \
     --name seqsetup \
     -p 127.0.0.1:5001:5001 \
     -e SEQSETUP_HTTPS_ONLY=1 \
     -e MONGODB_URI=mongodb://your-mongodb-host:27017 \
     -e MONGODB_DATABASE=seqsetup \
     -e SEQSETUP_SESSION_SECRET=$(openssl rand -hex 32) \
     -v ./config:/app/config \
     seqsetup

MongoDB Atlas (Cloud)
~~~~~~~~~~~~~~~~~~~~~

For MongoDB Atlas, use the connection string from the Atlas dashboard:

.. code-block:: bash

   docker run -d \
     --name seqsetup \
     -p 127.0.0.1:5001:5001 \
     -e SEQSETUP_HTTPS_ONLY=1 \
     -e MONGODB_URI="mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true" \
     -e MONGODB_DATABASE=seqsetup \
     -e SEQSETUP_SESSION_SECRET=$(openssl rand -hex 32) \
     seqsetup

Environment Variables
---------------------

Configure the application using environment variables:

.. list-table::
   :header-rows: 1
   :widths: 30 50 20

   * - Variable
     - Description
     - Default
   * - ``MONGODB_URI``
     - MongoDB connection string
     - ``mongodb://localhost:27017``
   * - ``MONGODB_DATABASE``
     - Database name
     - ``seqsetup``
   * - ``SEQSETUP_SESSION_SECRET``
     - Session encryption key (32+ hex characters)
     - Auto-generated
   * - ``INSTRUMENTS_CONFIG``
     - Path to the instruments YAML file to read instead of the one SeqSetup
       ships. Set, it decides; SeqSetup does not start when it names a path
       that is not a file (see :doc:`/admin-guide/instruments`)
     - unset: ``config/instruments.yaml``
   * - ``TZ``
     - The time zone SeqSetup shows times in, an IANA name such as
       ``Europe/Stockholm`` (see :ref:`time-zone`)
     - The server's own zone
   * - ``SEQSETUP_HTTPS_ONLY``
     - ``1`` (or ``true``, ``yes``) when users reach SeqSetup over HTTPS:
       Secure session cookie and HSTS; ``0`` (or ``false``, ``no``) for plain
       HTTP. Any other value stops the start. Required with Docker Compose
       (see :ref:`port-and-https`)
     - Off
   * - ``SEQSETUP_PUBLISH_ADDRESS``
     - Docker Compose only: the address the app's port is published on
       (see :ref:`port-and-https`)
     - ``127.0.0.1``

.. _time-zone:

Time Zone
~~~~~~~~~

SeqSetup stores every time in UTC and shows it in one time zone, with the
zone's name after the time (for example ``2026-03-10 10:17 CET``): on the
pages, including the audit trail and its date search, in the v1 Sample
Sheet's ``Date`` and in the validation reports. Set ``TZ`` to your lab's
zone, for example ``TZ=Europe/Stockholm`` in ``.env``; without it, SeqSetup
uses the server's own zone, which in a container is usually UTC.

``TZ`` must be an IANA zone name (``Europe/Stockholm``, ``UTC``). Other forms
the operating system accepts, such as ``:/etc/localtime``, a file path or a
rule like ``CET-1CEST,M3.5.0,M10.5.0/3``, are refused: if ``TZ`` names no
known zone, SeqSetup stops at start and says so, rather than showing times
in UTC without anyone noticing.

Two kinds of time are not shown in the zone: the details of an audit event
keep the UTC time they were recorded with (marked ``+00:00``), and the dates
of LIMS worklists are shown as the LIMS gives them. In the API, run times
are UTC ending in ``Z``, and the validation report's ``timestamp`` carries
its offset from UTC.

Production Deployment
---------------------

For production deployments, consider the following configuration.

Production Docker Compose
~~~~~~~~~~~~~~~~~~~~~~~~~

Create a ``docker-compose.prod.yml``:

.. code-block:: yaml

   services:
     app:
       image: seqsetup:latest
       ports:
         - "127.0.0.1:5001:5001"
       environment:
         - MONGODB_URI=mongodb://mongodb:27017
         - MONGODB_DATABASE=seqsetup
         - SEQSETUP_SESSION_SECRET=${SESSION_SECRET}
         - SEQSETUP_HTTPS_ONLY=1
       volumes:
         - ./config:/app/config:ro
       depends_on:
         - mongodb
       restart: unless-stopped

     mongodb:
       image: mongo:7
       volumes:
         - mongo_data:/data/db
       restart: unless-stopped
       # Don't expose port externally in production

   volumes:
     mongo_data:

Run with:

.. code-block:: bash

   # Generate a session secret and start
   export SESSION_SECRET=$(openssl rand -hex 32)
   docker compose -f docker-compose.prod.yml up -d

Production Checklist
~~~~~~~~~~~~~~~~~~~~

Before deploying to production:

1. **Set a secure session secret**

   Generate and store a persistent session secret:

   .. code-block:: bash

      openssl rand -hex 32

   Store this value securely and pass it via ``SEQSETUP_SESSION_SECRET``.
   If the secret changes, all user sessions will be invalidated.

2. **Configure LDAP/AD authentication**

   Set up LDAP or Active Directory sign-in through the admin interface, with
   both the Users group and the Admins group. See
   :doc:`/admin-guide/authentication`.

3. **Test directory sign-in once**

   On **Admin > Authentication**, use **Run Sign-in Test** with a member of
   the Admins group, a member of the Users group, and someone in neither.
   The first two must sign in with the right role; the third must be
   refused.

4. **No old sign-in settings on the server**

   There must be no ``config/users.yaml`` and no
   ``SEQSETUP_LDAP_BIND_PASSWORD``. Neither is used any more; the app logs a
   warning at start when it finds one.

5. **Enable LDAP SSL certificate verification**

   In the LDAP settings, enable "Verify SSL Certificate" to prevent
   man-in-the-middle attacks.

6. **Use a reverse proxy**

   Place SeqSetup behind a reverse proxy (nginx, Traefik, etc.) that
   handles:

   - HTTPS termination
   - Rate limiting
   - Access logging

   Set ``SEQSETUP_HTTPS_ONLY=1`` and keep the app's port on ``127.0.0.1``
   (see :ref:`port-and-https`).

7. **Back up MongoDB regularly**

   Set up automated backups of the MongoDB data volume or use MongoDB
   Atlas with automated backups.

Reverse Proxy Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Example nginx configuration:

.. code-block:: nginx

   server {
       listen 443 ssl;
       server_name seqsetup.example.com;

       ssl_certificate /etc/ssl/certs/seqsetup.crt;
       ssl_certificate_key /etc/ssl/private/seqsetup.key;

       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;

       # SeqSetup caps each request body itself: 2 MB, and 21 MB only where
       # samples are added from a file (nginx's own default is 1 MB).
       client_max_body_size 2m;

       location / {
           proxy_pass http://127.0.0.1:5001;
       }

       location ~ ^/runs/[^/]+/samples/(preview|bulk)$ {
           client_max_body_size 21m;
           proxy_pass http://127.0.0.1:5001;
       }
   }

.. important::

   Behind a **TLS-terminating** reverse proxy (HTTPS at the proxy, plain HTTP to
   the app), the app sees ``http`` as its own scheme while browsers send
   ``Origin: https://your-host``. The CSRF Origin check then rejects every
   state-changing request (POST/PUT/PATCH/DELETE) with HTTP 403. Set
   ``SEQSETUP_TRUSTED_ORIGINS`` to your public HTTPS origin(s) (comma-separated,
   e.g. ``https://seqsetup.example.com``) so the Origin check accepts them. HSTS
   does not depend on it: with ``SEQSETUP_HTTPS_ONLY=1`` every answer carries
   HSTS (see :ref:`port-and-https`). Both are required production config
   whenever TLS is terminated upstream.

Fail-Closed External-Service Gates
----------------------------------

For safety, connections to external services fail **closed** by default. An
existing deployment that relied on a non-TLS or private-network service will
stop authenticating users or importing worklists the moment it upgrades — the
failure surfaces only as a login or import error. Review these before
upgrading and set the opt-ins only where a deployment genuinely needs them.

LDAP over cleartext
~~~~~~~~~~~~~~~~~~~~~

The app refuses to bind to an LDAP server over a cleartext connection
(an ``ldap://`` URL / port 389 with no TLS), because every user's password would
cross the network in the clear. Use ``ldaps://`` (or a host configured for
TLS). Only on a trusted, isolated network may you opt back in:

.. code-block:: bash

   SEQSETUP_LDAP_ALLOW_CLEARTEXT=1   # NOT for production

If this is unset and the configured URL is cleartext, directory sign-in is
refused (local fallback applies if it is on), and **Run Connection Test** on
**Admin > Authentication** shows a message that names this variable.

LIMS over plain HTTP or on a private network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The LIMS API client requires HTTPS and refuses hostnames that resolve to a
loopback / link-local / RFC1918-private / reserved address (an SSRF guard).
Production must use HTTPS so the api-key is never sent in clear. For a LIMS
that legitimately lives on a private corporate network, or speaks plain HTTP
in a dev setup, opt in explicitly — this is a deliberate, audited decision per
deployment:

.. code-block:: bash

   SEQSETUP_LIMS_ALLOW_HTTP=1          # LIMS speaks plain HTTP (sends api-key in clear)
   SEQSETUP_LIMS_ALLOW_PRIVATE_NETS=1  # LIMS resolves to a private/RFC1918 address

Leave both unset in production.

Health Checks
-------------

The application exposes a simple health check at the root URL. A successful
response indicates the application is running. For more comprehensive health
checks, verify database connectivity by accessing the dashboard (requires
authentication).

Updating the Application
------------------------

To update to a new version:

.. code-block:: bash

   # Pull or build the new image
   docker compose build

   # Restart with the new image
   docker compose up -d

   # Or for a clean restart
   docker compose down
   docker compose up -d

The MongoDB data volume persists across container restarts, so your data
is preserved during updates.

Versions before the one that added ``TZ`` stored times in the server's own
zone, and SeqSetup has no tool to convert them. If that zone was not UTC,
times stored before the update are read as UTC, so they are off by the
zone's offset: they are shown shifted, the API gives them shifted (a run's
``updated_at`` can then go backwards when it is changed after the update,
which matters to a LIMS that asks for runs changed since its last check),
lists that sort by time can put old and new entries in the wrong order, and
API tokens made before the update end that much earlier or later. On such a
server, start from an empty database, or accept these shifts for the old
data. A server that ran on UTC is not affected.

.. _lims-stored-key-check:

Check for a stored LIMS api-key before updating
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Versions before the one that removed the api-key box on
**Admin > LIMS Integration** stored the typed key in the settings
collection. This version never reads, uses or writes that value, and the
next save of that page removes it — but until someone saves the page, the
old key is still in the database and in every backup taken from it.

SeqSetup runs no migration for this. Before updating, ask the database
whether a key is stored. The command below prints a one-line answer and
never prints the key; ``MONGODB_URI`` is the same connection string the app
uses:

.. code-block:: bash

   mongosh "$MONGODB_URI" --quiet --eval 'print(db.settings.countDocuments({_id: "sample_api_config", "config.api_key": {$nin: ["", null]}}) ? "a LIMS api-key is stored" : "no LIMS api-key is stored")'

If it says a key is stored: after updating, open
**Admin > LIMS Integration** (which now says the same thing) and press
**Save Configuration** to remove it, set the real key in
``SEQSETUP_LIMS_API_KEY``, and treat the old key as exposed — rotate it in
the LIMS, and remember that database backups taken before the save still
contain it.

Troubleshooting
---------------

Container won't start
~~~~~~~~~~~~~~~~~~~~~

Check the logs:

.. code-block:: bash

   docker compose logs app

Common issues:

- MongoDB not reachable: Ensure the MongoDB container is running and the
  URI is correct
- Port already in use: Change the port mapping in docker-compose.yml
- Permission denied on config volume: Check file permissions

Cannot connect to MongoDB
~~~~~~~~~~~~~~~~~~~~~~~~~

Verify MongoDB is running and accessible:

.. code-block:: bash

   # Check MongoDB container status
   docker compose ps

   # Test MongoDB connection
   docker compose exec mongodb mongosh --eval "db.stats()"

Session issues after restart
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If users are logged out after container restarts, ensure
``SEQSETUP_SESSION_SECRET`` is set to a persistent value rather than
being auto-generated on each start.
