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
the application and MongoDB:

.. code-block:: bash

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

The application will be available at http://localhost:5001.

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
run only the application container:

.. code-block:: bash

   docker run -d \
     --name seqsetup \
     -p 5001:5001 \
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
     -p 5001:5001 \
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
     - Path to instruments YAML config
     - ``config/instruments.yaml``
   * - ``TZ``
     - The time zone SeqSetup shows times in, an IANA name such as
       ``Europe/Stockholm`` (see :ref:`time-zone`)
     - The server's own zone

.. _time-zone:

Time Zone
~~~~~~~~~

SeqSetup stores every time in UTC and shows it in one time zone, with the
zone's name after the time (for example ``2026-03-10 10:17 CET``): on every
page, including the audit trail and its date search, in the v1 Sample
Sheet's ``Date`` and in the validation reports. Set ``TZ`` to your lab's
zone, for example ``TZ=Europe/Stockholm`` in ``.env``; without it, SeqSetup
uses the server's own zone, which in a container is usually UTC. If ``TZ``
names no known zone, SeqSetup stops at start and says so, rather than
showing times in UTC without anyone noticing. The API gives times in UTC,
ending in ``Z``.

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
         - "5001:5001"
       environment:
         - MONGODB_URI=mongodb://mongodb:27017
         - MONGODB_DATABASE=seqsetup
         - SEQSETUP_SESSION_SECRET=${SESSION_SECRET}
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

       location / {
           proxy_pass http://localhost:5001;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }

.. important::

   Behind a **TLS-terminating** reverse proxy (HTTPS at the proxy, plain HTTP to
   the app), the app sees ``http`` as its own scheme while browsers send
   ``Origin: https://your-host``. The CSRF Origin check then rejects every
   state-changing request (POST/PUT/PATCH/DELETE) with HTTP 403, and HSTS is not
   emitted. Set ``SEQSETUP_TRUSTED_ORIGINS`` to your public HTTPS origin(s)
   (comma-separated, e.g. ``https://seqsetup.example.com``) so the Origin check
   and security headers work correctly. This is required production config
   alongside ``SEQSETUP_HTTPS_ONLY`` whenever TLS is terminated upstream.

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
zone. If that zone was not UTC, times stored before the update are shown
shifted by the zone's offset from UTC; times stored after it are right.

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
