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
the application and MongoDB. There are two environment files to copy and fill
in: ``.env`` for the application (``docker compose`` refuses to start while a
required value is missing, ``SEQSETUP_HTTPS_ONLY`` among them -- see
:ref:`port-and-https`) and ``.env.db`` for the MongoDB root password, which
only the database container reads.

.. code-block:: bash

   # Your settings (once), then fill both in
   cp .env.example .env
   cp .env.db.example .env.db

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
the application on port 5001. It installs the default Pixi environment only,
so the test, browser and docs tools (pytest, pytest-playwright, mongomock,
httpx2, sphinx, furo) are not in it.

Both base images are pinned by digest, not by a moving tag: the ``Dockerfile``
builds on ``ghcr.io/prefix-dev/pixi`` at the version that writes
``pixi.lock``, and ``docker-compose.yml`` runs a fixed ``mongo:7`` build. Two
builds of one commit therefore give the same image. To bump either,
``docker buildx imagetools inspect <image>:<tag>`` prints the new digest; put
the tag and the digest in the file together.

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

The shipped Compose file is the production one
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the ``docker-compose.yml`` in the repository as it is. Do not write a
second Compose file for production: this one is where the protections live,
and a copy of it drifts.

It runs ``mongod --auth`` with a root user that MongoDB creates on first
start, creates a separate least-privileged application user through
``docker/mongo-init.sh``, publishes the application port on ``127.0.0.1``
only, pins the MongoDB image by digest, waits for the database to report
healthy, drops every Linux capability from the application container and
blocks setuid escalation in it. MongoDB gets no ``ports:`` entry at all --
and note that an *unpublished* container port is still reachable from the
Docker host, so running MongoDB without authentication would let any local
account on the server read the database, or change a Ready run's stored
sample sheet, with no password.

Fill in the two environment files and start it:

.. code-block:: bash

   cp .env.example .env          # application settings and the app DB user
   cp .env.db.example .env.db    # the MongoDB root credential, mongod only
   chmod 600 .env .env.db        # both hold passwords: yours alone

   # The containers read these as users of their own; on a server whose
   # umask keeps other users out, make them readable (see Installation).
   chmod o+r docker/mongo-init.sh
   chmod -R o+rX config

   # A session signing key, and passwords the URI and the env-file parser
   # both leave alone. Generate hex and nothing else -- see the comments in
   # the two files.
   openssl rand -hex 32          # -> SEQSETUP_SESSION_SECRET in .env
   openssl rand -hex 24          # -> MONGO_APP_PASSWORD in .env
   openssl rand -hex 24          # -> MONGO_INITDB_ROOT_PASSWORD in .env.db
                                 #    FIRST INSTALL ONLY: see "Upgrading an
                                 #    existing deployment" below

   docker compose up -d

The root credential is in its own file because the application container
reads the whole of ``.env``, and the application never needs it.

For anything site-specific -- another published address, an extra volume, a
different log driver -- add a ``docker-compose.override.yml`` next to it.
Compose reads it automatically and merges it over the base file, so you keep
the protections above and still see, in one small file, exactly what your
site changed.

.. warning::
   Never remove authentication from ``docker-compose.yml``. If you need a
   throwaway local run without it, put that in
   ``docker-compose.override.yml`` on that machine and nowhere near a
   machine holding real runs.

Upgrading an existing deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The MongoDB root credential moved out of ``.env`` into its own ``.env.db``.
If you already run SeqSetup, do these three things before ``docker compose
up``. Your database keeps working either way, which is exactly why none of
them reports itself.

1. **Put the root password you already have into ``.env.db``** -- do not
   generate a new one.

   .. code-block:: bash

      cp .env.db.example .env.db
      # MONGO_INITDB_ROOT_USERNAME = your old MONGO_ROOT_USER
      # MONGO_INITDB_ROOT_PASSWORD = your old MONGO_ROOT_PASSWORD

   ``MONGO_INITDB_ROOT_*`` is read only by MongoDB's own first-start step,
   which never runs again once the data volume exists. A fresh password there
   is **silently ignored**: the database keeps the old one, and your
   ``.env.db`` then records a password that does not work. Use the old names'
   values, under the new names -- writing the *old* names into ``.env.db``
   leaves mongod with no root user at all.

2. **Delete ``MONGO_ROOT_USER`` and ``MONGO_ROOT_PASSWORD`` from your
   ``.env``.** The application container reads the whole of ``.env`` and never
   needs them. ``docker-compose.yml`` names them empty on the application
   service so an ``.env`` written before this change cannot hand them over,
   but the lines are dead weight in a secret file -- remove them.

3. **Check that the database still signs you in.** The database container's
   health check now signs in as the *application* user instead of pinging:

   .. code-block:: bash

      docker compose up -d
      docker compose ps          # mongodb must say (healthy)

   If it says ``unhealthy``, the application will not start -- on purpose.
   Look at ``docker compose logs mongodb`` for a line from
   ``mongo-init.sh``. Before, this state came up *healthy* and the
   application answered "Authentication failed" for ever.

.. note::
   If you ever worked around the old ``authSource=admin`` setting by creating
   the application user in the ``admin`` database, that user is no longer
   found: ``docker-compose.yml`` now authenticates against ``seqsetup``,
   where ``docker/mongo-init.sh`` creates it. Recreate it there:

   .. code-block:: bash

      docker compose exec mongodb mongosh --username <root> --password \
        --authenticationDatabase admin --eval \
        'db.getSiblingDB("seqsetup").createUser({user: "seqsetup_app", pwd: passwordPrompt(), roles: [{role: "readWrite", db: "seqsetup"}]})'

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

7. **Back up MongoDB regularly, the whole database**

   Set up automated backups of the MongoDB data volume or use MongoDB
   Atlas with automated backups.

   A Ready run's five export files -- both Sample Sheets, the JSON, and
   the check report as JSON and as a PDF -- are stored in their own
   collection, ``run_exports``, one record per file; the run document
   names them with their lengths and SHA-256 hashes. A backup or a restore
   that leaves that collection out keeps the runs and loses their files:
   every download and every API call for such a run then answers ``500``
   with a message naming the file, which is deliberate -- SeqSetup serves
   exactly the bytes a run's checks passed, or nothing (see
   :ref:`export-file-damaged`). Back up and restore ``runs`` and
   ``run_exports`` together.

   **Never prune ``run_exports``.** Records of a Mark Ready that failed
   part way, and of a deleted run's kept copy, look unreferenced: they are
   not. SeqSetup itself only ever inserts into this collection -- it never
   updates or deletes a record -- so a file a run names is the file that
   was checked. Removing one by hand makes that run refuse to serve
   rather than serve something else.

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
       proxy_set_header X-Forwarded-For $remote_addr;
       proxy_set_header X-Forwarded-Proto $scheme;

       # SeqSetup caps each request body itself: 2 MB, and 21 MB only where
       # samples are added from a file (nginx's own default is 1 MB).
       client_max_body_size 2m;

       # Mark Ready answers only once it has drawn the check report: about
       # two minutes for 96 samples on all 8 lanes of a NovaSeq X 10B, and
       # longer when two people mark large runs Ready at once. nginx's own
       # default is 60 s; past it the page shows an error while the run
       # still turns Ready.
       proxy_read_timeout 600s;

       location / {
           proxy_pass http://127.0.0.1:5001;
       }

       location ~ ^/runs/[^/]+/samples/(preview|bulk)$ {
           client_max_body_size 21m;
           proxy_pass http://127.0.0.1:5001;
       }
   }

``X-Forwarded-For`` is set to ``$remote_addr`` -- the address the proxy
itself is talking to -- and **not** to nginx's ``$proxy_add_x_forwarded_for``,
which appends to whatever the client sent. SeqSetup gives each client its own
sign-in limit by reading the first hop of that header, so a header the client
can write means a client that can choose which limit it spends: a new value
each time buys unlimited attempts, and someone else's value spends theirs. If
your proxy is itself behind another proxy, keep the real client's address in
the first position, and never let a value the client sent reach it.

Then turn on the variable that makes SeqSetup read it, so each user is
counted separately instead of every user behind the proxy sharing the
proxy's own address:

.. code-block:: bash

   SEQSETUP_TRUST_FORWARDED_FOR=1   # only behind a proxy that REPLACES the header

The Docker Compose recipe sets this to ``1`` already. Turn it off
(``SEQSETUP_TRUST_FORWARDED_FOR=0`` in ``.env``) if SeqSetup is ever reached
directly, without the proxy in front of it: then the header is whatever the
client typed, and the direct TCP address is the only honest identity.
SeqSetup keeps at most the first 64 characters of the address it reads
from the header (a real address has 45 at most), so a forged, overlong
value cannot fill its memory.

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

   SEQSETUP_LIMS_ALLOW_HTTP=1                 # LIMS speaks plain HTTP (sends api-key in clear)
   SEQSETUP_LIMS_ALLOWED_NETS=10.0.0.0/8      # the networks the LIMS may be on

Leave both unset in production unless the LIMS really is on a private
network.

``SEQSETUP_LIMS_ALLOWED_NETS`` is a comma-separated list of networks in CIDR
form, for example ``10.0.0.0/8, 192.168.10.0/24``. After DNS resolution, an
address is allowed when it is public — as always — or when it lies inside one
of the listed networks. List only the network the LIMS is actually on: a wide
entry opens every host on it to a LIMS URL an admin can type.

Four kinds of address stay refused however they are listed: **link-local**
(``169.254.0.0/16``, ``fe80::/10`` — where a cloud host's instance metadata
service lives), **multicast**, **unspecified** and **reserved**. A list that
is not valid CIDR, or that names a network reaching into one of those ranges
at all (``169.0.0.0/8`` does), stops SeqSetup at start with a message naming
the entry. Loopback (``127.0.0.1/32``) is not in that group: it is refused
unless listed, and listing it is how a dev setup reaches a mock LIMS on the
same host. IPv6 loopback is listed as ``::1/128``, which a host whose
``localhost`` resolves to ``::1`` needs (Fedora/RHEL and macOS defaults, and
many container images); list it alongside the IPv4 one,
``SEQSETUP_LIMS_ALLOWED_NETS=127.0.0.1/32,::1/128``. It is allowed even
though it lies inside the reserved ``::/8`` -- a network wholly inside
loopback is an entry for loopback and nothing else -- while ``::/8`` itself
stays refused.

.. important::

   ``SEQSETUP_LIMS_ALLOW_PRIVATE_NETS`` has been **removed**. It allowed every
   private address at once, link-local included, so a LIMS URL could be
   pointed at ``http://169.254.169.254/`` and read the host's own cloud
   credentials. SeqSetup refuses to start while that variable is set at all,
   with a message naming ``SEQSETUP_LIMS_ALLOWED_NETS``: replace it with the
   list of networks the LIMS is on, and unset the old name (remove it from
   ``.env`` too).

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
- Permission denied on config volume, or Admin > Instruments says the local
  configuration file was not read: the application container runs as a user
  of its own, so ``config/`` must be readable by other users -- see
  :doc:`installation`

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
