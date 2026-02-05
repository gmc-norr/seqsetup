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

   Set up LDAP or Active Directory authentication through the admin
   interface. See :doc:`/admin-guide/authentication`.

3. **Disable default credentials**

   Remove or empty the ``config/users.yaml`` file, or configure LDAP
   without local fallback. See :doc:`configuration`.

4. **Enable LDAP SSL certificate verification**

   In the LDAP settings, enable "Verify SSL Certificate" to prevent
   man-in-the-middle attacks.

5. **Use a reverse proxy**

   Place SeqSetup behind a reverse proxy (nginx, Traefik, etc.) that
   handles:

   - HTTPS termination
   - Rate limiting
   - Access logging

6. **Back up MongoDB regularly**

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
