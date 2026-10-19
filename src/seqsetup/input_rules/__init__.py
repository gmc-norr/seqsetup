"""One strict check for every input SeqSetup reads.

Every input goes through the same pipeline: read (with the line and column of
every key, value and list item), adapt the source format, validate against the
input type's rulebook, convert into the domain objects. See
docs/design/2026-10-18-input-rules-design.md.

Nothing in this package starts the app: no repositories, no
``seqsetup.data.instruments`` (which reads the local instruments file at
import) and no ``services.github_sync``. The settings command depends on that.
"""
