"""Route all TraceBack API and static requests through the existing handler."""
from server import Handler, init_db

# Serverless instances start with an empty filesystem, so prepare the persistent
# Postgres schema before the first request handled by each warm instance.
init_db()

handler = Handler
