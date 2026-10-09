# TraceBack

TraceBack is a network investigation workstation with an offline SQLite mode and a hosted PostgreSQL mode for Vercel. Demonstration events are synthetic and labeled as such. Local imports are stored in `traceback.db`; Vercel imports are stored in the connected PostgreSQL database.

## Run

Requires Python 3.11+. From this directory:

```powershell
python server.py
```

Open <http://127.0.0.1:8765>. On first start, the application seeds a synthetic investigation. Use **Import evidence** to upload JSON, JSONL, or CSV. CSV accepts `timestamp`, `src_ip`, `dst_ip`, and optional `src_port`, `dst_port`, `protocol`, `event_type`, `length`, and `severity` headers. JSON can be a list or an object with an `events` list. Files are limited to 10 MB and are parsed as data, never executed. Invalid rows are reported. PCAP/PCAPNG parsing is not available in this dependency-free runtime.

## Data and API

SQLite is created in the project directory. Back it up by copying `traceback.db` while the server is stopped. APIs: `GET /api/overview`, `/api/incidents`, `/api/incidents/{id}`, `/api/incidents/{id}/graph`, `/api/events`, `/api/findings`, `/api/hosts`, `POST /api/upload` (multipart `file`), `POST /api/sample`, and `GET /api/incidents/{id}/report` (HTML). API responses are JSON; static UI is served by the same process. Reports escape all imported text.

## Vercel deployment

Connect this repository to Vercel and attach a hosted PostgreSQL database such as Neon. Set `DATABASE_URL` (or `POSTGRES_URL`) and a long random `TRACEBACK_ACCESS_KEY` in the Vercel project environment, then redeploy. The app requires both variables on Vercel and fails closed if either is missing; the access key protects API reads and writes. Enter the key in the workspace login screen. Production uploads are limited to 4 MB by Vercel's function request limit; local uploads remain capped at 10 MB. The local SQLite database is not migrated or uploaded by deployment.

## Limitations

This compact implementation uses the Python standard library rather than FastAPI, SQLAlchemy, NetworkX, Scapy, React, or Three.js: those dependencies were unavailable locally and npm is configured offline. Correlation and graph analysis are implemented with deterministic Python/SQLite logic. The topology is an interactive SVG with pan/zoom and depth styling rather than WebGL 3D. There is no authentication, RBAC, WebSocket, Alembic migration, incident editing/archival UI, date range filters, or PCAP parser yet; deploy only on a trusted machine and bind to loopback. Uploaded evidence is capped at 10 MB. Events are observations; findings are heuristic interpretations and explicitly include limitations. The interface uses system sans-serif and monospace fonts to remain offline-capable.

## Checks

Run the standard-library tests with `python -m unittest discover -s tests`. Start the application with `python server.py`.
