# DNSGuard-X web UI

A React + TypeScript frontend (Vite + Recharts) with a small FastAPI backend that
wraps the detection engine. The backend serves the built frontend, so the whole app
runs from **one command**.

```
web/
  server.py          FastAPI backend (API + serves the built frontend)
  requirements.txt   backend dependencies
  frontend/          Vite + React + TypeScript app
    src/
      App.tsx         page layout and data flow
      api.ts          calls to /api/*
      theme.ts        light/dark theme + chart palettes
      components/     metrics, charts, tables, error boundary
    dist/            production build (created by `npm run build`)
```

Themes: **orange on white** (day) and **cyan-green on black** (night); toggle with the
sun/moon button, choice is remembered.

## Run it (already built)

The frontend is already built into `frontend/dist`, so you only need the backend:

```bash
pip install -r web/requirements.txt          # once
python web/server.py
```

Then open **http://localhost:8000** and click *Run the sample capture*, or drag in your
own `.pcap` file.

> On Windows, if `python` is not found, use the full path, e.g.
> `C:\Users\<you>\AppData\Local\Programs\Python\Python314\python.exe web/server.py`

## Rebuild the frontend (only if you change the UI)

```bash
cd web/frontend
npm install          # once
npm run build        # writes frontend/dist, which server.py serves
```

## Develop the frontend with hot-reload (optional)

Run the backend and the Vite dev server in two terminals:

```bash
python web/server.py                 # terminal 1 (API on :8000)
cd web/frontend && npm run dev       # terminal 2 (UI on :5173)
```

Open http://localhost:5173. In dev mode the app calls the API on port 8000 (CORS is
already allowed).

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | liveness check |
| GET | `/api/sample` | analyse the bundled `data/pcaps/mixed.pcap` |
| POST | `/api/analyze` | analyse an uploaded `.pcap` (multipart `file`) |
| GET | `/api/runs` | list runs stored in `dnsguard.db` |
| GET | `/api/runs/{id}` | warnings + stats for one stored run |
