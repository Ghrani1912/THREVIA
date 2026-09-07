# THREVIA Dashboard

## Setup

```bash
pip install -r requirements.txt
```

Make sure MongoDB is running locally on `mongodb://localhost:27017/` with a
`threvia` database containing the collections: `graph_nodes`, `graph_edges`,
`graph_communities`, `graph_meta`, `stream_alerts`, `bloom_hits`.

For the Network Graph tab, place your exported graph visualization at
`graph_export.html` in this same folder (e.g. output from PyVis / NetworkX).

## Run

```bash
streamlit run app.py
```

The `.streamlit/config.toml` file sets the dark theme automatically — no
extra flags needed. Empty collections show a graceful in-app warning instead
of crashing. Use the "Refresh Data" button in the sidebar to bypass the
30-second cache and pull fresh results immediately.
