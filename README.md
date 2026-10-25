# AIRGUARD — wireless intrusion detection prototype

AIRGUARD is a passive Wi-Fi intrusion detection system (WIDS). It uses a Random Forest model trained on a small, prepared subset of AWID3 to recognize traffic patterns that look like deauthentication flooding. It reports and logs suspicious activity; it does not block devices or transmit Wi-Fi frames.

## Start the local web dashboard

On Windows, double-click `run_dashboard.bat`. On the first run it installs the Python packages in `requirements.txt`, starts the dashboard, and opens your browser at `http://127.0.0.1:8765`.

Or, in PowerShell:

```powershell
cd "C:\Users\fatma\Documents\intrusion-detection-system"
python -m pip install -r requirements.txt
python dashboard.py
```

The web server listens only on your own computer (`127.0.0.1`). Keep the terminal window open while using the dashboard. Press **Ctrl+C** in that window to stop it. If port 8765 is busy, run `python dashboard.py --port 8766` and open the URL printed in the terminal.

## Dashboard tour

- **Overview:** accuracy, precision, recall and F1; a confusion matrix; influential features; and a button to replay held-out AWID3 examples.
- **How it works:** a picture and plain-English steps showing frames → feature window → Random Forest → alert.
- **Alert history:** saved detections, their time, source, attack probability and threshold.
- **Model & results:** what the classifier learned, the ten input features, the data split, and limits of the evaluation.
- **Live monitor:** an optional receive-only capture form for a supported monitor-mode adapter. Provide the adapter interface name and a listening duration. The adapter/driver must expose 802.11 monitor frames to Scapy; many built-in Windows adapters cannot. Only observe a network you own or are authorized to test. No attack traffic is generated.

The overview's sample replay is offline and safe: it scores two held-out AWID3 windows without using a radio. It appends any detection to `alerts.jsonl`; the alert-history view refreshes automatically. During live capture, each score uses 100 frames and is recalculated after 50 more frames. The first alert can only be assessed after enough frames arrive.

## What the model checks

Each frame window is summarized into ten values: average normalized frame length; average and variation in signal strength (RSSI); management-frame fraction; deauthentication count per 100 frames; largest deauthentication count in any 10-frame run; retry fraction; protected-frame fraction; number of distinct subtypes; and frame-type entropy.

The class-balanced scikit-learn Random Forest estimates the chance that a window contains deauthentication activity. A threshold is selected using validation data. When the probability reaches that threshold, AIRGUARD raises a deauthentication alert and records it locally. It does not identify an attacker with certainty or automatically prevent the traffic.

## AWID3 prototype results

Results come from a chronological held-out tail of 455 windows from one prepared AWID3 capture. Accuracy is **97.1%**, precision **100.0%**, recall **94.8%**, and F1 **97.3%**. The confusion matrix (actual rows; predicted columns, normal then attack) is:

```
                 predicted normal   predicted attack
actual normal           207                 0
actual attack             13               235
```

The 13 missed attacks matter: the model is not perfect. These scores are a small prototype benchmark, not a promise about other networks. The source data has no timestamps, so the deauthentication rate is per 100 frames, not per second. Live RSSI and frame-length scaling may need adapter-specific calibration.

## Project files

- `dashboard.py` and `dashboard.html`: localhost server and multi-view browser UI
- `wids.py`: model training, offline replay, alert logging, and optional receive-only capture
- `awid3_deauth_windows.csv`: compact engineered feature subset from AWID3
- `wids_model.joblib` and `metrics.json`: trained classifier and evaluation results
- `WIDS_A1_Poster_AWID3.pptx`: A1 landscape project poster
- `WIDS_AWID3_Submission.zip`: portable source-and-poster bundle
- `prepare_awid3_subset.py`: reproducible data preparation from the cited archive
- `GITHUB_PUBLISH.md`: GitHub setup and publishing notes

## AI use

Codex helped polish the code and presentation. The author should be able to explain the feature extraction, Random Forest, alert threshold, test split and limitations.

## Data source

The prepared subset comes from the preprocessed AWID3 deauthentication record [Zenodo record 17406710](https://zenodo.org/records/17406710), released under CC BY 4.0. The small engineered-feature CSV is included; the large source archive is not. See the poster and `prepare_awid3_subset.py` for details.

## Publish this working folder to GitHub

This folder already has a local Git commit and an `origin` remote configured. After editing files, run:

```powershell
cd "C:\Users\fatma\Documents\intrusion-detection-system"
git add dashboard.py dashboard.html README.md GITHUB_PUBLISH.md run_dashboard.bat WIDS_AWID3_Submission.zip .gitignore
git commit -m "Update AIRGUARD localhost dashboard"
git push -u origin main
```

Do not add private captures, passwords or API keys. `alerts.jsonl`, capture files and Python cache are ignored by Git.
