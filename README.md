# AWID3 passive WIDS prototype

A working, receive-only wireless intrusion detection prototype. It trains a class-balanced scikit-learn Random Forest on real, preprocessed AWID3 deauthentication windows, tunes its alert threshold on validation data, evaluates a chronological held-out tail, and logs deauthentication alerts during safe offline replay or optional authorized monitor-mode capture.

This is a **WIDS**, not a WIPS: it observes and logs only. It never transmits management frames or blocks devices.

## Files

- `wids.py`: training, evaluation, held-out AWID3 replay, passive Scapy capture, and JSONL alert logging
- `dashboard.py`: local desktop dashboard for metrics, confusion matrix, feature importance and safe replay
- `awid3_deauth_windows.csv`: compact 2,279-window feature subset derived from AWID3
- `prepare_awid3_subset.py`: reproducibly extract the subset from the cited, checksum-verified archive
- `wids_model.joblib`: trained model and validation-selected threshold
- `metrics.json`: saved evaluation and feature-importance results
- `WIDS_A1_Poster_AWID3.pptx`: single-slide A1 landscape poster
- `requirements.txt`: Python dependencies

Earlier synthetic-only files may remain in the output folder from the first prototype pass (`lab_windows.csv`, `generate_demo_data.py`, and `WIDS_A1_Poster.pptx`). They are superseded; use the AWID3 files listed above. The AWID3 submission ZIP excludes those older files.

## Run the desktop dashboard

Python 3.10+ is recommended. Extract `WIDS_AWID3_Submission.zip`, open a terminal in the extracted folder, then run:

```powershell
python -m pip install -r requirements.txt
python dashboard.py
```

A desktop window opens with a left sidebar and separate tools: **Overview** (metrics and confusion matrix), **Offline replay** (run the held-out examples), **Alert history** (browse logged detections in a separate window), and **Model & data** (features and limitations). Replay is offline and sends no Wi-Fi traffic. Close the window to stop it. On Windows, double-click `run_dashboard.bat`; it installs the listed Python packages if needed, then opens the dashboard. Or use the PowerShell commands above.

For command-line use, run `python wids.py train` to retrain and refresh the metrics, then `python wids.py replay` for the safe offline example. The included model and metrics already let you start with the dashboard.

## Optional receive-only capture

Use only an adapter in monitor mode on a network and channel you are authorized to observe. The capture command listens and prints/logs a score for each 100-frame window after each 50 new frames:

```powershell
python wids.py capture --interface wlan0mon --seconds 60
```

Use the interface name for your system. Capture requires a monitor-mode capable Wi-Fi adapter, OS capture permissions, and Scapy. Some Windows adapters do not expose monitor-mode frames to Scapy. The capture path uses RadioTap RSSI where available. It has adjustable scaling defaults (`--rssi-min`, `--rssi-max`, `--max-frame-bytes`); calibrate these for the adapter before interpreting live scores. The reported metrics below are from AWID3 offline evaluation, not from live radio capture.

No attack-generation tool is included. For the demonstration, use offline replay. Any future radio testing must be confined to an approved isolated lab.

## Model and features

The estimator is a Random Forest with `class_weight="balanced_subsample"`, reflecting the imbalance-aware Random Forest approach in the related insider-threat project. It produces a deauthentication probability. A threshold is selected for F1 on a validation segment, then the model is refit on the full training segment. The test data is held aside until final scoring.

Each observation describes a 100-frame window; the source blocks advance by 50 rows. Ten features are calculated:

- mean normalized frame length and mean/standard deviation of normalized signal strength
- management-frame fraction
- deauthentication-subtype count per 100 frames and the largest count in any rolling 10-frame span
- retry and protected-frame fractions
- number of distinct subtypes and frame-type entropy

The prepared source encodes frame type as 0, 0.5, or 1, and the deauthentication subtype as 12/14 = 0.8571. The extractor converts these to named features. The rate feature is a count per 100 captured frames; the preprocessed data has no timestamps, so it cannot support a frames-per-second claim.

## AWID3 evaluation

The included evaluation uses 2,279 windows from the deauthentication-class preprocessed AWID3 file: 1,037 normal-only and 1,242 attack-containing windows. It splits each contiguous class run chronologically into fitting, validation, and held-out test portions, leaving two windows at each split boundary because source windows overlap by 50 frames. This gives both classes in each segment. The test segment contains 455 windows.

- Accuracy: **97.1%**
- Precision: **100.0%**
- Recall: **94.8%**
- F1: **97.3%**
- Validation-selected threshold: **0.983**

Confusion matrix (actual rows, predicted columns; normal, deauthentication):

```
                 predicted normal   predicted attack
actual normal           207                 0
actual attack             13               235
```

These are results from a chronological tail of one preprocessed AWID3 capture file. The windows do not share packet rows across split boundaries, but the test is not an independent site or adapter. They should be presented as a small prototype benchmark, not field accuracy. The single-file data order and adapter-specific RSSI calibration are important limitations.

## Rebuild the compact subset

Download the preprocessed archive from the cited Zenodo record. The script checks the archive MD5 before it reads the pickle. Pickle files can execute code when loaded, so use only the exact archive at that record, with the expected checksum:

```powershell
python prepare_awid3_subset.py --archive C:\path\to\awid3_preprocessed.zip
python wids.py train
```

Expected MD5: `0b29e1afa48100e65003da3df3780eb1`.

## Ten-minute demonstration

1. **0:00–1:00** — Start `python dashboard.py` and introduce passive monitoring and the normal/attack labels.
2. **1:00–3:00** — Show the dashboard metrics; explain the ten features, balanced Random Forest, chronological split, and validation threshold.
3. **3:00–5:00** — Click **Replay held-out windows**; point out the AWID3 window, deauthentication score, threshold, and JSONL alert.
4. **5:00–7:00** — Explain the confusion matrix: 235 detected attacks, 13 missed attacks, no false alerts in this test slice.
5. **7:00–9:00** — Walk through `capture` as optional receive-only mode and explain adapter calibration and authorization.
6. **9:00–10:00** — Discuss improvements: test on independent AWID3 capture sessions and hardware, calibrate RSSI, add time-based rates and alert persistence, and evaluate false positives across more benign environments.

Record the live demonstration during the week after submission, as required by the brief.

## Publish the code to GitHub

Create an empty repository on GitHub (do not initialize it with a README or license). Then open PowerShell in this `outputs` folder and run the commands below. Replace `YOUR-USERNAME` and `YOUR-REPOSITORY` with your GitHub account and repository name. Git will prompt you to authenticate through your configured credential manager or browser.

```powershell
git init -b main
git add README.md GITHUB_PUBLISH.md .gitignore dashboard.py run_dashboard.bat wids.py awid3_deauth_windows.csv wids_model.joblib metrics.json requirements.txt prepare_awid3_subset.py WIDS_A1_Poster_AWID3.pptx
git commit -m "Add AWID3 wireless intrusion detection prototype"
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

To publish later edits, run `git add .`, `git commit -m "Describe your update"`, then `git push`. Keep `alerts.jsonl` out of Git because it is a generated runtime log. Never commit passwords, API keys, or private captures.

## AI use

OpenAI Codex helped polish the Python code, process the AWID3 subset, calculate the evaluation, and draft the poster. The author should be ready to explain feature extraction, the Random Forest, threshold selection, the split, and the limits of the result.

## Data and citations

The compact CSV is derived from the preprocessed AWID3 record [Zenodo 17406710](https://zenodo.org/records/17406710), released under CC BY 4.0. The accompanying study describes the windowed feature preparation: Şolpan et al., [“A Hybrid Feature Fusion Approach for Multiclass Wi-Fi Intrusion Detection Using Classical Machine Learning”](https://link.springer.com/article/10.1007/s10207-026-01224-2). The raw archive is not redistributed here; the small engineered feature subset is included for reproducible training.




