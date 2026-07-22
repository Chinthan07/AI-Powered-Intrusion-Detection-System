# IntelliGuard IDS

AI-powered Intrusion Detection System using a Random Forest classifier trained on CICIDS2018, combined with a rule-based Hybrid Decision Engine evaluating behavioural flow characteristics. Supports real-time detection (Scapy), offline traffic analysis, and CSV/PDF reporting via a Streamlit dashboard.

## Overview

IntelliGuard IDS is a flow-based network intrusion detection system that classifies network traffic as **Benign** or **Malicious**. Rather than relying on traditional signature matching, it uses a Random Forest classifier trained on the CICIDS2018 benchmark dataset to learn statistical patterns from network flow behaviour, paired with a hybrid rule-based layer to improve detection reliability. The system supports both continuous live monitoring and offline analysis of previously captured traffic, all accessible through a single interactive web interface.

<p align="center"> <img src="images/Home_Page.png" width="50%" style="margin:0;padding:0;"><img src="images/training.png" width="50%" style="margin:0;padding:0;"> </p> <p align="center"> <img src="images/Live_Detection.png" width="50%" style="margin:0;padding:0;"><img src="images/Offline_Detection.png" width="50%" style="margin:0;padding:0;"> </p>

## Key Features

- **Real-time intrusion detection** — captures live network traffic via Scapy and classifies flows as they occur
- **Offline detection & analytics** — upload CSV/Parquet flow datasets for historical or forensic analysis
- **Hybrid Decision Engine** — combines Random Forest confidence scores with behavioural heuristic rules (port, packet volume, packet imbalance, timing) for more reliable classification
- **Interactive analytics dashboards** — visualizes traffic distributions, protocol statistics, and detection results
- **Model training module** — trains and evaluates the Random Forest classifier directly from the CICIDS2018 dataset, with accuracy, precision, recall, F1-score, and confusion matrix output
- **Reporting** — exports detection results as downloadable CSV files and PDF reports
- **Streamlit-based web interface** — no command-line interaction required

## How It Works

1. **Feature Extraction** — Live packets are captured via Scapy and grouped into bidirectional flows by the FlowTracker module; offline data is read directly from uploaded CSV/Parquet files. Both produce the same 21 flow-based features (e.g. flow duration, packet counts, inter-arrival times, port, protocol).
2. **Feature Scaling** — Raw feature values are normalized using a StandardScaler fitted during training, ensuring new data is scaled consistently with what the model learned.
3. **Model Prediction** — The scaled features are passed to a trained Random Forest classifier, which outputs a probability/confidence score for the flow being malicious.
4. **Hybrid Decision Engine** — If the model's confidence is high enough, its prediction is accepted directly. Otherwise, the engine evaluates behavioural heuristic rules on the raw flow data; if enough rules are triggered, the flow is still flagged as malicious.
5. **Output & Reporting** — The final classification, along with the confidence score, is displayed on the dashboard and can be exported as CSV or PDF for further analysis.
