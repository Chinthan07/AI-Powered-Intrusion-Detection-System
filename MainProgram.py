import streamlit as st
import pandas as pd
import numpy as np
import os
import csv
import time
import pickle
from datetime import datetime
import glob
import base64
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from fpdf import FPDF
import tempfile
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

#Model Metrics used
from sklearn.metrics import (
    recall_score,
    precision_score,
    f1_score,
    balanced_accuracy_score,
    accuracy_score,
    confusion_matrix,
    roc_auc_score
)


st.set_page_config(page_title="IntelliGuard IDS", layout="wide", page_icon=":shield:")

SELECTED_COLUMNS = [
    'Dst Port',
    'Protocol',
    'Flow Duration',
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'TotLen Fwd Pkts',
    'TotLen Bwd Pkts',
    'Fwd Pkt Len Max',
    'Fwd Pkt Len Min',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Label'
]

DATASET_DIR = r"D:\MSIS Imp Files\AI - IDS\Files\Nov-Dec-Jan-Feb\Development\Datasets\PARAQUET"
CAPTURE_DIR = r"D:\MSIS Imp Files\AI - IDS\Files\Nov-Dec-Jan-Feb\Development\captured_data"
os.makedirs(CAPTURE_DIR, exist_ok=True)


# ================= DOWNLOAD LINKS (README, Links) =================
def download_link(file_path, link_text):
    if not os.path.exists(file_path):
        return f"❌ {file_path} not found"

    with open(file_path, "rb") as f:
        data = f.read()

    b64 = base64.b64encode(data).decode()
    filename = os.path.basename(file_path)

    return f'''
    <a href="data:application/octet-stream;base64,{b64}" download="{filename}">
        {link_text}
    </a>
    '''

# ================== FLOW TRACKER CLASS =================
class FlowTracker:
    """A stateful class to track network flows and calculate features."""
    
#===========Creation of Class Object===========
    
    def __init__(self, output_csv_path, feature_names, timeout=30, ui_callback=None):
        self.active_flows = {}
        self.flow_timeout = timeout
        self.output_csv_path = output_csv_path
        self.feature_names = feature_names
        self.ui_callback = ui_callback 
        self._initialize_csv()

#==========CSV Initialization===========

    def _initialize_csv(self):
        if not os.path.exists(self.output_csv_path) or os.path.getsize(self.output_csv_path) == 0:
            with open(self.output_csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(self.feature_names[:-1] + ["Label"])

#========== Core to Flow Track ===========

    def _get_flow_key(self, packet):
        """Creates a unique, direction-agnostic key for a flow."""

        if IP not in packet:
            return None, None

        proto = packet[IP].proto

        # TCP / UDP 
        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport

        # ICMP
        elif ICMP in packet:
            sport = packet[ICMP].type
            dport = packet[ICMP].code

        else:
            return None, None

        key = tuple(sorted((packet[IP].src, packet[IP].dst))) + \
            tuple(sorted((sport, dport))) + \
            (proto,)

        original_source = (packet[IP].src, sport)
        return key, original_source

#========== Process Each Packet ===========

    def process_packet(self, packet):
        """Accepts a packet and updates its corresponding flow."""
        flow_key, original_source = self._get_flow_key(packet)
        if not flow_key:
            return

        current_time = packet.time
        flow = self.active_flows.get(flow_key)

        if flow is None:
            flow = defaultdict(list)
            flow['start_time'] = current_time
            flow['last_seen'] = current_time
            flow['original_source'] = original_source
            self.active_flows[flow_key] = flow

        flow['packets'].append(packet)
        flow['last_seen'] = current_time
        
        if TCP in packet and (packet[TCP].flags.F or packet[TCP].flags.R):
            self._finish_flow(flow_key)
        
        for key, flow in list(self.active_flows.items()):
            if current_time - flow['last_seen'] > self.flow_timeout:
                self._finish_flow(key)
                
        print(packet.summary())

#========= Check for Flow Timeouts ===========
    def finish_all_flows(self):
        """Method to force-finalize all remaining active flows."""
        for key in list(self.active_flows.keys()):
            self._finish_flow(key)

    def _finish_flow(self, flow_key):
        if flow_key not in self.active_flows:
            return

        flow_data = self.active_flows.pop(flow_key)
        packets = flow_data['packets']
        if len(packets) < 1:
            return

        feature_vector = defaultdict(float)
        first_pkt = packets[0]
        if TCP in first_pkt or UDP in first_pkt:
            feature_vector["Dst Port"] = int(first_pkt.dport)
        elif ICMP in first_pkt:
            feature_vector["Dst Port"] = int(first_pkt[ICMP].type)
        else:
            feature_vector["Dst Port"] = 0

        feature_vector["Protocol"] = int(first_pkt[IP].proto)


        #==================FLOW DURATION==================
        duration_sec = flow_data['last_seen'] - flow_data['start_time']
        duration_sec = max(duration_sec, 1e-6)
        feature_vector['Flow Duration'] = duration_sec * 1_000_000  # microseconds

        #===============FORWARD / BACKWARD PACKETS (TCP, UDP, ICMP)=========
        def get_src_id(pkt):
            if TCP in pkt or UDP in pkt:
                return (pkt[IP].src, pkt.sport)
            elif ICMP in pkt:
                return (pkt[IP].src, pkt[ICMP].type)
            else:
                return (pkt[IP].src, 0)

        fwd_packets = [p for p in packets
                        if get_src_id(p) == flow_data['original_source']
                    ]

        bwd_packets = [p for p in packets
                        if get_src_id(p) != flow_data['original_source']
                    ]


        feature_vector['Tot Fwd Pkts'] = len(fwd_packets)
        feature_vector['Tot Bwd Pkts'] = len(bwd_packets)

    # ================ PACKET LENGTH FEATURES =================
        fwd_pkt_lengths = [len(p) for p in fwd_packets]
        bwd_pkt_lengths = [len(p) for p in bwd_packets]

        feature_vector['TotLen Fwd Pkts'] = sum(fwd_pkt_lengths)
        feature_vector['TotLen Bwd Pkts'] = sum(bwd_pkt_lengths)

        if fwd_pkt_lengths:
            feature_vector['Fwd Pkt Len Max'] = np.max(fwd_pkt_lengths)
            feature_vector['Fwd Pkt Len Min'] = np.min(fwd_pkt_lengths)

    # =======================FLOW IAT=================
        flow_iat = [(packets[i+1].time - packets[i].time) * 1_000_000
        for i in range(len(packets) - 1)]

        if flow_iat:
            feature_vector['Flow IAT Mean'] = np.mean(flow_iat)
            feature_vector['Flow IAT Std']  = np.std(flow_iat)
            feature_vector['Flow IAT Max']  = np.max(flow_iat)
            feature_vector['Flow IAT Min']  = np.min(flow_iat)

    # ===========================FWD IAT====================================
        fwd_iat = [(fwd_packets[i+1].time - fwd_packets[i].time) * 1_000_000
               for i in range(len(fwd_packets) - 1)]

        if fwd_iat:
            feature_vector['Fwd IAT Mean'] = np.mean(fwd_iat)
            feature_vector['Fwd IAT Std']  = np.std(fwd_iat)
            feature_vector['Fwd IAT Max']  = np.max(fwd_iat)
            feature_vector['Fwd IAT Min']  = np.min(fwd_iat)

    #===========================BWD IAT==============================
        bwd_iat = [(bwd_packets[i+1].time - bwd_packets[i].time) * 1_000_000
               for i in range(len(bwd_packets) - 1)]

        if bwd_iat:
            feature_vector['Bwd IAT Mean'] = np.mean(bwd_iat)
            feature_vector['Bwd IAT Std']  = np.std(bwd_iat)
            feature_vector['Bwd IAT Max']  = np.max(bwd_iat)
            feature_vector['Bwd IAT Min']  = np.min(bwd_iat)

    # ==========================STREAMLIT CALLBACK (Updation in UI)======================
        if self.ui_callback:
            self.ui_callback(feature_vector)

#======================== Save flow data with predictions =========================
@st.cache_data(show_spinner=False)
def load_data():
    files = (
        glob.glob(os.path.join(DATASET_DIR, "*.parquet")) +
        glob.glob(os.path.join(DATASET_DIR, "*.snappy.parquet")) +
        glob.glob(os.path.join(DATASET_DIR, "*.pq"))
    )

    if not files:
        st.error("No Parquet datasets found in PARAQUET folder")
        st.stop()

    df_final = None

    for f in files:
        df = pd.read_parquet(
            f,
            columns=SELECTED_COLUMNS,
            engine="pyarrow"
        )

        for col in df.columns:
            if col != "Label":
                df[col] = df[col].astype("float32")

        if df_final is None:
            df_final = df
        else:
            df_final = pd.concat([df_final, df], ignore_index=True)

        del df

    df_final = df_final.dropna()

    # ---- Remove duplicate / near-duplicate flows (BEFORE any row cap) ----
    # CICFlowMeter-style datasets contain large numbers of exact-duplicate
    # flow records (repeated attack tool runs, repeated benign sessions).
    # Deduplicating on the FULL dataset first (rather than after an early
    # proportional cap) ensures we don't throw away unique Malicious rows
    # before we even know how many we truly have available.
    before = len(df_final)
    df_final = df_final.drop_duplicates()
    removed = before - len(df_final)
    if removed > 0:
        print(f"[load_data] Removed {removed} duplicate flow rows "
              f"({removed / before * 100:.2f}% of dataset) to prevent train/test leakage.")

    # ---- Build the largest possible dataset at a ~60:40 (Benign:Malicious) ----
    # ratio, capped at MAX_ROWS. We size both classes off the TRUE unique
    # counts (post-dedup) so we use as much real data as is available,
    # rather than under-using Malicious rows that a naive proportional
    # cap would have discarded earlier.
    MAX_ROWS = 10000000
    TARGET_BENIGN_RATIO = 0.60  # Benign:Malicious ~= 60:40

    counts = df_final['Label'].value_counts()
    if 'Benign' in counts and 'Malicious' in counts:
        n_benign_avail = counts['Benign']
        n_malicious_avail = counts['Malicious']

        # Largest total achievable at the target ratio WITHOUT duplicating
        # any row (duplicating rows here would reintroduce leakage risk).
        max_total_from_benign = n_benign_avail / TARGET_BENIGN_RATIO
        max_total_from_malicious = n_malicious_avail / (1 - TARGET_BENIGN_RATIO)
        achievable_total = min(max_total_from_benign, max_total_from_malicious, MAX_ROWS)

        target_benign = int(achievable_total * TARGET_BENIGN_RATIO)
        target_malicious = int(achievable_total * (1 - TARGET_BENIGN_RATIO))

        benign_rows = df_final[df_final['Label'] == 'Benign'].sample(
            n=min(target_benign, n_benign_avail), random_state=42
        )
        malicious_rows = df_final[df_final['Label'] == 'Malicious'].sample(
            n=min(target_malicious, n_malicious_avail), random_state=42
        )

        df_final = pd.concat([benign_rows, malicious_rows], ignore_index=True)
        df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

        print(f"[load_data] Built dataset at ~60:40 ratio: "
              f"Benign={len(benign_rows)}, Malicious={len(malicious_rows)}, "
              f"Total={len(df_final)} (unique Malicious available: {n_malicious_avail}).")

        if achievable_total < MAX_ROWS:
            print(f"[load_data] NOTE: capped by available unique Malicious rows "
                  f"({n_malicious_avail}) — not enough unique Malicious data to "
                  f"reach {MAX_ROWS} total while keeping a 60:40 ratio without duplication.")

    return df_final


#======================== Preprocess data (Label encoding) ========================
def preprocess_data(df):
    df_processed = df.copy()
    df_processed['Label'] = df_processed['Label'].apply(lambda x: 1 if x != 'Benign' else 0)
    return df_processed

#======================== Train the Random Forest model ========================
def train_model(X_train, y_train):
    clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    min_samples_leaf=100,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced")
    
    clf.fit(X_train, y_train)
    return clf

#================== Create feature importance plot ========================
def create_feature_importance_plot(model, feature_names):
    importances = model.feature_importances_ *100
    indices = np.argsort(importances)[::-1]
    
    fig = go.Figure(data=[go.Bar(
        x=[feature_names[i] for i in indices],
        y=[importances[i] for i in indices],
        text=[f"{importances[i]:.2f}%" for i in indices],
        textposition='auto',
    )])
    
    fig.update_layout(
        title='Feature Importance',
        xaxis_title='Features',
        yaxis_title='Importance (%)',
        xaxis_tickangle=-45
    )
    return fig
  
#======================== Save flow data with predictions =========================              
def save_flow_data(flow_data, predictions, filename):
    """
    Save flow data along with predictions to a CSV file.
    
    Args:
        flow_data (pd.DataFrame): Original flow data
        predictions (dict): Dictionary containing prediction results
        filename (str): Name of the CSV file to save
    """
    save_df = flow_data.copy()
    
    save_df['detection_time'] = predictions['detection_time']
    save_df['predicted_label'] = predictions['prediction']
    save_df['prediction_confidence'] = predictions['confidence']
   
    os.makedirs('captured_data', exist_ok=True)
    
   
    filepath = os.path.join('captured_data', filename)
    
   
    if os.path.exists(filepath):
        save_df.to_csv(filepath, mode='a', header=False, index=False)
    else:
        save_df.to_csv(filepath, index=False)
    
    return filepath

#========================= Load model and scaler from disk ========================
@st.cache_resource(show_spinner=False)
def load_saved_model():
    """Loads the model and scaler from disk if they exist."""
    try:
        with open('ids_model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('ids_scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        return model, scaler
    except FileNotFoundError:
        return None, None
   
#========================= Hybrid Decision Engine (ML + Heuristics) ======================== 
def hybrid_decision_engine(feature_vector, model_proba, confidence, confidence_threshold, suspicion_threshold):
    """
    Hybrid IDS decision using ML + confidence + flow behavior
    """

    prediction = int(np.argmax(model_proba))

    dst_port = int(feature_vector.get("Dst Port", 0))
    fwd_pkts = int(feature_vector.get("Tot Fwd Pkts", 0))
    bwd_pkts = int(feature_vector.get("Tot Bwd Pkts", 0))
    flow_duration = float(feature_vector.get("Flow Duration", 0))
    iat_mean = float(feature_vector.get("Flow IAT Mean", 0))

    suspicion_score = 0

    if dst_port in [21,22,23,25,53,80,139,445,3389]:
        suspicion_score += 1

    if fwd_pkts > 50 and flow_duration < 2_000_000:
        suspicion_score += 1

    if bwd_pkts <= 2 and fwd_pkts > 20:
        suspicion_score += 1

    if iat_mean > 0 and iat_mean < 5000:
        suspicion_score += 1

    if prediction == 1 and confidence >= confidence_threshold:
        return "Malicious", 1

    if suspicion_score >= suspicion_threshold:
        return "Malicious", 1

    return "Benign", 0
    
    
#========================= Live Detection Page ========================
def live_detection():
    
    st.title("Live Network Flow Monitoring")
    
    model, scaler = load_saved_model()
    
    if model is None or scaler is None:
        st.warning("⚠️ No trained model found! Please go to the 'Training' page and train the model first.")
        return

    save_data = st.sidebar.checkbox("Save Captured Flows", value=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    default_filename = f"Flow_{timestamp}.csv"

    custom_filename = st.sidebar.text_input(
        "Output Filename",
        default_filename
)

    full_output_path = os.path.join(CAPTURE_DIR, custom_filename)
    capture_duration = st.sidebar.number_input("Capture Duration (s)", min_value=10, value=60)

    if st.button("Start Flow Monitoring"):
        try:
            placeholder = st.empty()
            chart_placeholder = st.empty()
            
            flow_history = []
            saved_flows_count = 0
            
            def update_ui(feature_vector):
                nonlocal saved_flows_count
                
                cols_for_model = SELECTED_COLUMNS[:-1] 
                
                df_input = pd.DataFrame([feature_vector], columns=cols_for_model)
                input_data = df_input.fillna(0).values
                
                # Predict
                scaled_flow = scaler.transform(input_data)
                proba = model.predict_proba(scaled_flow)[0]


                confidence = float(np.max(proba))

                label, prediction = hybrid_decision_engine(
                feature_vector,
                proba,
                confidence,
                confidence_threshold=0.75,
                suspicion_threshold=2
                )   

                if save_data:
                    row = [feature_vector[col] for col in cols_for_model]
                    row.append(label)

                    with open(full_output_path, 'a', newline='') as f:
                        csv.writer(f).writerow(row)
                        
                saved_flows_count += 1
                
                flow_history.append({
                    'time': datetime.now(),
                    'prediction': prediction,
                    'confidence': confidence
                })
                
                with placeholder.container():
                    col1, col2, col3 = st.columns(3)
                    with col1: st.metric("Flow ID", f"#{saved_flows_count}")
                    with col2:
                        if prediction == 0: st.success("Benign Flow")
                        else: st.error("Suspicious Flow")
                    with col3: st.metric("Confidence", f"{confidence:.2%}")
                    
                    if save_data:
                        st.text(f"Saving to: {custom_filename}")
                        
                    # Show JSON preview of key stats
                    st.json({
                        'Flow Duration (µs)': f"{feature_vector['Flow Duration']:.2f}",
                        'Total Fwd Packets': int(feature_vector['Tot Fwd Pkts']),
                        'Total Bwd Packets': int(feature_vector['Tot Bwd Pkts']),
                        'Fwd Pkt Len Max': int(feature_vector['Fwd Pkt Len Max']),
                        'Flow IAT Mean': f"{feature_vector['Flow IAT Mean']:.2f}"
                    })

                
                if len(flow_history) > 1:
                    history_df = pd.DataFrame(flow_history)
                    fig = px.line(history_df, x='time', y='confidence',
                                color=history_df['prediction'].astype(str),
                                title='Flow Analysis History',
                                color_discrete_map={'0': 'green', '1': 'red'})
                    chart_placeholder.plotly_chart(fig)


            with st.spinner(f"Capturing traffic for {capture_duration} seconds..."):
                tracker = FlowTracker(full_output_path, SELECTED_COLUMNS, timeout=30, ui_callback=update_ui)
                sniff(iface="Wi-Fi", prn=tracker.process_packet, timeout=capture_duration, store=False, promisc=True, filter="ip")
                tracker.finish_all_flows() 

            st.success(f"Monitoring complete! {saved_flows_count} flows analyzed.")
            
        except PermissionError:
            st.error("Permission Denied: Run as Administrator/Root to sniff packets.")
        except Exception as e:
            st.error(f"Error: {e}")
            
            
#========================= Save user feedback to CSV ========================
def save_feedback_to_csv(feedback):
    """
    Save the user feedback to a CSV file.
    """
    file_path = "feedback.csv"
    file_exists = os.path.isfile(file_path)
    with open(file_path, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Feedback"])
        
        writer.writerow([feedback])       

#========================= Get latest scanned CSV file from CAPTURE_DIR ========================
def get_latest_live_scan_file():
    """Return latest scanned CSV file path from CAPTURE_DIR, else None."""
    csv_files = glob.glob(os.path.join(CAPTURE_DIR, "*.csv"))
    if not csv_files:
        return None

    latest_file = max(csv_files, key=os.path.getmtime)

    try:
        df = pd.read_csv(latest_file)
        if df.empty:
            return None
        return latest_file
    except Exception:
        return None

#========================= Get top important features from the trained model ========================
def get_top_features_from_model(top_n=8):
    """Return top N important feature names from the trained RandomForest model."""
    model, _ = load_saved_model()
    if model is None:
        return None

    feature_cols = SELECTED_COLUMNS[:-1]  # exclude Label
    importances = model.feature_importances_

    top_idx = np.argsort(importances)[::-1][:top_n]
    top_features = [feature_cols[i] for i in top_idx]
    return top_features

#========================= PDF Generation ========================
def save_chart():

    tmp = tempfile.NamedTemporaryFile(
        suffix=".png",
        delete=False
    )

    plt.savefig(
        tmp.name,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close("all")

    return tmp.name


def generate_pdf_report(df, filename):

    total = len(df)
    benign = (df["Predicted_Label"] == "Benign").sum()
    malicious = (df["Predicted_Label"] == "Malicious").sum()

    malicious_pct = (malicious / total * 100) if total else 0
    benign_pct = (benign / total * 100) if total else 0
    avg_conf = df["Confidence"].mean() * 100

    if malicious_pct < 5:
        risk = "LOW"
    elif malicious_pct < 20:
        risk = "MEDIUM"
    elif malicious_pct < 50:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    pdf = FPDF()
    pdf.set_auto_page_break(True, 15)

    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, "OFFLINE NETWORK DETECTION REPORT", ln=True)

    pdf.ln(5)

    pdf.set_font("Helvetica", "", 12)

    pdf.cell(0, 8, f"Generated : {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", ln=True)
    pdf.cell(0, 8, f"Offline Scan File : {filename}", ln=True)
    pdf.cell(0, 8, f"Total Flows : {total}", ln=True)
    pdf.cell(0, 8, f"Risk Level : {risk}", ln=True)

    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(0, 10, "Executive Summary", ln=True)

    pdf.set_font("Helvetica", "", 12)

    pdf.cell(0, 8, f"Total Flows          : {total}", ln=True)
    pdf.cell(0, 8, f"Benign Flows         : {benign}", ln=True)
    pdf.cell(0, 8, f"Malicious Flows      : {malicious}", ln=True)
    pdf.cell(0, 8, f"Benign Percentage    : {benign_pct:.2f}%", ln=True)
    pdf.cell(0, 8, f"Malicious Percentage : {malicious_pct:.2f}%", ln=True)
    pdf.cell(0, 8, f"Average Confidence   : {avg_conf:.2f}%", ln=True)
    pdf.cell(0, 8, f"Risk Level           : {risk}", ln=True)

    pdf.ln(8)

    pdf.set_font("Helvetica","B",15)
    pdf.cell(0,10,"Security Findings",ln=True)

    pdf.set_font("Helvetica","",12)

    pdf.multi_cell(
        0,
        8,
        f"""\
- {malicious} malicious flows detected.

- Average confidence of {avg_conf:.2f}%.

- Overall network risk classified as {risk}.

- Review high-confidence malicious traffic."""
    )
        # ================= Detection Distribution =================

    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Detection Distribution", ln=True)

    plt.figure(figsize=(6, 5))

    counts = df["Predicted_Label"].value_counts()

    colors = []

    for label in counts.index:
        if label == "Benign":
            colors.append("green")
        else:
            colors.append("red")

    plt.pie(
        counts.values,
        labels=counts.index,
        autopct="%1.1f%%",
        colors=colors,
        startangle=90
    )

    plt.title("Benign vs Malicious Distribution")

    img = save_chart()

    pdf.image(img, x=20, y=30, w=170)

    os.remove(img)
    
        # ================= Confidence Histogram =================

    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Confidence Score Distribution", ln=True)

    plt.figure(figsize=(7, 5))

    benign_df = df[df["Predicted_Label"] == "Benign"]
    malicious_df = df[df["Predicted_Label"] == "Malicious"]

    if not benign_df.empty:
        plt.hist(
            benign_df["Confidence"],
            bins=25,
            alpha=0.6,
            color="green",
            label="Benign"
        )

    if not malicious_df.empty:
        plt.hist(
            malicious_df["Confidence"],
            bins=25,
            alpha=0.6,
            color="red",
            label="Malicious"
        )

    plt.xlabel("Confidence Score")
    plt.ylabel("Number of Flows")
    plt.title("Confidence Distribution")
    plt.legend()

    img = save_chart()

    pdf.image(img, x=15, y=25, w=180)

    os.remove(img)
    
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Top 8 Most Influential Features Used by the IDS", ln=True)

    model, _ = load_saved_model()

    importances = model.feature_importances_

    feature_df = pd.DataFrame({
        "Feature": SELECTED_COLUMNS[:-1],
        "Importance": importances * 100
    })

    feature_df = feature_df.sort_values(
        by="Importance",
        ascending=False
    ).head(8)

    plt.figure(figsize=(8,5))

    plt.barh(
        feature_df["Feature"],
        feature_df["Importance"],
        color="steelblue"
    )

    plt.xlabel("Importance (%)")
    plt.title("Top 8 Most Influential Features")

    plt.gca().invert_yaxis()

    img = save_chart()

    pdf.image(img, x=15, y=25, w=180)
    os.remove(img)
      
    pdf_bytes = pdf.output(dest="S").encode("latin-1")
    return pdf_bytes


#========================= Live Analytics PDF ========================
def generate_live_pdf_report(df, filename):

    total = len(df)
    top_features = get_top_features_from_model(top_n=8)

    if top_features is None:
        top_features = []

    top_features = [f for f in top_features if f in df.columns]

    benign = (df["Label"] == "Benign").sum()
    malicious = (df["Label"] == "Malicious").sum()

    benign_pct = (benign / total * 100) if total else 0
    malicious_pct = (malicious / total * 100) if total else 0

    if malicious_pct < 5:
        risk = "LOW"
    elif malicious_pct < 20:
        risk = "MEDIUM"
    elif malicious_pct < 50:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    pdf = FPDF()
    pdf.set_auto_page_break(True, 15)

    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, "LIVE NETWORK ANALYTICS REPORT", ln=True)

    pdf.ln(5)

    pdf.set_font("Helvetica", "", 12)

    pdf.cell(
        0,
        8,
        f"Generated : {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        ln=True
    )

    pdf.cell(0, 8, f"Filename : {filename}", ln=True)
    pdf.cell(0, 8, f"Total Flows : {total}", ln=True)
    pdf.cell(0, 8, f"Risk Level : {risk}", ln=True)

    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(0, 10, "Executive Summary", ln=True)

    pdf.set_font("Helvetica", "", 12)

    pdf.cell(0, 8, f"Total Flows          : {total}", ln=True)
    pdf.cell(0, 8, f"Benign Flows         : {benign}", ln=True)
    pdf.cell(0, 8, f"Malicious Flows      : {malicious}", ln=True)
    pdf.cell(0, 8, f"Benign Percentage    : {benign_pct:.2f}%", ln=True)
    pdf.cell(0, 8, f"Malicious Percentage : {malicious_pct:.2f}%", ln=True)
    pdf.cell(0, 8, f"Risk Level           : {risk}", ln=True)
    
    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(0, 10, "Security Findings", ln=True)
        
    pdf.set_font("Helvetica", "", 12)

    pdf.multi_cell(
    0,
    8,
    f"""\
        
    - Total network flows analyzed: {total}.

    - Benign traffic detected: {benign} flows.

    - Malicious traffic detected: {malicious} flows.

    - Overall network risk classified as {risk}.

    - Live monitoring successfully analyzed network traffic.
    """
    )
    
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Live Flow Classification Distribution", ln=True)

    plt.figure(figsize=(6,5))

    counts = df["Label"].value_counts()

    colors = []

    for label in counts.index:
        if label == "Benign":
            colors.append("green")
        else:
            colors.append("red")

    plt.pie(
        counts.values,
        labels=counts.index,
        autopct="%1.1f%%",
        colors=colors,
        startangle=90
    )

    plt.title("Live Flow Classification Distribution")

    img = save_chart()

    pdf.image(img, x=20, y=30, w=170)
    os.remove(img)   
    
    
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Top 8 Most Influential Features Used by the IDS", ln=True)

    model, _ = load_saved_model()

    importances = model.feature_importances_

    feature_df = pd.DataFrame({
        "Feature": SELECTED_COLUMNS[:-1],
        "Importance": importances * 100
    })

    feature_df = feature_df.sort_values(
        by="Importance",
        ascending=False
    ).head(8)

    plt.figure(figsize=(8,5))

    plt.barh(
        feature_df["Feature"],
        feature_df["Importance"],
        color="steelblue"
    )

    plt.xlabel("Importance (%)")
    plt.title("Top 8 Most Influential Features")

    plt.gca().invert_yaxis()

    img = save_chart()

    pdf.image(img, x=15, y=25, w=180)
    os.remove(img)

    
    # ================= Essential Feature Bar Charts =================

    for col in top_features:

        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"Average {col}", ln=True)

        plt.figure(figsize=(7,5))

        avg_df = (
            df.groupby("Label")[col]
            .mean()
            .reset_index()
        )

        plt.bar(
            avg_df["Label"],
            avg_df[col],
            color=["green", "red"]
        )

        plt.xlabel("Traffic Type")
        plt.ylabel(col)
        plt.title(f"Average {col}")

        img = save_chart()

        pdf.image(img, x=15, y=30, w=180)

        os.remove(img)
        
    pdf_bytes = pdf.output(dest="S").encode("latin-1")
    return pdf_bytes

#========================= Offline Detection & Analytics Page ========================
def offline_detection_and_analytics():
    st.title("Offline Detection & Analytics")

    model, scaler = load_saved_model()
    if model is None or scaler is None:
        st.warning("⚠️ No trained model found. Train the model first.")
        st.stop()

    uploaded_file = st.file_uploader(
        "Upload Flow File (CSV or Parquet)",
        type=["csv", "parquet"]
    )

    if uploaded_file is None:
        st.info("Please upload a CSV or Parquet file to continue.")
        st.stop()

    try:
        if uploaded_file.name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_parquet(uploaded_file)
    except Exception as e:
        st.error(f"Failed to read file: {e}")
        st.stop()

    st.success(f"✅ File uploaded successfully — {len(df)} flows loaded")

    required_cols = SELECTED_COLUMNS[:-1] 
    missing = [c for c in required_cols if c not in df.columns]

    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()

    X = df[required_cols].fillna(0)
    X_scaled = scaler.transform(X)

    proba = model.predict_proba(X_scaled)
    confidence = np.max(proba, axis=1)

    
    labels = []
    confidences = []

    for i in range(len(df)):
        label, _ = hybrid_decision_engine(
        df.iloc[i].to_dict(),
        proba[i],
        confidence[i],
        confidence_threshold=0.75,
        suspicion_threshold=2
    )
        labels.append(label)
        confidences.append(confidence[i])

    df["Predicted_Label"] = labels
    df["Confidence"] = confidences
    
    st.success("Offline detection completed")

    st.subheader("Offline Analytics")
    col1, col2 = st.columns(2)

    with col1:
        pie_fig = px.pie(
            df,
            names="Predicted_Label",
            title="Benign vs Malicious Distribution",
            color="Predicted_Label",
            color_discrete_map={"Benign": "green", "Malicious": "red"}
        )
        st.plotly_chart(pie_fig, use_container_width=True)
        
    with col2:
        hist_fig = px.histogram(
            df,
            x="Confidence",
            color="Predicted_Label",
            title="Confidence Score Distribution",
            color_discrete_map={"Benign": "green", "Malicious": "red"}
        )
        st.plotly_chart(hist_fig, use_container_width=True)
        
    st.subheader("Top 8 Most Important Features")

    plot_feature_importance()

    st.subheader("📡 Protocol Analysis")

    proto_counts = df["Protocol"].value_counts().reset_index()
    proto_counts.columns = ["Protocol", "count"]

    proto_fig = px.bar(
        proto_counts,
        x="Protocol",
        y="count",
        labels={"Protocol": "Protocol", "count": "Number of Flows"},
        title="Protocol-wise Flow Distribution"
    )
    proto_fig.update_traces(width=0.3)
    st.plotly_chart(proto_fig, use_container_width=True)
    
    st.subheader("🎯 Top Destination Ports (Malicious Traffic)")
    mal_df = df[df["Predicted_Label"] == "Malicious"]
    if not mal_df.empty:
        port_counts = mal_df["Dst Port"].value_counts().head(10).reset_index()
        port_counts.columns = ["Dst Port", "count"]

        port_fig = px.bar(
            port_counts,
            x="Dst Port",
            y="count",
            title="Top 10 Destination Ports in Malicious Flows",
            labels={"count": "Number of Flows"}
        )
        st.plotly_chart(port_fig, use_container_width=True)
    else:
        st.info("No malicious flows available for port analysis.")
    st.subheader("⏱ Flow Duration vs Confidence")

    scatter_fig = px.scatter(
        df,
        x="Flow Duration",
        y="Confidence",
        color="Predicted_Label",
        title="Flow Duration vs Prediction Confidence",
        color_discrete_map={"Benign": "green", "Malicious": "red"},
        opacity=0.4
    )
    st.plotly_chart(scatter_fig, use_container_width=True)
    
    st.subheader("📦 Packet Volume Comparison")

    packet_fig = px.histogram(
        df,
        x="Tot Fwd Pkts",
        color="Predicted_Label",
        nbins=30,
        barmode="overlay",
        title="Forward Packet Distribution by Prediction",
        color_discrete_map={"Benign": "green", "Malicious": "red"}
    )
    st.plotly_chart(packet_fig, use_container_width=True)
       
    st.subheader("⬇ Download Results")

    csv_data = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Detection Results",
        csv_data,
        "offline_detection_results.csv",
        "text/csv"
    )


    pdf_bytes = generate_pdf_report(df,uploaded_file.name)
    st.download_button(
    label="Download Offline Detection Report",
    data=pdf_bytes,
    file_name="Offline_Detection_Report.pdf",
    mime="application/pdf"
    )

def plot_feature_importance(top_n=8):

    model, _ = load_saved_model()

    if model is None:
        st.warning("No trained model found.")
        return

    importances = model.feature_importances_

    feature_df = pd.DataFrame({
        "Feature": SELECTED_COLUMNS[:-1],
        "Importance": importances * 100
    })

    feature_df = feature_df.sort_values(
        by="Importance",
        ascending=False
    ).head(top_n)

    fig = px.bar(
        feature_df,
        x="Importance",
        y="Feature",
        orientation="h",
        title="Top 8 Most Influential Features Used by the IDS",
        text="Importance",
        color="Importance",
        color_continuous_scale="Blues"
    )

    fig.update_traces(
        texttemplate="%{text:.2f}%",
        textposition="outside"
    )

    fig.update_layout(
        yaxis=dict(
            categoryorder="total ascending",
            title="Features",
            tickfont=dict(size=13)
        ),
        xaxis=dict(
            title="Importance (%)",
            tickfont=dict(size=13)
        ),
        title=dict(
            font=dict(size=18)
        ),
        font=dict(size=14),
        coloraxis_showscale=False
    )

    st.plotly_chart(fig, use_container_width=True)   


#===================== Main Streamlit App with Navigation ========================
def main():

    current_page = st.session_state.get("page", "Home")
    st.sidebar.title("Navigation")
    selected = st.sidebar.selectbox(
        "Choose a page",
        ["Home", "Training", "Live Detection", "Live Analytics", "Offline Detection & Analytics", "Help"],
        index=["Home", "Training", "Live Detection", "Live Analytics", "Offline Detection & Analytics", "Help"].index(current_page)
    )
    st.session_state.page = selected
    current_page = selected  
    
    
    if current_page == "Home":

        st.title("Network Based AI Intrusion Detection System")

        st.markdown("""
        ### Welcome to Network Based AI Intrusion Detection System
        This Network Flow-Based IDS monitors and analyzes traffic flows to 
        identify potential network threats. It uses machine learning model 
        trained on CICFlowMeter-derived features to detect anomalies and 
        attack patterns in real-time or offline datasets.

        ### Features:
        - Network-based traffic analysis  
        - Machine Learning based intrusion detection  
        - Real-time monitoring  
        - Offline packet analysis 
        - Interactive visualizations 
        - Attack detection and reporting

        ### Key Flow Metrics:
        - Protocol Identifiers (Destination Port, Protocol)
        - Flow Timing Stats (Duration, IAT Mean/Std/Max/Min)
        - Traffic Volume (Total Packets, Flow Bytes/s, Flow Packets/s)
        - Packet Dimensions (Length Max/Min/Mean/Std)
        - Header Information (Forward/Backward Header Lengths)
        - TCP Flag Counts (SYN, FIN, RST, PSH, ACK, URG)  
        """)

                
        if st.button("Need Help?"):
            st.session_state.page = "Help"  
            
        st.sidebar.title("Quick Actions")
        st.sidebar.write("Access the app's main features quickly:")
            
        if st.sidebar.button("View Analytics", key="analytics_btn"):
            st.session_state.page = "Live Analytics"
        
        if st.sidebar.button("Retrain Model", key="retrain_btn"):
            st.session_state.page = "Training"
            
        if st.sidebar.button("Live Detection", key="live_detection_btn"):
            st.session_state.page = "Live Detection"
         
        if st.sidebar.button("Offline Detection & Analytics", key="offline_detection_btn"):
            st.session_state.page = "Offline Detection & Analytics" 
            
        if st.sidebar.button("Need Help?",key="help_btn"):
            st.session_state.page = "Help" 
            
        st.sidebar.write("---")
        st.sidebar.title("About")
        st.sidebar.write("**IntelliGuard IDS**")
        st.sidebar.write("An AI based Intrusion Detection System powered by machine learning.  It analyzes network traffic, detects suspicious activity, and tries its best to keep your packets honest.")

        st.sidebar.write("---")
        st.sidebar.title("Feedback")
        with st.sidebar.form("feedback_form"):
            st.write("Let us know how we be improve!")
            feedback = st.text_area("Your feedback")
            submit = st.form_submit_button("Submit")
            if submit:
                if feedback.strip():
                    save_feedback_to_csv(feedback)
                    st.success("Thank you for your feedback! It has been saved.")
                else:
                    st.warning("Feedback cannot be empty. Please provide your feedback.")
                

    elif current_page == "Training":
        st.sidebar.write("---")
        st.sidebar.title("Training Module")
        st.sidebar.write("""
        Section used to train the intrusion detection model.


        **What happens here:**
        - Load CICFlowMeter-based csv datasets
        - Preprocess and label network flows
        - Train a Random Forest classifier
        - Save the trained model and scaler for live detection
        """)
        
        st.sidebar.write("---")
        st.sidebar.title("About")
        st.sidebar.write("**IntelliGuard IDS**")
        st.sidebar.write("An AI based Intrusion Detection System powered by machine learning.  It analyzes network traffic, detects suspicious activity, and tries its best to keep your packets honest.")

        st.sidebar.write("---")
        st.sidebar.title("Feedback")
        with st.sidebar.form("feedback_form"):
            st.write("Let us know how we be improve!")
            feedback = st.text_area("Your feedback")
            submit = st.form_submit_button("Submit")
            if submit:
                if feedback.strip():
                 save_feedback_to_csv(feedback)
                 st.success("Thank you for your feedback! It has been saved.")
            else:
                st.warning("Feedback cannot be empty. Please provide your feedback.")
                
        st.header("Dataset Load & Train")
        
        if st.button("Load and Process Data"):
            with st.spinner("Loading data..."):
                df = load_data()
                st.success(f"Loaded {len(df)} flow records!")
                
                st.subheader("Sample Flow Data")
                st.dataframe(df.head())
                
                df_processed = preprocess_data(df)
                X = df_processed.drop('Label', axis=1)
                y = df_processed['Label']
                
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42, stratify=y)
                
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train).astype("float32")
                X_test_scaled = scaler.transform(X_test).astype("float32")
                
                with st.spinner("Training model..."):
                    model = train_model(X_train_scaled, y_train)
                    
                with open('ids_model.pkl', 'wb') as f:
                    pickle.dump(model, f)
                with open('ids_scaler.pkl', 'wb') as f:
                    pickle.dump(scaler, f)

                # Bust the cached load_saved_model() result so Live Detection
                # picks up the freshly trained model instead of a stale
                # cached (None, None) from before training ran.
                load_saved_model.clear()
                
                y_pred = model.predict(X_test_scaled)

                st.subheader("Class Distribution")

                class_counts = df['Label'].value_counts()
                st.write(class_counts)

                fig = px.pie(
                    names=class_counts.index,
                    values=class_counts.values,
                    title="Benign vs Attack Distribution"
                )
                st.plotly_chart(fig)

                st.subheader("Model Performance")

                recall = recall_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred)
                f1 = f1_score(y_test, y_pred)
                bal_acc = balanced_accuracy_score(y_test, y_pred)
                accuracy = accuracy_score(y_test, y_pred)
                cm = confusion_matrix(y_test, y_pred)
                TN, FP, FN, TP = cm.ravel()
                fpr = FP / (FP + TN)
                y_prob = model.predict_proba(X_test_scaled)[:,1]
                roc_auc = roc_auc_score(y_test, y_prob)
                col1, col2, col3 = st.columns(3)
                col1.metric("Attack Detection Rate", f"{(recall*100):.2f}%")
                col2.metric("Precision", f"{(precision*100):.2f}%")
                col3.metric("F1 Score", f"{(f1*100):.2f}%")

                col1, col2, col3 = st.columns(3)
                col1.metric("False Positive Rate", f"{(fpr*100):.3f}%")
                col3.metric("Overall Accuracy", f"{(accuracy*100):.2f}%")


                cm = confusion_matrix(y_test, y_pred)
                fig, ax = plt.subplots()
                sns.heatmap(cm, annot=True, fmt='d', ax=ax, 
                          xticklabels=['Benign', 'Malicious'],
                          yticklabels=['Benign', 'Malicious'])
                plt.xlabel('Predicted')
                plt.ylabel('True')
                st.pyplot(fig)
                
                importance_fig = create_feature_importance_plot(model, X.columns)
                st.plotly_chart(importance_fig)
                
                
    elif current_page == "Live Detection":
        live_detection()
        
        st.sidebar.write("---")
        st.sidebar.title("Live Detection")
        st.sidebar.write("""
        Real-time network monitoring and threat detection.


        **Capabilities:**
        - Captures live packets using Scapy
        - Extracts flow-level features
        - Applies trained ML model
        - Flags suspicious traffic instantly based on confidence score
        - Optionally saves detected flows
        """)
        
        st.sidebar.write("---")
        st.sidebar.title("About")
        st.sidebar.write("**IntelliGuard IDS**")
        st.sidebar.write("An AI based Intrusion Detection System powered by machine learning.  It analyzes network traffic, detects suspicious activity, and tries its best to keep your packets honest.")

        st.sidebar.write("---")
        st.sidebar.title("Feedback")
        with st.sidebar.form("feedback_form"):
            st.write("Let us know how we be improve!")
            feedback = st.text_area("Your feedback")
            submit = st.form_submit_button("Submit")
            if submit:
                if feedback.strip():
                 save_feedback_to_csv(feedback)
                 st.success("Thank you for your feedback! It has been saved.")
            else:
                st.warning("Feedback cannot be empty. Please provide your feedback.")


    elif current_page == "Live Analytics":
        st.sidebar.write("---")
        st.sidebar.title("Live Analytics")
        st.sidebar.write("""
        Analyze the **latest live scan report**.


        **Insights include:**
        - Benign vs Malicious distribution
        - Flow behavior patterns
        - Essential feature distributions
        - Correlation heatmaps
        """)
        
        st.sidebar.write("---")
        st.sidebar.title("About")
        st.sidebar.write("**IntelliGuard IDS**")
        st.sidebar.write("An AI based Intrusion Detection System powered by machine learning.  It analyzes network traffic, detects suspicious activity, and tries its best to keep your packets honest.")

        st.sidebar.write("---")
        st.sidebar.title("Feedback")
        with st.sidebar.form("feedback_form"):
            st.write("Let us know how we be improve!")
            feedback = st.text_area("Your feedback")
            submit = st.form_submit_button("Submit")
            if submit:
                if feedback.strip():
                 save_feedback_to_csv(feedback)
                 st.success("Thank you for your feedback! It has been saved.")
            else:
                st.warning("Feedback cannot be empty. Please provide your feedback.")
        
        st.header("Live Analytics Dashboard")

        latest_scan_file = get_latest_live_scan_file()

        if latest_scan_file is None:
            st.warning("No live detection reports found. Run Live Detection first.")
            st.stop()

        df = pd.read_csv(latest_scan_file)

        if "Label" not in df.columns:
            st.error("Live scan file is missing 'Label' column.")
            st.stop()

        top_features = get_top_features_from_model(top_n=8)

        label_color_map = {"Benign": "green", "Malicious": "red"}
        
        if top_features is None:
            st.warning("No trained model found. Train the model first to generate essential feature analytics.")
            st.stop()

        top_features = [f for f in top_features if f in df.columns]

        if len(top_features) == 0:
            st.warning("No essential feature columns found in live scan report.")
            st.stop()

        st.success(f"Live Report Loaded: {os.path.basename(latest_scan_file)}")
        
        st.info("Essential Features Used for Plots:")
        st.write(top_features)

        col1, col2 = st.columns(2)

        with col1:
            label_counts = df["Label"].value_counts()
            fig = px.pie(
                values=label_counts.values,
                names=label_counts.index,
                color=label_counts.index,
                color_discrete_map=label_color_map,
                title="Live Flow Classification Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            if "Tot Fwd Pkts" in df.columns and "Tot Bwd Pkts" in df.columns:
                fig = px.scatter(
                    df,
                    x="Tot Fwd Pkts",
                    y="Tot Bwd Pkts",
                    color="Label",
                    title="Forward vs Backward Packets (Live)",
                    opacity=0.4,
                    color_discrete_map=label_color_map
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Tot Fwd Pkts / Tot Bwd Pkts not found in live file.")

        st.subheader("Top 8 Most Important Features")

        plot_feature_importance()
        
        
        st.subheader("Essential Feature Distributions (Live)")

        for col in top_features:

            avg_df = df.groupby("Label")[col].mean().reset_index()

            fig = px.bar(
                avg_df,
                x="Label",
                y=col,
                color="Label",
                title=f"Average {col}",
                color_discrete_map=label_color_map,
                text_auto=".2f"
            )
            fig.update_traces(width=0.3)
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Essential Feature Correlation Heatmap")

        corr_df = df[top_features].apply(pd.to_numeric, errors="coerce").fillna(0)

        fig = px.imshow(
            corr_df.corr(),
            text_auto=True,
            title="Correlation Heatmap (Essential Features)"
        )
        fig.update_layout(height=700)
        st.plotly_chart(fig, use_container_width=True)
        
        
        st.subheader("⬇ Download PDF Result")

        pdf_bytes = generate_live_pdf_report(
            df,
            os.path.basename(latest_scan_file)
        )

        st.download_button(
            label="Download Live Analytics Report",
            data=pdf_bytes,
            file_name="Live_Analytics_Report.pdf",
            mime="application/pdf"
        )
    
    elif current_page == "Offline Detection & Analytics":
        st.sidebar.write("---")
        st.sidebar.title("Offline Detection & Analytics")
        st.sidebar.write("""
        This module allows you to:
        - Upload CSV flow files
        - Run predictions using the trained model
        - Identify suspicious traffic
        - Perform deep statistical analysis
        """)
        
        st.sidebar.write("---")
        st.sidebar.title("About")
        st.sidebar.write("**IntelliGuard IDS**")
        st.sidebar.write("An AI based Intrusion Detection System powered by machine learning.  It analyzes network traffic, detects suspicious activity, and tries its best to keep your packets honest.")

        st.sidebar.write("---")
        st.sidebar.title("Feedback")
        with st.sidebar.form("feedback_form"):
            st.write("Let us know how we be improve!")
            feedback = st.text_area("Your feedback")
            submit = st.form_submit_button("Submit")
            if submit:
                if feedback.strip():
                  save_feedback_to_csv(feedback)
                  st.success("Thank you for your feedback! It has been saved.")
            else:
                st.warning("Feedback cannot be empty. Please provide your feedback.")
        
        offline_detection_and_analytics()
        
                
    elif current_page == "Help":
        st.sidebar.write("---")
        st.sidebar.title("Help & Documentation")
        st.sidebar.write("""
        This section explains how to use each part of IntelliGuard IDS.


        **Need assistance with:**
        - Model training
        - Live detection
        - Analytics dashboards
        - Dataset preparation


        Refer to the documentation provided on this page.
        """)
        st.sidebar.write("---")
        st.sidebar.title("About")
        st.sidebar.write("**IntelliGuard IDS**")
        st.sidebar.write("An AI based Intrusion Detection System powered by machine learning.  It analyzes network traffic, detects suspicious activity, and tries its best to keep your packets honest.")

        st.sidebar.write("---")
        st.sidebar.title("Feedback")
        with st.sidebar.form("feedback_form"):
            st.write("Let us know how we be improve!")
            feedback = st.text_area("Your feedback")
            submit = st.form_submit_button("Submit")
            if submit:
                if feedback.strip():
                 save_feedback_to_csv(feedback)
                 st.success("Thank you for your feedback! It has been saved.")
            else:
                st.warning("Feedback cannot be empty. Please provide your feedback.")
        
        st.title("Help & Documentation")

        st.markdown("## How to Use Network Flow IDS")

        with st.expander("Home"):
            st.write("""
            Overview of the IDS, features, and quick navigation buttons.
            Use this page to understand what IntelliGuard IDS does and jump to key actions fast.
            """)

        with st.expander("Training"):
            st.write("""
            Upload and process the dataset to train the ML model.
            - Loads Parquet flow dataset  
            - Trains RandomForest model  
            - Saves trained model + scaler for live detection  
            """)

        with st.expander("Live Detection"):
            st.write("""
            Start real-time flow capture and run ML predictions live.
            - Captures traffic using packet sniffing  
            - Predicts Benign / Malicious flows  
            - Auto-saves captured logs into `captured_data/`  
            """)

        with st.expander("Offline Detection & Analytics"):
            st.write("""
            Analyze an existing CSV flow file (not live capture).
            - Upload CSV of flows  
            - Generate predictions using saved model  
            - Visualize and inspect suspicious activity  
            """)

        with st.expander("Live Analytics"):
            st.write("""
            View analytics for the latest live scan report.
            - Benign vs Malicious distribution  
            - Flow duration, IAT, packet size patterns  
            - Destination port insights  
            """)

        st.markdown("## Installations Required")
        st.markdown("""
        - [Download Wireshark](https://www.wireshark.org/download.html)
        - [Download Npcap](https://nmap.org/npcap)
        - [Download CICFlowmeter - For Windows (GUI)/Linux](https://drive.google.com/file/d/1eR3v4Bq3Sal3RpzaXpIWUyswGWCzCfi9/view)
        - [Download CICFlowmeter (Python) - For Windows/Linux (Terminal/CLI)](https://pypi.org/project/cicflowmeter)\n
        If the above link doesnt work, try the below file:     
        - [Download CICFlowmeter (Java) - For Windows/Linux](https://github.com/ahlashkari/CICFlowMeter)
        """)
        
        st.subheader("Software Documentation")

        st.markdown(
            download_link("README/README_Py.md", "Download CICFlowMeter - Python version README"),
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            download_link("README/README_JAVA.md", "Download CICFlowMeter - Java version README\n"),
            unsafe_allow_html=True
        )
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("⬅ Back to Home"):
            st.session_state.page = "Home"
            
#========================= Run the Streamlit app ========================
if __name__ == "__main__":
    if "page" not in st.session_state:
        st.session_state.page = "Home"

    main()