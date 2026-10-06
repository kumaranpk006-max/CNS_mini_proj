# AI-Based Phishing URL Detection System Using Machine Learning

**Academic Level:** 3rd Year B.Tech — Artificial Intelligence and Data Science  
**Technology Stack:** Java 24, Weka 3.8.6, Java Swing, Apache Maven  
**Primary Algorithm:** Random Forest Ensemble (100 Trees)  
**Dataset:** UCI Phishing Websites Benchmark Dataset (`Training Dataset.arff`)  
**Trained Model Performance:** **97.56% Test Accuracy**, **0.9756 Weighted F1-Score**, **0.9931 ROC-AUC**

---

## 1. Abstract

Phishing is one of the most widespread and damaging cyber threats on the Internet today. Attackers disguise malicious websites as reputable organizations (banks, social media, payment gateways) to deceive users into disclosing sensitive personal credentials and financial data. Conventional security mechanisms, such as static blacklist databases, frequently fail against newly registered, zero-hour, and dynamically generated phishing domains. 

This project presents an **AI-Based Phishing URL Detection System** implemented in **Java** using the **Weka Machine Learning Library** and a desktop **Java Swing GUI**. A **Random Forest** classifier was trained on the benchmark UCI Phishing Websites dataset containing 11,055 instances and 30 categorical features. The system extracts URL lexical and structural features in real time, converts them into a standardized Weka feature vector, and performs probabilistic classification. On an unseen test partition of 2,211 instances, the model achieves **97.56% accuracy** with an inference latency of under 45 milliseconds. The application provides instant classification (`LEGITIMATE` vs. `PHISHING`), risk scoring (`LOW`, `MEDIUM`, `HIGH`), confidence percentages, and an interactive feature inspection dialog.

---

## 2. Introduction & Background

With the exponential growth of online banking, e-commerce, and cloud services, phishing attacks have grown increasingly sophisticated. Attackers leverage typosquatting, URL shortening services, sub-domain chaining, and deceptive host tokens to mislead victims. 

Machine Learning offers a proactive, data-driven approach to cyber defense. By extracting statistical, lexical, and structural characteristics from URLs, machine learning algorithms can detect malicious patterns even in URLs never seen before. This project provides an offline, defensive desktop security tool allowing end-users to evaluate suspicious links safely prior to opening them in web browsers.

---

## 3. Problem Statement

Traditional phishing detection techniques rely heavily on **blacklist filtering** (e.g., Google Safe Browsing, PhishTank). While effective for known malicious domains, blacklists have several major drawbacks:
1. **Zero-Day Vulnerability:** They cannot protect users against newly created phishing URLs during the critical window between attack launch and blacklist indexing (which can take hours or days).
2. **Short Life-Span:** Phishing sites typically remain active for only 4 to 24 hours before moving to new domains, outpacing manual verification.
3. **Blacklist Evasion:** Attackers easily bypass string matching by generating randomized subdomains, IP encodings, or URL shorteners.

Therefore, an intelligent, automated classification system that evaluates the inherent structure of a URL is necessary.

---

## 4. Existing System vs. Proposed System

| Parameter | Existing Blacklist-Based System | Proposed AI-Based ML System |
| :--- | :--- | :--- |
| **Detection Method** | Database lookup of known malicious URLs | Feature extraction + Random Forest ML inference |
| **Zero-Hour Detection** | Incapable; requires prior reporting and indexing | Capable; detects unseen URLs based on learned structural traits |
| **Response Speed** | Fast for indexed URLs, fails on new URLs | Real-time classification in < 45 milliseconds |
| **Safety** | Requires database synchronization | Safe, standalone desktop tool; no harmful payloads downloaded |
| **Confidence Scoring**| Binary presence in database (Yes/No) | Continuous probability distribution with multi-tier risk scoring |
| **Feature Inspection**| Not available | Full transparency via interactive **[ SHOW FEATURES ]** panel |

---

## 5. Objectives & Scope

### Project Objectives:
1. Load, validate, and analyze the canonical 31-attribute UCI Phishing Websites dataset without data leakage.
2. Train and tune a high-performance **Random Forest** classifier using Weka 3.8.6.
3. Implement a real-time **Java URL Feature Extractor** that computes lexical and structural attributes matching the training schema.
4. Design a clean, responsive desktop application using **Java Swing**.
5. Provide transparent risk assessment (`LOW`, `MEDIUM`, `HIGH`) and detailed feature breakdown for academic demonstration.

### Project Scope:
- **Included:** Lexical URL analysis, protocol verification, subdomain hierarchy evaluation, machine learning inference, risk classification, and desktop UI.
- **Excluded (By Design):** The application intentionally avoids downloading web pages or executing remote JavaScript to protect the host machine against drive-by downloads and web exploits.

---

## 6. System Architecture

The following diagram illustrates the complete end-to-end dataflow and architecture of the system:

```mermaid
flowchart TD
    A([User Enters Website URL]) --> B[Java Swing GUI - MainGUI]
    B --> C[URL Validation & Normalization - Utils]
    C --> D[Feature Extraction Engine - URLFeatureExtractor]
    
    subgraph FeatureEngineering [Feature Engineering & Schema Alignment]
        D --> D1[10 URL Lexical Features]
        D --> D2[2 Network/Protocol Features]
        D --> D3[18 Defensive Baseline Features]
        D1 & D2 & D3 --> E[30-Element Integer Vector]
    end
    
    E --> F[Weka Instance Builder - ModelPredictor]
    F --> G[(Saved Random Forest Model\nphishing_model.model)]
    G --> H[Ensemble Decision Trees\n100 Trees Evaluation]
    H --> I[Class Probability Distribution\nP(Legitimate) vs P(Phishing)]
    
    I --> J{Classification Decision}
    J -->|P_Legit >= P_Phish| K[Prediction: LEGITIMATE]
    J -->|P_Phish > P_Legit| L[Prediction: PHISHING]
    
    K & L --> M[Risk Scoring Engine - LOW / MEDIUM / HIGH]
    M --> N[GUI Result Display & Feature Inspector]
```

---

## 7. Dataset Description

The dataset used in this project is the **Phishing Websites Dataset** from the **UCI Machine Learning Repository**, compiled by researchers Rami M. Mohammad, Fadi Thabtah, and Lee McCluskey.

- **Primary Dataset File:** `dataset/Training Dataset.arff`
- **Total Records (Instances):** 11,055
- **Total Attributes:** 31 (30 input features + 1 target class)
- **Class Attribute:** `Result`
  - `1`: **LEGITIMATE** — 6,157 instances (55.69%)
  - `-1`: **PHISHING** — 4,898 instances (44.31%)
- **Missing Values:** **0** (Complete dataset)
- **Class Balance:** Well-balanced (no synthetic sampling/SMOTE needed)

### Summary of Dataset Features (30 Attributes)

1. `having_IP_Address`: Uses IP address directly as hostname (`-1` = IP used, `1` = domain).
2. `URL_Length`: Length thresholding (`1` < 54, `0` = 54–75, `-1` > 75).
3. `Shortining_Service`: Uses tinyurl, bit.ly, etc. (`-1` = shortener, `1` = standard).
4. `having_At_Symbol`: Contains `@` symbol (`-1` = present, `1` = absent).
5. `double_slash_redirecting`: Position of `//` after character index 7 (`-1` = redirect, `1` = normal).
6. `Prefix_Suffix`: Domain contains hyphen `-` (`-1` = contains hyphen, `1` = no hyphen).
7. `having_Sub_Domain`: Dot count in host (`1` = 1 dot, `0` = 2 dots, `-1` > 2 dots).
8. `SSLfinal_State`: HTTPS encryption and certificate trustworthiness (`1` = trusted HTTPS, `0` = suspicious, `-1` = insecure HTTP).
9. `Domain_registeration_length`: Domain expires in ≤ 1 year (`-1`) or > 1 year (`1`).
10. `Favicon`: Favicon loaded from foreign domain (`-1`) or same domain (`1`).
11. `port`: Open non-standard port specified (`-1`) or standard port (`1`).
12. `HTTPS_token`: Token `http`/`https` embedded inside domain label (`-1` = present, `1` = absent).
13. `Request_URL`: % of external media resources.
14. `URL_of_Anchor`: % of `<a>` tags with foreign, `#`, or empty links.
15. `Links_in_tags`: % of `<meta>`, `<script>`, `<link>` pointing to external domains.
16. `SFH` (Server Form Handler): Form action URL is empty or foreign.
17. `Submitting_to_email`: Uses `mailto:` or PHP `mail()` function in web forms.
18. `Abnormal_URL`: Hostname structure is malformed or absent.
19. `Redirect`: Redirect page count (`0` ≤ 1 redirect, `1` ≥ 2 redirects).
20. `on_mouseover`: JavaScript manipulates browser status bar on hover.
21. `RightClick`: JavaScript disables right-click context menu (`event.button==2`).
22. `popUpWidnow`: JavaScript popups contain credential input fields.
23. `Iframe`: Invisible `<iframe>` tags overlaying content.
24. `age_of_domain`: Domain registered < 6 months (`-1`) or ≥ 6 months (`1`).
25. `DNSRecord`: Resolves in DNS (`1`) or unresolvable (`-1`).
26. `web_traffic`: Alexa website traffic ranking.
27. `Page_Rank`: Google PageRank score.
28. `Google_Index`: Indexed by Google Search engine.
29. `Links_pointing_to_page`: Number of external backlinks pointing to page.
30. `Statistical_report`: Listed in PhishTank or StopBadware threat intelligence blacklists.

---

## 8. Machine Learning Algorithm: Random Forest

### Why Random Forest?
**Random Forest** is an ensemble learning method that constructs a collection of randomized decision trees during training and outputs the mode of the classes (or average probability distribution) across individual trees.

1. **High Non-Linear Separability:** Phishing URLs exhibit complex interaction patterns (e.g., an HTTPS URL that contains a hyphen and an embedded brand token). Random Forest models feature interactions naturally.
2. **Immunity to Feature Scaling:** Operates via orthogonal decision splits, making it completely invariant to monotonic transformations and scaling.
3. **Resilience to Overfitting:** By combining bootstrap aggregating (bagging) with random feature subspace sampling, variance is significantly reduced compared to individual decision trees.
4. **Fast Training & Real-Time Inference:** In our benchmarks, 100 trees trained on 8,844 instances in **1.15 seconds** and predicted individual URLs in **1 to 45 milliseconds**.

### Configuration Parameters:
- **Number of Trees (`numIterations`):** 100
- **Random Seed:** 42 (Guarantees reproducible results)
- **Parallelism (`numExecutionSlots`):** Multi-core enabled (0 = utilize all available CPU cores)

---

## 9. Model Training & Evaluation Results

The dataset was partitioned using an **80% Training / 20% Testing** stratified split:
- **Training Instances:** 8,844
- **Testing Instances:** 2,211 (Unseen test set)

### Performance Metrics on Unseen Test Data

| Metric | Measured Value | Meaning / Interpretation |
| :--- | :---: | :--- |
| **Accuracy** | **97.56%** | 2,157 out of 2,211 test instances correctly classified |
| **Weighted Precision** | **0.9757** | 97.57% of positive predictions were correct |
| **Weighted Recall** | **0.9756** | 97.56% of true instances were successfully detected |
| **Weighted F1-Score** | **0.9756** | Harmonic mean of Precision and Recall |
| **ROC-AUC** | **0.9931** | Area under Receiver Operating Characteristic curve |
| **Kappa Statistic** | **0.9504** | Near-perfect inter-rater agreement (> 0.81 is excellent) |

### Detailed Performance by Class

| Class Label | Value | Precision | Recall | F1-Score | ROC-AUC | Test Instances |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PHISHING** | `-1` | **0.9813** | **0.9632** | **0.9721** | **0.9931** | 978 |
| **LEGITIMATE** | `1` | **0.9712** | **0.9854** | **0.9783** | **0.9931** | 1,233 |

### Confusion Matrix

```text
       a        b     <-- Classified as
     942       36   | a = PHISHING (Value '-1')
      18     1215   | b = LEGITIMATE (Value '1')
```

- **True Positives (TP = 942):** Phishing websites correctly identified and blocked.
- **True Negatives (TN = 1,215):** Legitimate websites correctly verified.
- **False Positives (FP = 18):** Legitimate websites mistakenly flagged (0.8% false alarm rate).
- **False Negatives (FN = 36):** Phishing websites that evaded detection (1.6% miss rate).

---

## 10. Project Structure

```
cns_mini/
│
├── dataset/
│   ├── Training Dataset.arff           # Primary ARFF dataset (Read-only, 11,055 rows)
│   ├── .old.arff                       # Backup archive
│   └── Phishing Websites Features.docx # Mohammad et al. research feature definitions
│
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── phishingdetector/
│                   ├── Main.java                 # Primary application entry point (GUI launcher)
│                   ├── MainGUI.java              # Java Swing interactive desktop GUI
│                   ├── DatasetLoader.java        # ARFF dataset parser and schema validator
│                   ├── DataPreprocessor.java     # Stratified 80/20 train-test partitioner
│                   ├── ModelTrainer.java         # Weka Random Forest training & evaluation engine
│                   ├── ModelPredictor.java       # ML model deserializer & probability inference
│                   ├── PredictionResult.java     # Immutable prediction value object
│                   ├── URLFeatureExtractor.java  # 30-feature real-time extraction engine
│                   ├── URLPredictionService.java # Singleton prediction pipeline coordinator
│                   ├── Utils.java                # Risk level calculator & URL validator
│                   ├── SystemTestSuite.java      # 11-case automated test suite
│                   └── TestSetup.java            # Environment & Weka dependency verification
│
├── model/
│   ├── phishing_model.model            # Serialized Weka Random Forest model (8.7 MB)
│   └── model_header.arff               # Attribute template for real-time inference
│
├── results/
│   ├── model_evaluation.txt            # Complete evaluation report with confusion matrix
│   └── test_results.txt                # 11-case test execution audit log
│
├── docs/
│   └── VIVA.md                         # 26 Viva Questions and Answers with explanations
│
├── pom.xml                             # Maven build and dependency configuration
├── mvn.cmd                             # Project-level Apache Maven wrapper
└── README.md                           # Comprehensive project documentation
```

---

## 11. Installation & Setup Guide

### Prerequisites:
- **Operating System:** Windows 10 / 11, macOS, or Linux
- **Java Development Kit:** JDK 17, 21, or 24 (Tested with Oracle JDK 24.0.2)
- **Apache Maven:** Bundled Maven wrapper (`mvn.cmd`) provided in project root

### Quick Verification:
Check installed Java version:
```powershell
java -version
javac -version
```

---

## 12. How to Run, Train, and Test

### 1. Launch the Desktop GUI Application:
```powershell
# Standard launch
.\mvn.cmd exec:java
```

### 2. Retrain the Machine Learning Model:
```powershell
# Retrains the Random Forest model and generates results/model_evaluation.txt
.\mvn.cmd exec:java "-Dexec.mainClass=com.phishingdetector.ModelTrainer"
```

### 3. Run the Automated 11-Case Test Suite:
```powershell
# Executes test suite and updates results/test_results.txt
.\mvn.cmd exec:java "-Dexec.mainClass=com.phishingdetector.SystemTestSuite"
```

### 4. Test URL Feature Extractor Independently:
```powershell
.\mvn.cmd exec:java "-Dexec.mainClass=com.phishingdetector.URLFeatureExtractor"
```

### 5. Validate the Dataset Loader:
```powershell
.\mvn.cmd exec:java "-Dexec.mainClass=com.phishingdetector.DatasetLoader"
```

---

## 13. System Advantages

1. **High Predictive Accuracy:** Demonstrates **97.56% accuracy** and **0.9931 ROC-AUC** on real-world benchmark data.
2. **Sub-Millisecond Inference:** In-memory model caching produces results in 1 to 45 ms.
3. **Safe Defensive Operation:** Analyzes URLs strictly as character strings without downloading dangerous payloads or visiting untrusted servers.
4. **Complete Transparency:** Allows users and evaluators to inspect all 30 extracted features and their underlying reasoning.
5. **Clean Modular Architecture:** Strict separation between GUI presentation, service coordination, feature extraction, and ML inference.

---

## 14. Project Limitations

1. **Offline URL Scope:** Because the system operates safely without downloading external pages, HTML content features (like invisible iframes and form handlers) rely on safe defensive baselines when evaluated offline.
2. **Shortened URLs:** While the system correctly identifies URL shortening domains (`bit.ly`, `tinyurl.com`) as suspicious, resolving the ultimate destination requires following HTTP redirects over a network.
3. **Evolving Attack Vectors:** Adversaries continuously devise new techniques (e.g., Unicode homograph attacks or compromised legitimate websites) that may evade lexical filters.

---

## 15. Future Enhancements

1. **Browser Extension:** Package the feature extractor and inference engine as a Chrome/Firefox extension for real-time in-browser URL warnings.
2. **Sandboxed Headless Browser Content Inspection:** Run live URLs inside an isolated Docker container with headless Chromium to extract HTML/DOM features safely without host risk.
3. **Deep Learning Sequence Models:** Incorporate character-level Convolutional Neural Networks (CNN) or Bidirectional LSTMs for raw URL character embedding analysis.
4. **Real-Time Threat Intelligence Integration:** Query live PhishTank or VirusTotal REST APIs asynchronously to complement ML predictions.

---

## 16. Conclusion

This project successfully demonstrates the design and implementation of an **AI-Based Phishing URL Detection System** for college mini-project requirements. By combining Weka's powerful Random Forest ensemble classifier with a feature extraction engine and a responsive Java Swing interface, the application bridges theoretical machine learning with practical, defensive cybersecurity engineering.

---

## 17. References

1. Mohammad, R. M., Thabtah, F., & McCluskey, L. (2012). *An Assessment of Features Related to Phishing Websites using an Automated Approach.* International Conference on Internet Technology and Secured Transactions (ICITST).
2. Mohammad, R. M., Thabtah, F., & McCluskey, L. (2014). *Predicting Phishing Websites based on Self-Structuring Neural Network.* Neural Computing and Applications, 25(2), 443-458.
3. UCI Machine Learning Repository: *Phishing Websites Dataset*. University of California, Irvine.
4. Breiman, L. (2001). *Random Forests.* Machine Learning, 45(1), 5-32.
5. Hall, M., Frank, E., Holmes, G., Pfahringer, B., Reutemann, P., & Witten, I. H. (2009). *The WEKA Data Mining Software: An Update.* ACM SIGKDD Explorations Newsletter, 11(1), 10-18.
