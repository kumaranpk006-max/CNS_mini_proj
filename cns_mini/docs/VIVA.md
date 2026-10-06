# Viva Preparation Guide & Oral Defense Questions

**Project Title:** AI-Based Phishing URL Detection System Using Machine Learning  
**Student:** 3rd Year B.Tech — Artificial Intelligence and Data Science  
**Technology:** Java 24, Weka 3.8.6, Java Swing, Random Forest  

This guide contains **26 essential viva-voce questions and answers** prepared specifically for your college project review and external lab viva examination. The answers are written in clear, spoken English so you can explain them confidently to your professors and external examiners.

---

### 1. What is phishing?
**Answer:**  
Phishing is a form of social engineering cyberattack where an attacker pretends to be a trustworthy entity—such as a bank, an e-commerce platform, or a government portal—to trick users into revealing sensitive information like passwords, credit card numbers, or OTPs.

---

### 2. What is a phishing URL?
**Answer:**  
A phishing URL is a malicious web address designed to mimic a legitimate website. It often uses tricks like typosquatting (e.g., `paypa1.com` instead of `paypal.com`), IP addresses in place of domain names, excessive subdomains, or URL shortening services to hide the attacker's true destination.

---

### 3. Why did you choose this project?
**Answer:**  
Phishing is the number one entry point for cybersecurity breaches worldwide. Traditional blacklist approaches fail against newly registered, zero-day phishing sites. As an AI & Data Science student, I wanted to apply machine learning to build an intelligent, proactive defense system that can detect malicious URLs in real time based on learned structural characteristics.

---

### 4. Why did you choose Java for implementation?
**Answer:**  
Java provides three major advantages:
1. **Platform Independence:** "Write Once, Run Anywhere" via the Java Virtual Machine (JVM).
2. **Strong Typing & Enterprise Reliability:** Safe memory management and robust error handling.
3. **Seamless Native GUI & ML Integration:** Java provides Java Swing for desktop user interfaces and integrates natively with Weka, allowing the entire desktop application to run as a single, self-contained desktop system without requiring Python or external runtime bridges.

---

### 5. Why Weka?
**Answer:**  
Weka (Waikato Environment for Knowledge Analysis) is a mature, gold-standard Java machine learning library developed by the University of Waikato. It offers production-tested implementations of algorithms like Random Forest, built-in ARFF format parsers, and evaluation metrics (ROC-AUC, Precision, Recall, Confusion Matrix) that can be integrated directly into Java code via clean API calls.

---

### 6. Why did you choose Random Forest as your primary algorithm?
**Answer:**  
Random Forest was chosen because:
- It is an ensemble method combining multiple decision trees (we used 100 trees), which dramatically reduces variance and prevents overfitting.
- It naturally handles non-linear interactions between categorical features (such as combining HTTPS status with subdomain counts and domain hyphens).
- It achieved an outstanding **97.56% accuracy** and **0.9931 ROC-AUC** on our unseen test dataset.

---

### 7. What is Machine Learning?
**Answer:**  
Machine Learning is a branch of Artificial Intelligence where computer algorithms learn patterns and rules directly from historical data, allowing them to make predictions or decisions on new, unseen data without being explicitly programmed with hardcoded rules for every scenario.

---

### 8. What is classification in Machine Learning?
**Answer:**  
Classification is a supervised learning task where the target output variable is categorical (discrete classes). In our project, it is a **binary classification problem** because the model assigns each input URL to one of two categories: `LEGITIMATE` or `PHISHING`.

---

### 9. What is an attribute?
**Answer:**  
An attribute is a distinct property, characteristic, or column in a dataset. For example, `URL_Length`, `having_IP_Address`, and `SSLfinal_State` are input attributes in our ARFF dataset.

---

### 10. What is a feature?
**Answer:**  
A feature is a quantifiable, measurable property extracted from raw input data used by a machine learning model to make predictions. In our project, raw URL strings are converted into 30 numerical features (`-1`, `0`, `1`) before being passed into the Random Forest classifier.

---

### 11. What is the target attribute (class attribute)?
**Answer:**  
The target attribute is the dependent variable that the machine learning model is trained to predict. In our dataset, the target attribute is **`Result`**, which has two possible values:
- `1` = Legitimate website
- `-1` = Phishing website

---

### 12. What is an ARFF file?
**Answer:**  
ARFF stands for **Attribute-Relation File Format**. It is an ASCII text format developed for Weka that describes a list of instances sharing a common set of attributes. An ARFF file has two main sections:
1. **Header:** Defines the `@relation` name and list of `@attribute` names and data types (e.g. nominal sets like `{ -1, 1 }`).
2. **Data:** Starts with `@data` followed by comma-separated instance records.

---

### 13. What is training data?
**Answer:**  
Training data is the subset of the dataset (we used 80%, or 8,844 instances) used by the machine learning algorithm to learn patterns, tree splits, and relationships between features and the target class.

---

### 14. What is testing data?
**Answer:**  
Testing data is an independent subset of the dataset (we used 20%, or 2,211 instances) that the model has **never seen during training**. It is used exclusively to evaluate the true generalization performance of the model on real-world data.

---

### 15. What is a train-test split and why is it important?
**Answer:**  
Train-test split is the process of dividing a dataset into separate training and testing subsets. It is crucial to prevent **data leakage** and ensure that we evaluate the model on unseen data. We also used **stratification** and a fixed seed (`seed = 42`) to guarantee that the ratio of phishing to legitimate instances remained identical in both subsets.

---

### 16. How does Random Forest work internally?
**Answer:**  
Random Forest works through two core techniques:
1. **Bagging (Bootstrap Aggregation):** It builds $N$ individual decision trees (we used 100). Each tree is trained on a random sample of the training data drawn with replacement.
2. **Random Subspace Method:** At each split node in a tree, only a random subset of features is considered, ensuring diversity among the trees.  
During prediction, every tree votes for a class, and the forest outputs the class receiving the majority vote, or averages the probabilities across all trees.

---

### 17. What is overfitting and how do you prevent it?
**Answer:**  
Overfitting occurs when a machine learning model learns the training data too closely—including noise and random quirks—resulting in high training accuracy but poor performance on new test data. Random Forest naturally prevents overfitting by averaging the predictions of 100 independently trained randomized decision trees.

---

### 18. What is Accuracy?
**Answer:**  
Accuracy is the ratio of correctly classified instances to the total number of instances:
$$\text{Accuracy} = \frac{\text{True Positives} + \text{True Negatives}}{\text{Total Instances}}$$
In our model, accuracy on the unseen test set is **97.56%** (2,157 out of 2,211 correct).

---

### 19. What is Precision?
**Answer:**  
Precision is the ratio of correctly predicted positive observations to the total predicted positives:
$$\text{Precision} = \frac{\text{True Positives}}{\text{True Positives} + \text{False Positives}}$$
For phishing detection, precision answers: *"Of all URLs that our model flagged as Phishing, how many were actually phishing?"* Our model achieved **98.13% Precision for Phishing**.

---

### 20. What is Recall (Sensitivity)?
**Answer:**  
Recall is the ratio of correctly predicted positive observations to all actual observations in that class:
$$\text{Recall} = \frac{\text{True Positives}}{\text{True Positives} + \text{False Negatives}}$$
For phishing detection, recall answers: *"Of all actual phishing URLs, what percentage did our system successfully catch?"* Our model achieved **96.32% Recall for Phishing** (catching 942 out of 978 attacks).

---

### 21. What is F1-Score?
**Answer:**  
F1-Score is the harmonic mean of Precision and Recall:
$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
It is particularly useful because it provides a single balanced metric that penalizes extreme imbalances between precision and recall. Our model achieved an **F1-Score of 0.9721 for Phishing** and a weighted average of **0.9756**.

---

### 22. What is a Confusion Matrix?
**Answer:**  
A confusion matrix is a table that visualizes the performance of a classification algorithm by comparing actual ground truth labels against predicted labels:

| Actual \ Predicted | Predicted Phishing (`-1`) | Predicted Legitimate (`1`) |
| :--- | :---: | :---: |
| **Actual Phishing (`-1`)** | **942 (True Positives)** | **36 (False Negatives)** |
| **Actual Legitimate (`1`)** | **18 (False Positives)** | **1,215 (True Negatives)** |

---

### 23. What are False Positives in our project?
**Answer:**  
A False Positive occurs when a **legitimate website is mistakenly flagged as Phishing**. In our test results, this occurred 18 times (0.8% rate). In practice, this causes minor user inconvenience (e.g., an unnecessary warning prompt).

---

### 24. What are False Negatives, and why are they far more critical than False Positives?
**Answer:**  
A False Negative occurs when a **malicious phishing website is mistakenly classified as Legitimate**. In our test results, this occurred 36 times (1.6% rate).  
**Why Critical:** In cybersecurity, false negatives represent a direct security breach. If a user trusts a missed phishing URL, they will enter their credentials or banking data, leading to identity theft or financial loss. Therefore, minimizing False Negatives (maximizing Recall) is the primary defensive priority.

---

### 25. What are the limitations of this project?
**Answer:**  
1. **Offline URL Scope:** Because the system operates defensively without downloading remote web pages or running arbitrary JavaScript, DOM-level features rely on safe defensive baselines when evaluated offline.
2. **Shortened URLs:** The system detects URL shorteners like `bit.ly` as suspicious, but finding the ultimate destination without following HTTP redirects across the network is limited.
3. **Novel Evasion Techniques:** Sophisticated attackers who compromise established legitimate websites or use advanced homograph characters can occasionally mimic legitimate feature profiles.

---

### 26. What future enhancements can be added to this project?
**Answer:**  
1. **Browser Extension:** Integrate the detection model into a Google Chrome or Mozilla Firefox extension to scan URLs in real time as the user types.
2. **Containerized Headless Browser Sandbox:** Use headless Chromium inside an isolated Docker container to scrape HTML/DOM features safely without exposing the user's host OS.
3. **Deep Learning Character Embeddings:** Use character-level BiLSTM or 1D-CNN networks to capture subtle sub-word anomalies in raw URL character sequences.
4. **Live Threat Intelligence APIs:** Asynchronously query live feeds like PhishTank or VirusTotal to complement the machine learning prediction.
