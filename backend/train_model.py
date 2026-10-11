"""
PhishGuard - Model Training Script
College CSE Mini Project: Phishing Website Detection System

Trains a Random Forest Classifier on extracted URL lexical and structural features.
Calculates Accuracy, Precision, Recall, F1-Score, and Confusion Matrix.
Saves the trained model to phishing_model.pkl and phishing_model.json.
"""

import os
import csv
import json
import math
import random
import pickle
from feature_extractor import extract_features, FEATURE_NAMES

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "phishing_urls.csv")
MODEL_PKL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
MODEL_JSON_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.json")


def load_and_extract_data(filepath: str):
    """Loads CSV and extracts features for every URL."""
    X = []
    y = []
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found at {filepath}")

    with open(filepath, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row["url"].strip()
            label = int(row["label"].strip())
            
            ext = extract_features(url)
            f_dict = ext["features"]
            row_features = [f_dict[name] for name in FEATURE_NAMES]
            
            X.append(row_features)
            y.append(label)

    return X, y


def evaluate_predictions(y_true, y_pred):
    """Calculates evaluation metrics: accuracy, precision, recall, f1, confusion matrix."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    cm = {
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "true_positive": tp
    }

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
        "total_samples": total
    }


class PurePythonDecisionTree:
    """Lightweight single decision tree for portable standalone execution."""
    def __init__(self, max_depth=6, min_samples_split=2):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.tree = None

    def _gini(self, y):
        m = len(y)
        if m == 0:
            return 0
        p1 = sum(y) / m
        p0 = 1 - p1
        return 1.0 - (p0**2 + p1**2)

    def _best_split(self, X, y):
        best_gain = 0
        best_feature = None
        best_threshold = None
        current_gini = self._gini(y)
        n_features = len(X[0])

        for feat in range(n_features):
            values = sorted(set(x[feat] for x in X))
            for i in range(len(values) - 1):
                thresh = (values[i] + values[i+1]) / 2.0
                left_y = [y[j] for j, x in enumerate(X) if x[feat] <= thresh]
                right_y = [y[j] for j, x in enumerate(X) if x[feat] > thresh]

                if not left_y or not right_y:
                    continue

                p_l = len(left_y) / len(y)
                p_r = len(right_y) / len(y)
                gain = current_gini - (p_l * self._gini(left_y) + p_r * self._gini(right_y))

                if gain > best_gain:
                    best_gain = gain
                    best_feature = feat
                    best_threshold = thresh

        return best_feature, best_threshold

    def _build(self, X, y, depth=0):
        if not y:
            return {"leaf": True, "prob": 0.0}
        prob = sum(y) / len(y)

        if depth >= self.max_depth or len(y) < self.min_samples_split or self._gini(y) == 0:
            return {"leaf": True, "prob": prob}

        feat, thresh = self._best_split(X, y)
        if feat is None:
            return {"leaf": True, "prob": prob}

        left_idx = [i for i, x in enumerate(X) if x[feat] <= thresh]
        right_idx = [i for i, x in enumerate(X) if x[feat] > thresh]

        left_X = [X[i] for i in left_idx]
        left_y = [y[i] for i in left_idx]
        right_X = [X[i] for i in right_idx]
        right_y = [y[i] for i in right_idx]

        return {
            "leaf": False,
            "feature": feat,
            "feature_name": FEATURE_NAMES[feat],
            "threshold": thresh,
            "left": self._build(left_X, left_y, depth + 1),
            "right": self._build(right_X, right_y, depth + 1)
        }

    def fit(self, X, y):
        self.tree = self._build(X, y)

    def predict_proba_sample(self, node, x):
        if node["leaf"]:
            return node["prob"]
        if x[node["feature"]] <= node["threshold"]:
            return self.predict_proba_sample(node["left"], x)
        else:
            return self.predict_proba_sample(node["right"], x)


class PurePythonRandomForest:
    """Pure Python Random Forest ensemble providing seamless cross-platform execution."""
    def __init__(self, n_estimators=15, max_depth=6, random_state=42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.trees = []

    def fit(self, X, y):
        random.seed(self.random_state)
        n_samples = len(X)
        self.trees = []
        for i in range(self.n_estimators):
            # Bootstrap sampling
            indices = [random.randint(0, n_samples - 1) for _ in range(n_samples)]
            X_boot = [X[idx] for idx in indices]
            y_boot = [y[idx] for idx in indices]
            
            tree = PurePythonDecisionTree(max_depth=self.max_depth)
            tree.fit(X_boot, y_boot)
            self.trees.append(tree)

    def predict_proba(self, X):
        probs = []
        for x in X:
            tree_probs = [t.predict_proba_sample(t.tree, x) for t in self.trees]
            avg_prob = sum(tree_probs) / len(tree_probs)
            probs.append(avg_prob)
        return probs

    def predict(self, X):
        return [1 if p >= 0.5 else 0 for p in self.predict_proba(X)]

    def to_dict(self):
        return {
            "type": "RandomForestClassifier",
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "feature_names": FEATURE_NAMES,
            "trees": [t.tree for t in self.trees]
        }


def train():
    print("=" * 60)
    print("PhishGuard - Random Forest Model Training Pipeline")
    print("=" * 60)

    print(f"Loading dataset from: {DATASET_PATH}")
    X, y = load_and_extract_data(DATASET_PATH)
    print(f"Loaded {len(X)} samples with {len(FEATURE_NAMES)} features each.")

    # Train-test split (80% train, 20% test)
    combined = list(zip(X, y))
    random.seed(42)
    random.shuffle(combined)
    split_idx = int(len(combined) * 0.8)

    train_data = combined[:split_idx]
    test_data = combined[split_idx:]

    X_train, y_train = zip(*train_data)
    X_test, y_test = zip(*test_data)
    X_train, y_train = list(X_train), list(y_train)
    X_test, y_test = list(X_test), list(y_test)

    print(f"Training set: {len(X_train)} samples | Testing set: {len(X_test)} samples")

    model_trained = None
    metrics = None

    # Check if scikit-learn is installed
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        import joblib

        print("\nTraining using scikit-learn RandomForestClassifier...")
        clf = RandomForestClassifier(n_estimators=100, max_depth=7, random_state=42)
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        metrics = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": {
                "true_negative": int(cm[0][0]),
                "false_positive": int(cm[0][1]),
                "false_negative": int(cm[1][0]),
                "true_positive": int(cm[1][1])
            },
            "framework": "scikit-learn"
        }

        # Save model via joblib / pickle
        joblib.dump(clf, MODEL_PKL_PATH)
        print(f"Model saved to {MODEL_PKL_PATH} using joblib.")

    except ImportError:
        print("\nscikit-learn not detected in current environment. Training portable Random Forest...")
        rf = PurePythonRandomForest(n_estimators=25, max_depth=6, random_state=42)
        rf.fit(X_train, y_train)

        y_pred = rf.predict(X_test)
        metrics = evaluate_predictions(y_test, y_pred)
        metrics["framework"] = "pure-python-ensemble"

        # Save model with pickle
        with open(MODEL_PKL_PATH, "wb") as f:
            pickle.dump(rf, f)
        print(f"Portable Random Forest model saved to {MODEL_PKL_PATH}.")

        # Export JSON representation
        with open(MODEL_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "model": rf.to_dict(),
                "metrics": metrics,
                "feature_names": FEATURE_NAMES
            }, f, indent=2)
        print(f"Model metadata & tree structures exported to {MODEL_JSON_PATH}.")

    # Save metrics JSON for dashboard inspection
    metrics_path = os.path.join(os.path.dirname(__file__), "model_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\n--- Model Evaluation Results ---")
    print(f"Accuracy:  {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision: {metrics['precision'] * 100:.2f}%")
    print(f"Recall:    {metrics['recall'] * 100:.2f}%")
    print(f"F1-Score:  {metrics['f1_score'] * 100:.2f}%")
    print("Confusion Matrix:")
    print(f"  TN: {metrics['confusion_matrix']['true_negative']}, FP: {metrics['confusion_matrix']['false_positive']}")
    print(f"  FN: {metrics['confusion_matrix']['false_negative']}, TP: {metrics['confusion_matrix']['true_positive']}")
    print("=" * 60)
    print("Training Complete!\n")
    return metrics


if __name__ == "__main__":
    train()
