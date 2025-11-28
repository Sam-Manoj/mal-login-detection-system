from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
import os

# pgmpy imports
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.estimators import BayesianEstimator
from pgmpy.inference import VariableElimination

# sklearn for discretization
from sklearn.preprocessing import KBinsDiscretizer

# 1) Synthetic data generator
def make_synthetic_data(n=2000, seed = 42) -> pd.DataFrame:
    """Generate a fake labeled dataset mimicking login attempts."""
    rng = np.random.default_rng(seed)

    # Base rate for malicious attempts
    malicious_prob = 0.05
    malicious = rng.random(n) < malicious_prob

    # ip_risk: 0=low,1=med,2=high
    ip_risk = []
    device_unknown = []
    time_dev = []    # hours deviation buckets: 0=low,1=med,2=high
    velocity = []    # 0=normal,1=fast,2=impossible
    failed_attempts = []

    for m in malicious:
        if m:
            # malicious: more likely high risk ip, unknown device, large time dev, impossible velocity, many fails
            ip_risk.append(rng.choice([1, 2], p=[0.3, 0.7]))
            device_unknown.append(rng.choice([0, 1], p=[0.2, 0.8]))
            time_dev.append(rng.choice([1, 2], p=[0.4, 0.6]))
            velocity.append(rng.choice([1, 2], p=[0.3, 0.7]))
            failed_attempts.append(rng.choice([1, 2], p=[0.2, 0.8]))
        else:
            # benign: likely low ip risk, known device, low time deviation, normal velocity, few fails
            ip_risk.append(rng.choice([0, 1], p=[0.8, 0.2]))
            device_unknown.append(rng.choice([0, 1], p=[0.95, 0.05]))
            time_dev.append(rng.choice([0, 1], p=[0.9, 0.1]))
            velocity.append(rng.choice([0, 1], p=[0.98, 0.02]))
            failed_attempts.append(rng.choice([0, 1], p=[0.95, 0.05]))

    df = pd.DataFrame({
        'malicious': malicious.astype(int),
        'ip_risk': ip_risk,
        'device_unknown': device_unknown,
        'time_dev': time_dev,
        'velocity': velocity,
        'failed_attempts': failed_attempts
    })

    return df

# -------------------------
# 2) Preprocessing & discretization helpers
# -------------------------
def discretize_numeric_series(series: pd.Series, n_bins=3, strategy='quantile') -> pd.Series:
    """Discretize numeric pandas Series into integer bins 0..n_bins-1."""
    kb = KBinsDiscretizer(n_bins=n_bins, encode='ordinal', strategy=strategy)
    arr = series.to_numpy().reshape(-1, 1)
    # KBinsDiscretizer requires finite values
    arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
    binned = kb.fit_transform(arr).astype(int).ravel()
    return pd.Series(binned, index=series.index)

def prepare_and_discretize(df: pd.DataFrame, numeric_cols: dict = None) -> pd.DataFrame:
    """
    Convert raw dataframe to categorical/discrete values expected by the BN.
    """
    df = df.copy()
    if numeric_cols:
        for col, bins in numeric_cols.items():
            if col in df.columns:
                df[col] = discretize_numeric_series(df[col], n_bins=bins)
    for c in df.columns:
        if df[c].dtype == 'bool':
            df[c] = df[c].astype(int)
    df = df.dropna().astype(int)

    return df

# -------------------------
# 3) Bayesian Network: structure + training
# -------------------------
def get_default_model_structure() -> DiscreteBayesianNetwork:
    """
    Returns a default BN structure (star centered on 'malicious').
    """
    edges = [
        ('malicious', 'ip_risk'),
        ('malicious', 'device_unknown'),
        ('malicious', 'time_dev'),
        ('malicious', 'velocity'),
        ('malicious', 'failed_attempts'),
    ]
    model = DiscreteBayesianNetwork(edges)
    return model



def train_bn(df: pd.DataFrame, model: DiscreteBayesianNetwork = None) -> Tuple[DiscreteBayesianNetwork, VariableElimination]:
    """
    Train the Bayesian network from a prepared categorical DataFrame.
    Returns the fitted model and a pgmpy inference object (VariableElimination).
    """
    if model is None:
        model = get_default_model_structure()

    model.fit(df, estimator=BayesianEstimator)

    infer = VariableElimination(model)
    return model, infer

# -------------------------
# 4) Scoring function
# -------------------------
def score_evidence(infer: VariableElimination, evidence: Dict[str, Any]) -> float:
    """
    evidence: dict mapping variable -> observed categorical value (int or str)
    Returns P(malicious=1 | evidence)
    """
    q = infer.query(variables=['malicious'], evidence=evidence, show_progress=False)
    state_names = q.state_names.get('malicious')
    try:
        if state_names is not None:
            idx = list(state_names).index(1) if 1 in list(state_names) else 1
        else:
            idx = 1
    except Exception:
        idx = 1
    prob_malicious = float(q.values[idx])
    return prob_malicious

# -------------------------
# 5) Example flow (train and score)
# -------------------------
if __name__ == '__main__':
    
    # --- THIS BLOCK CREATES YOUR CSV FILE ---
    
    # Define the target CSV file name
    csv_filename = 'synthetic_dataset_for_training.csv'
    
    # 1) Make synthetic dataset
    print(f"Generating 3000 rows of synthetic data for '{csv_filename}'...")
    df = make_synthetic_data(3000)

    # 2) Prepare
    df_prep = prepare_and_discretize(df)
    
    # 3) Save the prepared data to the CSV file
    try:
        df_prep.to_csv(csv_filename, index=False)
        print(f"Successfully saved synthetic data to '{csv_filename}'")
        print("You can now run APP.PY")
    except Exception as e:
        print(f"ERROR: Could not save CSV file. {e}")
        print("Please check folder permissions.")
        
    print("-" * 30)
    print("Running self-test on the new data...")
    # --- END OF NEW BLOCK ---

    # 4) Create & train BN for self-test
    model = get_default_model_structure()
    # Use the 'df_prep' we just made for the test
    fitted_model, infer = train_bn(df_prep, model) 

    # Scenario A: A highly suspicious login attempt
    evidence_malicious = {
        'ip_risk': 2,
        'device_unknown': 0,
        'time_dev': 1,
        'velocity': 0,
        'failed_attempts': 1
    }
    p_malicious = score_evidence(infer, evidence_malicious)
    print(f"P(malicious=1 | suspicious evidence) = {p_malicious:.4f}")

    # Scenario B: A normal, benign login attempt
    evidence_safe = {
        'ip_risk': 0,
        'device_unknown': 0,
        'time_dev': 0,
        'velocity': 0,
        'failed_attempts': 0
    }
    p_benign = score_evidence(infer, evidence_safe)
    print(f"P(malicious=1 | benign evidence) = {p_benign:.4f}")
    print("Self-test complete.")