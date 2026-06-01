import sys
import os
import pandas as pd
import joblib

from feature_extractor import extract_features
from whitelist import allowed
from frequency import query_frequency
from risk_score import risk_score

# Determine the absolute directory containing detect.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL = os.path.join(BASE_DIR, "../models/model.pkl")

model=joblib.load(MODEL)


query = sys.argv[1] if len(sys.argv) > 1 else ""

user = sys.argv[2] if len(sys.argv) > 2 else "unknown"

ip = sys.argv[3] if len(sys.argv) > 3 else "unknown"


features=extract_features(

query

)

X=pd.DataFrame([features])

prediction=model.predict(X)[0]

# ml_score is the probability of the query being malicious (class 1)
ml_score = model.predict_proba(X)[0][1] * 100

keyword_score=min(

features["keyword_hits"]*10,

100

)

freq=query_frequency(

query,

user

)

ip_score=0 if allowed(ip) else 100

complexity=min(

features["multiple_queries"]*20+

features["joins"]*10,

100

)

risk=risk_score(

ml_score,

keyword_score,

freq,

ip_score,

complexity

)

if freq >= 100:

    risk = 100

LOG_FILE = os.path.join(BASE_DIR, "../../logs/detections.log")

with open(

LOG_FILE,

"a"

) as f:

    f.write(

f"{query} risk={risk}\n"

)

if risk > 30:

    print(1)

else:

    print(0)