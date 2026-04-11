import sys
import re
import joblib
import pandas as pd
import warnings

warnings.filterwarnings("ignore")

model = joblib.load("/home/hp/stealthsense/ml/model.pkl")

query = sys.argv[1].lower()

X = pd.DataFrame([{
    "length": len(query),
    "digits": len(re.findall(r'\d+',query)),
    "conditions": query.count("="),
    "has_where": 1 if "where" in query else 0
}])

pred = model.predict(X)

print(1 if pred[0] == -1 else 0)