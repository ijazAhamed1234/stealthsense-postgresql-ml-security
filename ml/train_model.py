import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

data = pd.read_csv("train.csv")

X = data[["length","digits","conditions","has_where"]]

model = IsolationForest(n_estimators=100, contamination=0.2)

model.fit(X)

joblib.dump(model,"model.pkl")

print("Model trained")