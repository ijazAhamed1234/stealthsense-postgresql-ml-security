import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier

from feature_extractor import extract_features

data=pd.read_csv(

"../data/train.csv"

)

features=[]

for q in data["query"]:

    features.append(

        extract_features(q)

    )

X=pd.DataFrame(features)

y=data["label"]

model=RandomForestClassifier(

n_estimators=300,

random_state=42,

class_weight="balanced"

)

model.fit(

X,

y

)

joblib.dump(

model,

"../models/model.pkl"

)

print(

"Training Complete"

)