#!/usr/bin/env python3

import pickle
import pandas as pd

from sklearn.preprocessing import TargetEncoder, StandardScaler

# Read stateless data
data_dir = '../../../data/DNS/stateless/stateless.csv'
data = pd.read_csv(data_dir)

encoder_dir = '../../../encoders/DNS/stateless'
encoder = pickle.load(open(f'{encoder_dir}/DNS_stateless_encoder.pkl', 'rb'))

timestamp = data['timestamp']
src_ip = data['src_ip']

data.drop(['timestamp', 'src_ip'], axis=1, inplace=True)

categorical_columns = data.select_dtypes(include='object').columns

data[categorical_columns] = encoder.transform(data[categorical_columns])

scaler = StandardScaler()

data = scaler.fit_transform(data)

model = pickle.load(open('XGB_stateless.pkl', 'rb'))

predictions = model.predict(data)

benign_count, malicious_count = [0 for x in range(2)]

for prediction in predictions:
    if prediction == 0: # Benign predictions
        benign_count += 1
    elif prediction == 1: # Malicious predictions
        malicious_count += 1

packet_count = len(predictions)

tau = malicious_count / packet_count

df = pd.concat([timestamp, src_ip], axis=1)

preds = pd.Series(predictions)
df['predictions'] = preds

print(f"Benign ratio: {benign_count / packet_count}, Benign packet count: {benign_count}")
print(f"Malicious ratio: {tau}, Malicious packet count: {malicious_count}")
print(df)
