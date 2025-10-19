#!/usr/bin/env python3

import pickle
import pandas as pd

from sklearn.preprocessing import TargetEncoder, StandardScaler

class Classifier:
    """
    Classify individual DNS packets using stateless features
    """
    def __init__(self, data_path, encoder_path, model_path):
        self.data_path = data_path
        self.encoder_path = encoder_path
        self.model_path = model_path
        self.data = None
        self.timestamp = None
        self.src_ip = None
        self.encoded_data = None
        self.scaled_data = None
        self.benign_count = 0
        self.malicious_count = 0
        self.ratios = {}

    def load_data(self):
        self.data = pd.read_csv(self.data_path)
        self.timestamp = self.data['timestamp']
        self.src_ip = self.data['src_ip']
        self.data = self.data.drop(['timestamp', 'src_ip'], axis=1)

    def encode_features(self):
        with open(self.encoder_path, 'rb') as f:
            encoder = pickle.load(f)
        categorical_columns = self.data.select_dtypes(include='object').columns
        self.data[categorical_columns] = encoder.transform(self.data[categorical_columns])

    def scale_features(self):
        scaler = StandardScaler()
        self.data = scaler.fit_transform(self.data)

    def load_model(self):
        with open(self.model_path, 'rb') as f:
            self.model = pickle.load(f)

    def predict(self):
        self.predictions = self.model.predict(self.data)

    def calculate_stats(self):
        self.benign_count = (self.predictions == 0).sum()
        self.malicious_count = (self.predictions == 1).sum()
        packet_count = len(self.predictions)
        self.ratios = {
            'benign_ratio': self.benign_count / packet_count,
            'benign_count': self.benign_count,
            'malicious_ratio': self.malicious_count / packet_count,
            'malicious_count': self.malicious_count,
        }

    def get_results_df(self):
        df = pd.concat([self.timestamp, self.src_ip], axis=1)
        preds = pd.Series(self.predictions, name='predictions')
        df['predictions'] = preds

        return df

    def run(self):
        self.load_data()
        self.encode_features()
        self.scale_features()
        self.load_model()
        self.predict()
        self.calculate_stats()

        return self.ratios, self.get_results_df()

def main():
    data = '../../../data/DNS/stateless/stateless.csv'
    encoder = '../../../encoders/DNS/stateless/DNS_stateless_encoder.pkl'
    model = 'XGB_stateless.pkl'
    
    classifier = Classifier(data, encoder, model)

    ratios, results_df = classifier.run()
    
    print(ratios)
    print(results_df)

if __name__ == "__main__":
    main()
