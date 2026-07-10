import os
import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

logger = logging.getLogger('flask.app')

class NIDSModel:
    def __init__(self, model_path):
        self.model_path = model_path
        self.model = None
        self.features = ['protocol', 'src_port', 'dst_port', 'packet_size', 'tcp_flags']
        self._load_or_train_model()

    def _load_or_train_model(self):
        """Loads the pre-trained model or trains a new one if not found."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Successfully loaded model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model from {self.model_path}: {e}")
                logger.info("Falling back to training a new synthetic model...")
                self._train_synthetic_model()
        else:
            logger.info(f"Model not found at {self.model_path}. Training synthetic model inline.")
            self._train_synthetic_model()

    def _train_synthetic_model(self):
        """Generates synthetic network data and trains a RandomForest model."""
        logger.info("Generating synthetic training data...")
        
        # 1 = Anomalous/Malicious, 0 = Normal
        
        # Normal Traffic (e.g., standard web browsing)
        num_normal = 1000
        normal_data = {
            'protocol': np.random.choice([6, 17], num_normal, p=[0.8, 0.2]), # Mostly TCP
            'src_port': np.random.randint(1024, 65535, num_normal), # High ports for source
            'dst_port': np.random.choice([80, 443, 53], num_normal, p=[0.4, 0.5, 0.1]),
            'packet_size': np.random.normal(800, 200, num_normal).astype(int), # Average size
            'tcp_flags': np.random.choice([2, 16, 24], num_normal), # SYN, ACK, PSH+ACK
            'label': 0
        }
        
        # Anomalous Traffic (e.g., port scans, abnormally large packets)
        num_anomalous = 300
        anomalous_data = {
            'protocol': np.random.choice([6, 17, 1], num_anomalous, p=[0.6, 0.2, 0.2]), # TCP, UDP, ICMP
            'src_port': np.random.randint(1, 1024, num_anomalous), # Source from privileged ports (suspicious)
            'dst_port': np.random.randint(1, 10000, num_anomalous), # Scanning many ports
            'packet_size': np.concatenate([np.random.normal(40, 5, 150), np.random.normal(5000, 500, 150)]).astype(int), # Tiny or huge
            'tcp_flags': np.random.choice([0, 1, 41], num_anomalous), # NULL, FIN, SYN+FIN+URG (weird flags)
            'label': 1
        }
        
        df_normal = pd.DataFrame(normal_data)
        df_anomalous = pd.DataFrame(anomalous_data)
        df = pd.concat([df_normal, df_anomalous], ignore_index=True)
        
        # Ensure positive sizes
        df['packet_size'] = df['packet_size'].clip(lower=20)
        
        X = df[self.features]
        y = df['label']
        
        logger.info("Training RandomForestClassifier on synthetic data...")
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Save model
        joblib.dump(self.model, self.model_path)
        logger.info(f"Successfully trained and saved synthetic model to {self.model_path}")

    def predict(self, packet_data_list):
        """
        Predicts whether packets are normal or anomalous.
        
        Args:
            packet_data_list (list): List of dictionaries from pcap_parser.
            
        Returns:
            list: The original list augmented with 'is_anomalous' and 'confidence' keys.
        """
        if not packet_data_list:
            return []
            
        # Convert list of dicts to DataFrame for prediction
        df = pd.DataFrame(packet_data_list)
        
        # Ensure all required features exist for the model
        for feature in self.features:
            if feature not in df.columns:
                df[feature] = 0
                
        # Extract just the features needed for the model
        X = df[self.features]
        
        # Predict class and probabilities
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        results = []
        for i, pkt in enumerate(packet_data_list):
            result_pkt = pkt.copy()
            pred_class = int(predictions[i])
            
            # Confidence is the probability of the predicted class
            confidence = float(probabilities[i][pred_class])
            
            result_pkt['is_anomalous'] = bool(pred_class == 1)
            result_pkt['confidence'] = round(confidence * 100, 2)
            results.append(result_pkt)
            
        return results
