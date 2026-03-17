import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder
import warnings
warnings.filterwarnings('ignore')

class LiveIDSPredictor:
    def __init__(self, model_path="models/best_ids_model.pkl"):
        """
        Initialize the Live IDS Prediction System
        
        Args:
            model_path: Path to your saved best model
        """
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.is_loaded = False
        
        # Expected feature names from your training
        self.expected_features = [
            'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
            'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate'
        ]
        
        self.load_model_components()
    
    def load_model_components(self):
        """Load all model components saved during training"""
        try:
            print("🔄 Loading model components...")
            
            # Load the best model
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print(f"✅ Modelo Categories: {type(self.model).__name__}")
            else:
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            # Load scaler
            if os.path.exists('models/feature_scaler.pkl'):
                self.scaler = joblib.load('models/feature_scaler.pkl')
                print("✅ Loaded feature scaler")
            else:
                print("⚠️  Scaler not found, scaling will be skipped")
            
            # Load label encoder
            if os.path.exists('models/label_encoder.pkl'):
                self.label_encoder = joblib.load('models/label_encoder.pkl')
                print("✅ Label encoder loaded")
                print(f"   Attack Categories: {list(self.label_encoder.classes_)}")
            else:
                print("⚠️  Label encoder not found")
            
            # Load feature names
            if os.path.exists('models/selected_features.pkl'):
                self.feature_names = joblib.load('models/selected_features.pkl')
                print(f"✅ Loaded function names: {len(self.feature_names)} features")
            else:
                self.feature_names = self.expected_features
                print("⚠️  Using default feature names")
            
            self.is_loaded = True
            print("🎯 Model system ready for predictions!")
            
        except Exception as e:
            print(f"❌ Error loading model components: {e}")
            self.is_loaded = False
    
    def preprocess_data(self, data):
        """
        Preprocess input data to match training format
        
        Args:
            data: DataFrame with network traffic features
            
        Returns:
            Preprocessed data ready for prediction
        """
        # Make a copy to avoid modifying original data
        processed_data = data.copy()
        
        # Ensure we have all required features
        missing_features = []
        for feature in self.feature_names:
            if feature not in processed_data.columns:
                processed_data[feature] = 0  # Fill missing features with 0
                missing_features.append(feature)
        
        if missing_features:
            print(f"⚠️  Missing features filled with 0: {missing_features}")
        
        # Select only the features used in training
        processed_data = processed_data[self.feature_names]
        
        # Data cleanup (same as training)
        processed_data = (
            processed_data.fillna(0)
                         .replace([np.inf, -np.inf], 0)
                         .apply(lambda col: pd.to_numeric(col, errors="coerce").fillna(0))
        )
        
        # Apply scaling if scaler is available
        if self.scaler is not None:
            processed_data_scaled = self.scaler.transform(processed_data)
        else:
            processed_data_scaled = processed_data.values
        
        return processed_data_scaled, processed_data
    
    def predict_single_sample(self, features_dict):
        """
        Predict attack category for a single sample
        
        Args:
            features_dict: Dictionary with feature values
            
        Returns:
            Tuple: (predicted_category, confidence, probabilities)
        """
        if not self.is_loaded:
            return "Model not loaded", 0.0, None
        
        # Convert dict to DataFrame
        sample_df = pd.DataFrame([features_dict])
        
        # Preprocess
        processed_data, _ = self.preprocess_data(sample_df)
        
        # Make prediction
        prediction = self.model.predict(processed_data)
        
        # Get probabilities if available
        probabilities = None
        confidence = 1.0
        
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(processed_data)[0]
            confidence = np.max(probabilities)
        
        # Decode prediction
        if self.label_encoder:
            predicted_category = self.label_encoder.inverse_transform(prediction)[0]
        else:
            predicted_category = prediction[0]
        
        return predicted_category, confidence, probabilities
    
    def predict_from_csv(self, csv_file_path, save_results=True):
        """
        Predict attack categories for data from CSV file
        
        Args:
            csv_file_path: Path to CSV file with network traffic data
            save_results: Whether to save results to file
            
        Returns:
            DataFrame with predictions
        """
        if not self.is_loaded:
            print("❌ Model not loaded properly")
            return None
        
        try:
            print(f"📂 Loading data from: {csv_file_path}")
            
            # Load CSV data
            data = pd.read_csv(csv_file_path)
            print(f"✅ Loaded {len(data)} samples with {len(data.columns)} columns")
            
            # Show available columns
            print(f"📋 Available columns: {list(data.columns)}")
            
            # Preprocess data
            print("🔄 Preprocessing data...")
            processed_data, original_features = self.preprocess_data(data)
            
            # Make predictions
            print("🎯 Making predictions...")
            predictions = self.model.predict(processed_data)
            
            # Get probabilities if available
            probabilities = None
            confidences = None
            
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(processed_data)
                confidences = np.max(probabilities, axis=1)
            
            # Decode predictions
            if self.label_encoder:
                predicted_categories = self.label_encoder.inverse_transform(predictions)
            else:
                predicted_categories = predictions
            
            # Create results DataFrame
            results_df = data.copy()
            results_df['predicted_attack_category'] = predicted_categories
            
            if confidences is not None:
                results_df['prediction_confidence'] = confidences
            
            # Add individual category probabilities if available
            if probabilities is not None and self.label_encoder:
                for i, category in enumerate(self.label_encoder.classes_):
                    results_df[f'prob_{category.replace(" ", "_")}'] = probabilities[:, i]
            
            # Generate summary statistics
            category_counts = pd.Series(predicted_categories).value_counts()
            
            print("\n" + "="*60)
            print("PREDICTION RESULTS SUMMARY")
            print("="*60)
            print(f"📊 Total samples processed: {len(data)}")
            print(f"🎯 Predictions completed: {len(predicted_categories)}")
            
            if confidences is not None:
                print(f"🔍 Average confidence: {np.mean(confidences):.3f}")
                print(f"📈 Confidence range: {np.min(confidences):.3f} - {np.max(confidences):.3f}")
            
            print("\n📋 Attack Category Distribution:")
            for category, count in category_counts.items():
                percentage = (count / len(data)) * 100
                print(f"   {category:<30}: {count:>6} ({percentage:>5.1f}%)")
            
            # Threat level assessment
            normal_count = category_counts.get('Normal', 0)
            attack_count = len(data) - normal_count
            threat_percentage = (attack_count / len(data)) * 100
            
            print(f"\n🚨 Threat Assessment:")
            print(f"   Normal traffic: {normal_count} ({100-threat_percentage:.1f}%)")
            print(f"   Attack traffic: {attack_count} ({threat_percentage:.1f}%)")
            
            if threat_percentage > 50:
                threat_level = "🔴 HIGH THREAT"
            elif threat_percentage > 20:
                threat_level = "🟡 MEDIUM THREAT"
            elif threat_percentage > 5:
                threat_level = "🟠 LOW THREAT"
            else:
                threat_level = "🟢 MINIMAL THREAT"
            
            print(f"   Threat Level: {threat_level}")
            
            # Save results if requested
            if save_results:
                output_file = csv_file_path.replace('.csv', '_predictions.csv')
                results_df.to_csv(output_file, index=False)
                print(f"\n💾 Results saved to: {output_file}")
                
                # Save summary statistics
                summary_file = csv_file_path.replace('.csv', '_summary.csv')
                summary_df = pd.DataFrame({
                    'attack_category': category_counts.index,
                    'count': category_counts.values,
                    'percentage': (category_counts.values / len(data) * 100).round(2)
                })
                summary_df.to_csv(summary_file, index=False)
                print(f"📊 Summary saved to: {summary_file}")
            
            return results_df
            
        except Exception as e:
            print(f"❌ Error during prediction: {e}")
            return None
    
    def batch_predict_directory(self, directory_path, file_pattern="*.csv"):
        """
        Predict for all CSV files in a directory
        
        Args:
            directory_path: Directory containing CSV files
            file_pattern: File pattern to match (default: "*.csv")
            
        Returns:
            Dictionary of results for each file
        """
        import glob
        
        if not self.is_loaded:
            print("❌ Model not loaded properly")
            return None
        
        csv_files = glob.glob(os.path.join(directory_path, file_pattern))
        
        if not csv_files:
            print(f"❌ No CSV files found in {directory_path}")
            return None
        
        print(f"📂 Found {len(csv_files)} CSV files to process")
        
        results = {}
        
        for i, csv_file in enumerate(csv_files, 1):
            print(f"\n{'='*60}")
            print(f"Processing file {i}/{len(csv_files)}: {os.path.basename(csv_file)}")
            print('='*60)
            
            result = self.predict_from_csv(csv_file, save_results=True)
            results[csv_file] = result
        
        print(f"\n✅ Batch prediction completed for {len(csv_files)} files")
        return results

# Simple usage functions
def predict_from_file(csv_file_path, model_path="best_ids_model.pkl"):
    """
    Simple function to predict from a CSV file
    
    Args:
        csv_file_path: Path to CSV file
        model_path: Path to trained model
        
    Returns:
        DataFrame with predictions
    """
    predictor = LiveIDSPredictor(model_path)
    return predictor.predict_from_csv(csv_file_path)

def predict_single(features_dict, model_path="best_ids_model.pkl"):
    """
    Simple function to predict a single sample
    
    Args:
        features_dict: Dictionary with feature values
        model_path: Path to trained model
        
    Returns:
        Tuple: (predicted_category, confidence)
    """
    predictor = LiveIDSPredictor(model_path)
    category, confidence, _ = predictor.predict_single_sample(features_dict)
    return category, confidence