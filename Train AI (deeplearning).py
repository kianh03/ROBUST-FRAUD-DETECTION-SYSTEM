import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, constraints, regularizers, Model
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, Callback
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import joblib
import shap
import matplotlib.pyplot as plt
from urllib.parse import urlparse
import random
from sklearn.utils import shuffle
import re

# Constants
MODEL_PATH = "fraud_model.h5"
TOKENIZER_PATH = "tokenizer.pkl"
SCALER_PATH = "scaler.pkl"
MAX_LEN = 200
TEXT_COLUMN = "url"
LABEL_COLUMN = "type"

# 1. Custom Components
# Use TF version compatibility
if hasattr(tf.keras, "saving"):
    register_serializable = tf.keras.saving.register_keras_serializable
else:
    register_serializable = tf.keras.utils.register_keras_serializable

@register_serializable(package="FraudDetection")
class FairnessConstraint(constraints.Constraint):
    def __init__(self, max_influence=0.3):
        self.max_influence = max_influence
        
    def __call__(self, w):
        return tf.clip_by_value(w, -self.max_influence, self.max_influence)
    
    def get_config(self):
        return {'max_influence': self.max_influence}

class ProtocolBalancer(Callback):
    def __init__(self, protocol_idx, total_epochs):
        super().__init__()
        self.protocol_idx = protocol_idx
        self.total_epochs = total_epochs
        
    def on_epoch_end(self, epoch, logs=None):
        layer = self.model.get_layer('feature_dense')
        if hasattr(layer, 'kernel'):
            kernel, bias = layer.get_weights()
            current_max = 0.3 * (1 - epoch / self.total_epochs)
            kernel[self.protocol_idx] = np.clip(kernel[self.protocol_idx], -current_max, current_max)
            layer.set_weights([kernel, bias])

@register_serializable(package="FraudDetection")
class FairnessPenalty(layers.Layer):
    def __init__(self, **kwargs):
        super(FairnessPenalty, self).__init__(**kwargs)
    
    def call(self, inputs):
        y_pred, features = inputs
        protocol = features[:, 4]
        http_mask = tf.cast(protocol < 0.5, tf.float32)
        http_mean = tf.reduce_mean(y_pred * http_mask)
        https_mean = tf.reduce_mean(y_pred * (1 - http_mask))
        penalty = tf.abs(http_mean - https_mean)
        self.add_loss(0.5 * penalty)
        return y_pred
    
    def get_config(self):
        config = super(FairnessPenalty, self).get_config()
        return config

# Save custom objects for model loading
CUSTOM_OBJECTS = {
    'FairnessConstraint': FairnessConstraint,
    'FairnessPenalty': FairnessPenalty
}

# 2. Feature Engineering
def calculate_entropy(s):
    if len(s) == 0: return 0.0
    p, lns = np.unique(list(s), return_counts=True)
    return -np.sum((lns/len(s)) * np.log2(lns/len(s)))

def tld_risk_score(tld):
    risky_tlds = {
        'xyz': 0.7, 'top': 0.65, 'loan': 0.85, 'bid': 0.8, 
        'online': 0.75, 'site': 0.7, 'club': 0.65, 'stream': 0.8,
        'icu': 0.75, 'live': 0.6, 'vip': 0.7, 'fit': 0.6,
        'tk': 0.8, 'ml': 0.75, 'ga': 0.75, 'cf': 0.7
    }
    return risky_tlds.get(tld.lower(), 0.2)

def extract_enhanced_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    return [
        len(domain), 
        url.count('-'), 
        min(url.count('.'), 5),
        sum(1 for c in url if not c.isalnum()), 
        int(url.startswith("https")),
        len(query), 
        domain.count('-'),
        sum(1 for c in domain if c.isdigit()) / (len(domain) or 1),
        len(path.split('/')) - 1, 
        sum(c.isupper() for c in domain),
        calculate_entropy(domain), 
        int('_' in domain),
        tld_risk_score(domain.split('.')[-1] if '.' in domain and len(domain.split('.')) > 1 else ''),
        len(url),
        int('@' in url),
        int('javascript:' in url.lower()),
        int('data:' in url.lower()),
        query.count('='),
        int(bool(re.search(r'\d{4,}', domain))),
        int(bool(re.search(r'[a-zA-Z]{15,}', domain)))
    ]

# 3. Data Loading and Balancing
def add_noise_to_features(features, noise_level=0.05):
    noisy_features = features.copy()
    for i in range(features.shape[1]):
        noise = np.random.normal(0, noise_level, size=features.shape[0])
        noisy_features[:, i] = features[:, i] + noise
    return noisy_features

def augment_urls(urls, labels, aug_factor=0.15):
    augmented_urls = []
    augmented_labels = []
    
    for url, label in zip(urls, labels):
        if random.random() < aug_factor:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if domain:
                if random.random() < 0.5 and '.' in domain:
                    parts = domain.split('.')
                    if len(parts) > 2:
                        if random.random() < 0.5 and len(parts[0]) > 1:
                            parts[0] = parts[0][:-1]
                        else:
                            parts[0] = parts[0] + random.choice('abcdefghijklmnopqrstuvwxyz')
                        new_domain = '.'.join(parts)
                        new_url = url.replace(domain, new_domain)
                        augmented_urls.append(new_url)
                        augmented_labels.append(label)
                else:
                    path = parsed.path
                    if path and len(path) > 1:
                        if random.random() < 0.5 and '/' in path[1:]:
                            parts = path.split('/')
                            if len(parts) > 2:
                                mod_index = random.randint(1, len(parts)-1)
                                if parts[mod_index]:
                                    parts[mod_index] = parts[mod_index] + random.choice('abcdefghijklmnopqrstuvwxyz')
                                new_path = '/'.join(parts)
                                new_url = url.replace(path, new_path)
                                augmented_urls.append(new_url)
                                augmented_labels.append(label)
    
    return augmented_urls, augmented_labels

def load_and_balance_data(filepath):
    df = pd.read_csv(filepath)
    print("Loaded rows:", len(df))
    df.dropna(subset=[TEXT_COLUMN, LABEL_COLUMN], inplace=True)
    print("After dropna rows:", len(df))

    label_mapping = {'benign': 0, 'phishing': 1, 'malware': 1, 'defacement': 1}
    df[LABEL_COLUMN] = df[LABEL_COLUMN].str.lower().map(label_mapping)
    if df[LABEL_COLUMN].isnull().any():
        print("Warning: Unmapped labels found, dropping them")
        df = df.dropna(subset=[LABEL_COLUMN])
    df[LABEL_COLUMN] = df[LABEL_COLUMN].astype(int)
    print("Initial distribution:\n", df[LABEL_COLUMN].value_counts())

    benign = df[df[LABEL_COLUMN] == 0]
    malicious = df[df[LABEL_COLUMN] == 1]
    
    if len(benign) > 0 and len(malicious) > 0:
        target_ratio = 1.5
        if len(benign) / len(malicious) > target_ratio:
            benign = benign.sample(int(len(malicious) * target_ratio), random_state=42)
        elif len(malicious) / len(benign) > 1/target_ratio:
            malicious = malicious.sample(int(len(benign) / target_ratio), random_state=42)
    
    final_df = pd.concat([benign, malicious])
    final_df = shuffle(final_df, random_state=42)
    
    augmented_urls, augmented_labels = augment_urls(
        final_df[TEXT_COLUMN].tolist(), 
        final_df[LABEL_COLUMN].tolist()
    )
    
    if augmented_urls:
        aug_df = pd.DataFrame({
            TEXT_COLUMN: augmented_urls,
            LABEL_COLUMN: augmented_labels
        })
        final_df = pd.concat([final_df, aug_df])
        final_df = shuffle(final_df, random_state=42)
    
    print("Final balanced distribution:\n", final_df[LABEL_COLUMN].value_counts())
    return final_df

# 4. Training Pipeline
def build_model(vocab_size, feature_dim):
    text_input = layers.Input(shape=(MAX_LEN,))
    feature_input = layers.Input(shape=(feature_dim,))
    
    # Use simpler architecture to avoid serialization issues
    x = layers.Embedding(vocab_size, 64)(text_input)
    x = layers.SpatialDropout1D(0.2)(x)
    x = layers.Bidirectional(layers.LSTM(48, return_sequences=True, 
                                         kernel_regularizer=regularizers.l2(1e-4)))(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Bidirectional(layers.LSTM(24, 
                                         kernel_regularizer=regularizers.l2(1e-4)))(x)
    x = layers.Dropout(0.3)(x)
    # Remove constraint that causes serialization issues
    x = layers.Dense(12, activation='relu', 
                      kernel_regularizer=regularizers.l2(1e-4))(x)
    
    f = layers.Dense(12, activation='relu', name='feature_dense',
                      kernel_regularizer=regularizers.l2(1e-4))(feature_input)
    f = layers.Dropout(0.25)(f)
    f = layers.Dense(8, activation='relu',
                      kernel_regularizer=regularizers.l2(1e-4))(f)
    
    combined = layers.Concatenate()([x, f])
    combined = layers.Dropout(0.2)(combined)
    output = layers.Dense(1, activation='sigmoid',
                           kernel_regularizer=regularizers.l2(1e-4))(combined)
    
    # Apply fairness penalty using our custom layer
    output = FairnessPenalty()(([output, feature_input]))
    
    model = Model(inputs=[text_input, feature_input], outputs=output)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001, clipnorm=1.0),
        loss='binary_crossentropy', 
        metrics=['accuracy', tf.keras.metrics.AUC()]
    )
    return model

def main():
    try:
        df = load_and_balance_data(r"C:\Users\kianh\Documents\Final Year Project\archive\malicious_phish1.csv")
        if len(df) < 5:
            raise ValueError(f"Need at least 5 samples, got {len(df)}")
        
        tokenizer = Tokenizer(char_level=True)
        tokenizer.fit_on_texts(df[TEXT_COLUMN])
        sequences = tokenizer.texts_to_sequences(df[TEXT_COLUMN])
        X_text = pad_sequences(sequences, maxlen=MAX_LEN)
        
        X_features = np.array([extract_enhanced_features(url) for url in df[TEXT_COLUMN]])
        scaler = MinMaxScaler()
        X_features = scaler.fit_transform(X_features)
        
        y = df[LABEL_COLUMN].values
        
        X_text_train, X_text_test, X_feat_train, X_feat_test, y_train, y_test = train_test_split(
            X_text, X_features, y, test_size=0.2, random_state=42, stratify=y
        )
        
        X_feat_train_noisy = add_noise_to_features(X_feat_train, noise_level=0.05)
        
        model = build_model(len(tokenizer.word_index) + 1, X_features.shape[1])
        model.summary()
        
        callbacks = [
            EarlyStopping(patience=15, restore_best_weights=True, monitor='val_auc'),
            ReduceLROnPlateau(factor=0.5, patience=8, min_lr=1e-5, monitor='val_auc'),
            ProtocolBalancer(protocol_idx=4, total_epochs=40)
        ]
        
        class_weights = {0: 1.0, 1: 1.5}
        
        history = model.fit(
            [X_text_train, X_feat_train_noisy], y_train,
            validation_data=([X_text_test, X_feat_test], y_test),
            epochs=40, batch_size=32, callbacks=callbacks, verbose=1,
            class_weight=class_weights
        )
        
        test_loss, test_acc, test_auc = model.evaluate([X_text_test, X_feat_test], y_test)
        print(f"Test accuracy: {test_acc:.4f}, AUC: {test_auc:.4f}")
        
        # Save model with custom objects
        model.save(MODEL_PATH, save_format='h5')
        
        # Save a dictionary of custom objects with the model path for easy loading
        custom_objects_info = {
            'model_path': MODEL_PATH,
            'custom_objects': {
                'FairnessConstraint': 'FraudDetection',
                'FairnessPenalty': 'FraudDetection'
            }
        }
        
        with open('custom_objects.json', 'w') as f:
            import json
            json.dump(custom_objects_info, f)
            
        joblib.dump(tokenizer, TOKENIZER_PATH)
        joblib.dump(scaler, SCALER_PATH)
        print("Model and artifacts saved successfully")
        
        plt.figure(figsize=(12, 5))
        plt.subplot(1, 2, 1)
        plt.plot(history.history['accuracy'], label='train_accuracy')
        plt.plot(history.history['val_accuracy'], label='val_accuracy')
        plt.title('Model Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.legend()
        
        plt.subplot(1, 2, 2)
        plt.plot(history.history['auc'], label='train_auc')
        plt.plot(history.history['val_auc'], label='val_auc')
        plt.title('Model AUC')
        plt.xlabel('Epoch')
        plt.ylabel('AUC')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig('model_training_history.png')
        plt.show()
        
    except Exception as e:
        print(f"Training failed: {str(e)}")

if __name__ == "__main__":
    main()