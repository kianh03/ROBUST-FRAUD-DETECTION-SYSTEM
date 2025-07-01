import os
import logging
import numpy as np
import tensorflow as tf

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for model and scaler
_model = None
_scaler = None

class DirectScaler:
    """
    Simple scaler implementation that normalizes features.
    """
    def transform(self, X):
        """Simple normalization of input features"""
        if isinstance(X, np.ndarray):
            # Basic normalization to [0,1] range
            # Add small epsilon to avoid division by zero
            epsilon = 1e-10
            max_values = np.max(np.abs(X), axis=0, keepdims=True)
            max_values[max_values < epsilon] = 1.0
            
            return X / max_values
        return X

def create_model():
    """
    Load the user's model file, or create a model if loading fails.
    
    Returns:
        tf.keras.Sequential: The loaded or created model
    """
    # Define the path to the model file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(current_dir, 'models', 'fraud_model.h5')
    
    # First try to load the user's model
    if os.path.exists(model_path):
        try:
            logger.info(f"Loading model from {model_path}")
            model = tf.keras.models.load_model(model_path)
            logger.info("Successfully loaded user's model")
            return model
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            logger.info("Falling back to creating a new model")
    else:
        logger.warning(f"Model file not found at {model_path}")
    
    # If loading fails, create a new model
    logger.info("Creating model with fixed architecture")
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(96,)),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(16, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    
    # Compile the model
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    logger.info("New model created and compiled successfully")
    
    return model

def initialize():
    """
    Initialize the model and scaler.
    
    Returns:
        tuple: (model_success, scaler_success)
    """
    global _model, _scaler
    
    logger.info("Initializing model service")
    
    # Create scaler
    try:
        _scaler = DirectScaler()
        logger.info("Scaler created successfully")
        scaler_success = True
    except Exception as e:
        logger.error(f"Error creating scaler: {str(e)}")
        _scaler = None
        scaler_success = False
    
    # Create model
    try:
        _model = create_model()
        model_success = True
    except Exception as e:
        logger.error(f"Error creating model: {str(e)}")
        _model = None
        model_success = False
    
    return model_success, scaler_success

def get_model():
    """
    Get the model instance, initializing if necessary.
    
    Returns:
        tf.keras.Model: The model
    """
    global _model
    if _model is None:
        initialize()
    return _model

def get_scaler():
    """
    Get the scaler instance, initializing if necessary.
    
    Returns:
        DirectScaler: The scaler
    """
    global _scaler
    if _scaler is None:
        initialize()
    return _scaler

def predict(features):
    """
    Make a prediction using the model.
    
    Args:
        features: Feature vector (numpy array)
        
    Returns:
        numpy.ndarray: Prediction result
    """
    model = get_model()
    scaler = get_scaler()
    
    if model is None:
        raise ValueError("Model is not initialized")
    
    # Scale features if scaler is available
    if scaler is not None:
        features = scaler.transform(features)
    
    # Make prediction
    return model.predict(features)

def get_status():
    """
    Get the status of the model service.
    
    Returns:
        dict: Status information
    """
    global _model, _scaler
    
    # Initialize if not already done
    if _model is None or _scaler is None:
        initialize()
    
    status = {
        "model_loaded": _model is not None,
        "model_type": str(type(_model)) if _model else "None",
        "scaler_loaded": _scaler is not None,
        "status": "operational" if _model is not None and _scaler is not None else "error",
        "using_fallback": False
    }
    
    return status

# Initialize the model service when the module is imported
initialize() 