import os
from datetime import datetime
from flask import current_app
from core.model import NIDSModel

_model_instance = None

def get_model_instance():
    """Singleton pattern for the ML model."""
    global _model_instance
    if _model_instance is None:
        model_path = current_app.config['MODEL_PATH']
        _model_instance = NIDSModel(model_path)
    return _model_instance

def get_model_status():
    """Retrieve metadata about the current model."""
    model_path = current_app.config['MODEL_PATH']
    exists = os.path.exists(model_path)
    
    last_trained = None
    if exists:
        mtime = os.path.getmtime(model_path)
        last_trained = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        
    return {
        "exists": exists,
        "path": model_path,
        "last_trained": last_trained,
        "status": "Ready" if exists else "Not Found (Will train on demand)",
        "features": get_model_instance().features
    }

def retrain_model():
    """Force retrain the model."""
    model = get_model_instance()
    # Call the internal training method to generate synthetic data and overwrite the model
    model._train_synthetic_model()
    return get_model_status()
