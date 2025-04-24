# detection/apps.py
from django.apps import AppConfig

class DetectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'detection' # Should match your app name

    def ready(self):
        # Implicitly connect signal handlers decorated with @receiver.
        print("--- Loading detection signals in AppConfig.ready() ---") # Add a very noticeable print
        from detection import signals  # Ensure signals are imported
        _ = signals  # Explicitly reference signals to avoid unused import warning
        print("--- Detection signals successfully imported ---")