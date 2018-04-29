import json
from pathlib import Path

class Config():

    filepath = Path('config.json')

    def __init__(self):
        # Load config values from file
        if self.filepath.exists():
            with open(self.filepath, 'r') as config_file:
                self.values = json.load(config_file)
        else:
            self.values = dict()

    def get(self, key, default_value=None):
        return self.values.get(key, default_value)

    def set(self, key, value):
        self.values[key] = value

    def save(self):
        """Save config values to file."""
        with open(self.filepath, 'w') as config_file:
            json.dump(self.values, config_file)

config = Config()
