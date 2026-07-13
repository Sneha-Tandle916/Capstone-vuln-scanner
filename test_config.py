import yaml

with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

print("Configuration Loaded Successfully!")
print(config)