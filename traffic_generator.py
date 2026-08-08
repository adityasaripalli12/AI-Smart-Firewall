import random

def generate_traffic():
    return {
        "requests": random.randint(1,300),
        "failed_logins": random.randint(0,10)
    }