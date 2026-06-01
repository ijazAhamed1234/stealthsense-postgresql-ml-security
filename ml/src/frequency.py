import time
import os
import json

WINDOW = 60
HISTORY_FILE = "/tmp/stealthsense_frequency_history.json"

def query_frequency(query, user):
    now = time.time()
    
    # Load history
    history = {"queries": {}, "users": {}}
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            pass
            
    # Ensure structure keys exist
    if "queries" not in history:
        history["queries"] = {}
    if "users" not in history:
        history["users"] = {}
        
    # Clean up old timestamps
    for q in list(history["queries"].keys()):
        history["queries"][q] = [x for x in history["queries"][q] if now - x < WINDOW]
        if not history["queries"][q]:
            del history["queries"][q]
            
    for u in list(history["users"].keys()):
        history["users"][u] = [x for x in history["users"][u] if now - x < WINDOW]
        if not history["users"][u]:
            del history["users"][u]

    # Update current query and user history
    if query not in history["queries"]:
        history["queries"][query] = []
    history["queries"][query].append(now)
    
    if user not in history["users"]:
        history["users"][user] = []
    history["users"][user].append(now)
    
    # Save history back to file
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f)
        os.chmod(HISTORY_FILE, 0o666)
    except Exception:
        pass
        
    query_count = len(history["queries"][query])
    user_count = len(history["users"][user])
    
    # If specific query or general user rate exceeds 100 per min, return 100
    if query_count > 100 or user_count > 100:
        return 100
    elif query_count > 50 or user_count > 50:
        return 70
    return 10