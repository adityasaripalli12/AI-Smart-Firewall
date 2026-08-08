import time
import threading

# 🔁 Global control flag
attack_mode = False


# ---------------- START CONTINUOUS SIMULATION ----------------
def start_continuous_simulation(app, func):
    global attack_mode

    # If already running → do nothing
    if attack_mode:
        return

    attack_mode = True

    def run():
        while attack_mode:
            try:
                # ✅ Required for Flask background execution
                with app.app_context():
                    func()
            except Exception as e:
                print("Error in background thread:", e)

            time.sleep(0.5)  # delay between traffic generation

    # Run in background
    threading.Thread(target=run, daemon=True).start()


# ---------------- STOP SIMULATION ----------------
def stop_attack_mode():
    global attack_mode
    attack_mode = False