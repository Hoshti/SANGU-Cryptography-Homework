import random

def simulate_malicious_zkp(trials=20):
    """
    Simulates the Ali Baba Cave ZKP specifically for a malicious prover
    (one who does not know the password and is guessing).

    Args:
        trials (int): The number of simulation rounds.

    Returns:
        float: The success probability of the malicious prover.
    """
    malicious_success_count = 0
    print(f"--- Simulating {trials} ZKP trials for a MALICIOUS Prover (Guessing) ---")

    for i in range(trials):
        # 1. Prover (without password) randomly chooses a path to enter
        path_entered = random.choice(['A', 'B'])
        # print(f"Trial {i+1}: Malicious prover enters path {path_entered}") # Optional print

        # 2. Verifier randomly issues a challenge path
        challenge = random.choice(['A', 'B'])
        # print(f"Trial {i+1}: Verifier challenges path {challenge}") # Optional print

        # 3. Determine success: Malicious prover succeeds ONLY if their
        #    randomly chosen path matches the verifier's random challenge.
        #    We force knows_password = False for this simulation.
        knows_password = False

        if knows_password:
            # This branch is conceptually here but won't be hit in this specific simulation
            success = True
            print("Error: Simulation should have knows_password = False") # Should not happen
        else:
            # Success = True if path_entered == challenge, otherwise False
            success = (path_entered == challenge)

        if success:
            malicious_success_count += 1
            # print(f"Trial {i+1}: SUCCESS (Guessed correctly!)") # Optional print
        # else:
            # print(f"Trial {i+1}: FAIL (Guessed incorrectly)") # Optional print


    # Calculate the success probability
    success_probability = malicious_success_count / trials

    print(f"\n--- Simulation Results ({trials} trials) ---")
    print(f"Total successful guesses by malicious prover: {malicious_success_count}")
    print(f"Success Probability for Malicious Prover: {success_probability:.2f} ({malicious_success_count}/{trials})")
    print("-" * 40)

    # Theoretical expectation check
    print(f"Theoretical expectation: A malicious prover has a 1 in 2 (0.50) chance")
    print(f"of guessing correctly in any single trial.")

    return success_probability

# Run the simulation for a malicious prover
simulate_malicious_zkp(trials=20)