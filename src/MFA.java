import java.io.*;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;

/**
 * Core logic for the Multi-Factor Authentication (MFA) system.
 *
 * This class manages:
 *   - An in-memory store of registered user accounts
 *   - User registration with password hashing and secondary factor setup
 *   - Two-factor login: password (factor 1) + OTP or security question (factor 2)
 *   - Account lockout after repeated failures
 *   - Optional file persistence so accounts survive program restarts (extra credit)
 */
public class MFA {

    /** In-memory user store: maps username -> Account. */
    private static final HashMap<String, Account> accounts = new HashMap<>();

    /** File used to persist account data between sessions (extra credit). */
    private static final String DATA_FILE = "users.dat";

    /** Delimiter used when serialising account fields to the data file. */
    private static final String DELIMITER = "|||";

    // =========================================================================
    // OTP helpers
    // =========================================================================

    /**
     * Generates a random 6-digit OTP and simulates delivering it to the
     * user's registered contact (phone or email).
     *
     * In a production system the OTP would be sent via SMS/email; here we
     * print it to the console to demonstrate the flow.
     *
     * @param account the account that is attempting to log in
     * @return the generated OTP string (always exactly 6 digits)
     */
    public static String sendVerificationCode(Account account) {
        Random rand = new Random();
        // Pad with leading zeros if necessary so the code is always 6 digits
        String otp = String.format("%06d", rand.nextInt(1_000_000));
        System.out.println("[SIMULATED] OTP " + otp + " sent to: " + account.getContact());
        return otp;
    }

    /**
     * Returns true if the user-supplied code matches the code that was sent.
     *
     * @param sentCode      the OTP that was generated and "sent"
     * @param userInputCode the OTP the user typed in
     */
    public static boolean verifyCode(String sentCode, String userInputCode) {
        return sentCode.equals(userInputCode);
    }

    // =========================================================================
    // Registration
    // =========================================================================

    /**
     * Guides the user through creating a new account.
     *
     * Steps:
     *   1. Choose a unique username
     *   2. Choose a password (will be hashed with a random salt)
     *   3. Choose a secondary factor — OTP or security question
     *
     * @param userInput the shared Scanner reading from System.in
     */
    public static void createAccount(Scanner userInput) {
        // --- Username ---
        System.out.print("Enter a username: ");
        String username = userInput.nextLine().trim();

        if (username.isEmpty()) {
            System.out.println("Error: Username cannot be empty.");
            return;
        }
        if (accounts.containsKey(username)) {
            System.out.println("Error: Username '" + username + "' is already taken.");
            return;
        }

        // --- Password ---
        System.out.print("Enter a password: ");
        String password = userInput.nextLine();

        if (password.isEmpty()) {
            System.out.println("Error: Password cannot be empty.");
            return;
        }

        // Create the Account — the constructor immediately hashes the password
        Account newAccount = new Account(username, password);

        // --- Secondary factor selection ---
        System.out.println("Choose a secondary authentication factor:");
        System.out.println("  1 - OTP (one-time password sent to your phone/email)");
        System.out.println("  2 - Security Question");
        System.out.print("Your choice: ");
        String factorChoice = userInput.nextLine().trim();

        if (factorChoice.equals("1")) {
            // OTP factor
            System.out.print("Enter your phone number or email for OTP delivery: ");
            String contact = userInput.nextLine().trim();
            if (contact.isEmpty()) {
                System.out.println("Error: Contact information cannot be empty.");
                return;
            }
            newAccount.setOtpFactor(contact);

        } else if (factorChoice.equals("2")) {
            // Security question factor
            System.out.print("Enter your security question: ");
            String question = userInput.nextLine().trim();
            System.out.print("Enter your answer: ");
            String answer = userInput.nextLine().trim();
            if (question.isEmpty() || answer.isEmpty()) {
                System.out.println("Error: Security question and answer cannot be empty.");
                return;
            }
            newAccount.setSecurityQuestionFactor(question, answer);

        } else {
            System.out.println("Error: Invalid choice. Account creation cancelled.");
            return;
        }

        // Persist the new account
        accounts.put(username, newAccount);
        saveAccounts();   // extra credit: write to disk immediately

        System.out.println("Account created successfully for '" + username + "'!");
    }

    // =========================================================================
    // Login
    // =========================================================================

    /**
     * Handles the full two-factor login flow.
     *
     * Factor 1 — Password:
     *   The entered password is hashed and compared to the stored hash.
     *
     * Factor 2 — Secondary:
     *   OTP: a fresh code is generated and the user must reproduce it.
     *   Security question: the user must answer the question they set at registration.
     *
     * A failed attempt (wrong password OR wrong secondary factor) increments
     * the account's failure counter.  After MAX_FAILED_ATTEMPTS the account
     * is locked and further login attempts are rejected.
     *
     * @param userInput the shared Scanner reading from System.in
     */
    public static void login(Scanner userInput) {
        System.out.print("Username: ");
        String username = userInput.nextLine().trim();

        // Validate that the account exists
        if (!accounts.containsKey(username)) {
            System.out.println("Error: No account found for username '" + username + "'.");
            return;
        }

        Account account = accounts.get(username);

        // Reject locked accounts before checking any credentials
        if (account.isLocked()) {
            System.out.println("Error: Account '" + username
                    + "' is locked after too many failed attempts. Contact support.");
            return;
        }

        // -----------------------------------------------------------------
        // Factor 1: Password verification
        // -----------------------------------------------------------------
        System.out.print("Password: ");
        String password = userInput.nextLine();

        if (!account.checkPassword(password)) {
            account.incrementFailedAttempts();
            if (account.isLocked()) {
                System.out.println("Error: Incorrect password. "
                        + "Account is now LOCKED after " + Account.MAX_FAILED_ATTEMPTS
                        + " failed attempts.");
            } else {
                int remaining = Account.MAX_FAILED_ATTEMPTS - account.getFailedAttempts();
                System.out.println("Error: Incorrect password. "
                        + remaining + " attempt(s) remaining before lockout.");
            }
            saveAccounts();   // persist updated failure count
            return;
        }

        System.out.println("Password authentication successful.");

        // -----------------------------------------------------------------
        // Factor 2: Secondary factor verification
        // -----------------------------------------------------------------
        boolean secondaryPassed = false;

        if ("OTP".equals(account.getSecondaryFactorType())) {
            // Generate and "deliver" a fresh OTP
            String otp = sendVerificationCode(account);
            System.out.print("Enter the verification code: ");
            String userOtp = userInput.nextLine().trim();

            if (verifyCode(otp, userOtp)) {
                secondaryPassed = true;
            } else {
                System.out.println("Error: Incorrect verification code.");
            }

        } else if ("QUESTION".equals(account.getSecondaryFactorType())) {
            System.out.println("Security Question: " + account.getSecurityQuestion());
            System.out.print("Your answer: ");
            String answer = userInput.nextLine().trim();

            if (account.checkSecurityAnswer(answer)) {
                secondaryPassed = true;
            } else {
                System.out.println("Error: Incorrect security answer.");
            }
        }

        // -----------------------------------------------------------------
        // Grant or deny access
        // -----------------------------------------------------------------
        if (secondaryPassed) {
            // Successful login — reset failure counter
            account.resetFailedAttempts();
            saveAccounts();
            System.out.println("Multi-Factor Authentication successful. "
                    + "Access granted. Welcome, " + username + "!");
        } else {
            // Secondary factor failed
            account.incrementFailedAttempts();
            if (account.isLocked()) {
                System.out.println("Account is now LOCKED after "
                        + Account.MAX_FAILED_ATTEMPTS + " failed attempts.");
            } else {
                int remaining = Account.MAX_FAILED_ATTEMPTS - account.getFailedAttempts();
                System.out.println("Access denied. "
                        + remaining + " attempt(s) remaining before lockout.");
            }
            saveAccounts();
        }
    }

    // =========================================================================
    // File persistence (extra credit)
    // =========================================================================

    /**
     * Loads all accounts from the data file into the in-memory store.
     * Called once at program startup.
     *
     * Each line in the file represents one account with fields separated by
     * the DELIMITER string:
     *   username | hashedPassword | salt | secondaryFactorType |
     *   contact  | securityQuestion | securityAnswerHash | failedAttempts | locked
     */
    public static void loadAccounts() {
        File file = new File(DATA_FILE);
        if (!file.exists()) {
            return;   // No saved data yet — start fresh
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\|\\|\\|", -1);
                if (parts.length < 9) continue;   // Malformed line — skip

                String username          = parts[0];
                String hashedPassword    = parts[1];
                String salt              = parts[2];
                String factorType        = parts[3];
                String contact           = parts[4];
                String securityQuestion  = parts[5];
                String securityAnswerHash = parts[6];
                int failedAttempts       = Integer.parseInt(parts[7]);
                boolean locked           = Boolean.parseBoolean(parts[8]);

                // Use the package-private constructor that accepts pre-hashed values
                Account account = new Account(username, hashedPassword, salt,
                        factorType, contact, securityQuestion, securityAnswerHash,
                        failedAttempts, locked);

                accounts.put(username, account);
            }
            if (!accounts.isEmpty()) {
                System.out.println("[System] Loaded " + accounts.size() + " account(s) from disk.");
            }
        } catch (IOException e) {
            System.out.println("[Warning] Could not read saved accounts: " + e.getMessage());
        }
    }

    /**
     * Saves all in-memory accounts to the data file.
     * Called automatically after every registration or login attempt.
     */
    public static void saveAccounts() {
        try (PrintWriter writer = new PrintWriter(new FileWriter(DATA_FILE))) {
            for (Account account : accounts.values()) {
                // Write one account per line; use DELIMITER to separate fields
                writer.println(
                        account.getUsername()           + DELIMITER +
                        account.getHashedPassword()     + DELIMITER +
                        account.getSalt()               + DELIMITER +
                        nullToEmpty(account.getSecondaryFactorType()) + DELIMITER +
                        nullToEmpty(account.getContact())             + DELIMITER +
                        nullToEmpty(account.getSecurityQuestion())    + DELIMITER +
                        nullToEmpty(account.getSecurityAnswerHash())  + DELIMITER +
                        account.getFailedAttempts()     + DELIMITER +
                        account.isLocked()
                );
            }
        } catch (IOException e) {
            System.out.println("[Warning] Could not save accounts: " + e.getMessage());
        }
    }

    /** Returns the string unchanged, or an empty string if it is null. */
    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
