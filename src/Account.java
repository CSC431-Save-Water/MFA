import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Represents a registered user account.
 *
 * Passwords are never stored in plaintext — they are hashed with SHA-256
 * combined with a unique random salt, which protects against rainbow-table
 * and brute-force attacks.
 *
 * Each account supports one of two secondary authentication factors:
 *   - OTP: a one-time password sent to the user's phone/email
 *   - QUESTION: a secret security question with a hashed answer
 */
public class Account {

    /** Maximum consecutive failed login attempts before the account is locked. */
    public static final int MAX_FAILED_ATTEMPTS = 3;

    // -------------------------------------------------------------------------
    // Core credentials
    // -------------------------------------------------------------------------

    private final String username;
    private final String hashedPassword;   // SHA-256 hash of (salt + password)
    private final String salt;             // Random Base64-encoded salt

    // -------------------------------------------------------------------------
    // Secondary factor
    // -------------------------------------------------------------------------

    /** Either "OTP" or "QUESTION". Set after construction via the setter methods. */
    private String secondaryFactorType;

    /** For OTP: the phone number or email address where codes are "sent". */
    private String contact;

    /** For security question: the question text. */
    private String securityQuestion;

    /** For security question: SHA-256 hash of the (trimmed, lowercase) answer. */
    private String securityAnswerHash;

    // -------------------------------------------------------------------------
    // Lockout tracking
    // -------------------------------------------------------------------------

    private int failedAttempts;  // Consecutive failed login attempts
    private boolean locked;      // True when failedAttempts >= MAX_FAILED_ATTEMPTS

    // =========================================================================
    // Constructor
    // =========================================================================

    /**
     * Creates a new account with a securely hashed password.
     *
     * @param username the desired username
     * @param password the plaintext password — immediately hashed and discarded
     */
    public Account(String username, String password) {
        this.username = username;
        this.salt = generateSalt();
        this.hashedPassword = hashValue(password, this.salt);
        this.failedAttempts = 0;
        this.locked = false;
    }

    /**
     * Private constructor used when loading accounts from a saved file.
     * Accepts pre-hashed values so we don't re-hash already-hashed data.
     */
    Account(String username, String hashedPassword, String salt,
            String secondaryFactorType, String contact,
            String securityQuestion, String securityAnswerHash,
            int failedAttempts, boolean locked) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.salt = salt;
        this.secondaryFactorType = secondaryFactorType;
        this.contact = contact;
        this.securityQuestion = securityQuestion;
        this.securityAnswerHash = securityAnswerHash;
        this.failedAttempts = failedAttempts;
        this.locked = locked;
    }

    // =========================================================================
    // Secondary factor configuration
    // =========================================================================

    /**
     * Configures OTP as the secondary factor.
     *
     * @param contact phone number or email to which OTPs will be "sent"
     */
    public void setOtpFactor(String contact) {
        this.secondaryFactorType = "OTP";
        this.contact = contact;
    }

    /**
     * Configures a security question as the secondary factor.
     * The answer is hashed before storage so it is never kept in plaintext.
     *
     * @param question the security question text
     * @param answer   the plaintext answer (trimmed and lowercased before hashing)
     */
    public void setSecurityQuestionFactor(String question, String answer) {
        this.secondaryFactorType = "QUESTION";
        this.securityQuestion = question;
        // Normalise the answer to make comparisons case- and whitespace-insensitive
        this.securityAnswerHash = hashValue(answer.toLowerCase().trim(), this.salt);
    }

    // =========================================================================
    // Credential verification
    // =========================================================================

    /**
     * Returns true if the given plaintext password matches the stored hash.
     */
    public boolean checkPassword(String plainPassword) {
        return hashedPassword.equals(hashValue(plainPassword, this.salt));
    }

    /**
     * Returns true if the given plaintext security answer matches the stored hash.
     * Comparison is case- and whitespace-insensitive.
     */
    public boolean checkSecurityAnswer(String answer) {
        return securityAnswerHash != null &&
               securityAnswerHash.equals(hashValue(answer.toLowerCase().trim(), this.salt));
    }

    // =========================================================================
    // Account lockout
    // =========================================================================

    /**
     * Increments the failed-attempt counter and locks the account if the
     * maximum number of attempts has been reached.
     */
    public void incrementFailedAttempts() {
        this.failedAttempts++;
        if (this.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            this.locked = true;
        }
    }

    /** Resets the failed-attempt counter after a successful login. */
    public void resetFailedAttempts() {
        this.failedAttempts = 0;
    }

    // =========================================================================
    // Getters
    // =========================================================================

    public String getUsername()            { return username; }
    public String getHashedPassword()      { return hashedPassword; }
    public String getSalt()                { return salt; }
    public String getSecondaryFactorType() { return secondaryFactorType; }
    public String getContact()             { return contact; }
    public String getSecurityQuestion()    { return securityQuestion; }
    public String getSecurityAnswerHash()  { return securityAnswerHash; }
    public int    getFailedAttempts()      { return failedAttempts; }
    public boolean isLocked()              { return locked; }

    // =========================================================================
    // Static hashing utilities
    // =========================================================================

    /**
     * Generates a cryptographically random 16-byte salt encoded as Base64.
     * A unique salt per account ensures that two users with the same password
     * still have different stored hashes.
     */
    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    /**
     * Hashes a value combined with a salt using SHA-256 and returns the
     * result as a lowercase hex string.
     *
     * @param value the plaintext value to hash (password or answer)
     * @param salt  the account's unique salt
     * @return 64-character hex-encoded SHA-256 digest
     */
    public static String hashValue(String value, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Prepend the salt bytes before hashing
            md.update(salt.getBytes());
            byte[] hashBytes = md.digest(value.getBytes());

            // Convert the raw bytes to a readable hex string
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be present in any standard JVM
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
