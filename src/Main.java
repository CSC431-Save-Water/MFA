import java.util.Scanner;

/**
 * Entry point for the Multi-Factor Authentication (MFA) System.
 *
 * Presents a simple menu that lets users register a new account or log in
 * to an existing one.  On startup, any previously saved accounts are loaded
 * from disk so that registrations persist between sessions.
 */
public class Main {
    public static void main(String[] args) {
        // Load any accounts saved from a previous session
        MFA.loadAccounts();

        System.out.println("Welcome to the Multi-Factor Authentication (MFA) System!");

        Scanner userInput = new Scanner(System.in);
        int choice = -1;

        while (choice != 0) {
            System.out.println("Please select an option:");
            System.out.println("  0 - Exit");
            System.out.println("  1 - Register");
            System.out.println("  2 - Log In");
            System.out.print("Your choice: ");

            choice = userInput.nextInt();
            userInput.nextLine();   // consume the trailing newline

            switch (choice) {
                case 1 -> MFA.createAccount(userInput);
                case 2 -> MFA.login(userInput);
                case 0 -> System.out.println("Exiting the system. Goodbye!");
                default -> System.out.println("Invalid option. Please try again.");
            }

            System.out.println();
        }

        userInput.close();
    }
}
