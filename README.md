# Process Scanner & Signature Verifier

This is a process scanner that checks running processes on a Windows system to verify whether the executables are signed and checks if they match a list of legitimate processes. It ensures that only the processes that are not in the list of trusted executables are examined for signatures.

## Features
- Scans running processes on the system.
- Verifies whether each process has a valid digital signature.
- Skips known legitimate processes based on the executable name.
- Flags unsigned or suspicious executables.
- Provides details about each process and any signature issues.

## How It Works
1. The program creates a snapshot of all the running processes.
2. It retrieves the executable names and compares them with a predefined list of **legitimate** process names.
3. If the process is not legitimate, the program checks if the executable has a valid signature using Windows' `WinVerifyTrust` API.
4. The program logs the results to the console, showing which executables are signed and which are unsigned.

## Requirements
- Windows operating system.
- Visual Studio or compatible C++ compiler with Windows SDK.

## Usage

### Compile and Run
1. Clone this repository.
2. Open the project in your preferred C++ IDE (e.g., Visual Studio).
3. Build the project and run the executable.
4. The program will automatically scan all running processes and check the signatures for any unsigned executables that aren't in the list of legitimate processes.

### Output
The program outputs the following information for each process:
- **Legitimate processes**: Skipped without further checking.
- **Signed executables**: The executable is verified as signed.
- **Unsigned executables**: Detected as unsigned and flagged.

Example output:

