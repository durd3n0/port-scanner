# **Python Nmap Port Scanner**

This is a versatile, command-line port scanning utility developed in Python. It leverages the Nmap engine to scan hosts and provides two distinct modes of operation:

1. **Interactive Mode:** A guided experience that prompts the user for target, port range, and scan options.  
2. **Command-Line Interface (CLI) Mode:** A non-interactive mode that accepts all inputs as command-line arguments, suitable for automation and scripting.

## **Prerequisites**

Execution of this script requires the following system components and libraries:

1. **Python 3**  
2. **Nmap Engine:** The script is a wrapper for the Nmap tool and will not function if Nmap is not installed.  
   * **Download:** [Nmap Download Page](https://nmap.org/download.html)  
3. **python-nmap Library:** The Python module used to interface with Nmap.

## **Installation**

1. Acquire the Source Code:  
   Clone or download the repository to your local machine:  
   ```bash
    git clone https://github.com/durd3n0/port-scanner.git  
    cd port-scanner
   ```

2. **Install the Nmap Engine:**  
   * **Windows:** Utilize the installer from the [Nmap Download Page](https://nmap.org/download.html).  
   * **Debian/Ubuntu:** sudo apt install nmap  
   * **macOS (Homebrew):** brew install nmap  
3. **Install the python-nmap Library:**  
   ```bash
    pip install python-nmap
   ```
   *(The script includes a runtime check for this dependency.)*

## **How to Run**

The utility can be executed in two primary modes:

### **Option 1: Interactive Mode**

Execute the script without command-line arguments to initiate the guided, interactive session:  
```bash
 python3 port-scanner.py
```
The tool will display its banner and guide the user through the process, prompting for target, ports, and scan options.

### **Option 2: Command-Line Interface (CLI) Mode**

Supply all parameters as command-line arguments for non-interactive or automated execution.

#### **Syntax:**
```bash
 python3 port-scanner.py -t <target> -p <ports> -o "<options>"
```
*Note: Encapsulating Nmap options in quotation marks is recommended practice.*

#### **Example:**

This command scans scan.nmap.org for ports 80 and 443 with the \-sV (version detection) argument.  
```bash
 python3 port-scanner.py -t scan.nmap.org -p 80,443 -o "sV"
```
### **Example Session (CLI Mode)**
```
 python3 port-scanner.py -t scan.nmap.org -p 80,443 -o "sV"

[+] Set target to: scan.nmap.org
[+] Set port range to: 80,443
[+] Using Nmap arguments: sV

[+] Scanning scan.nmap.org for ports 80,443 with arguments sV...
This may take a moment...
[+] Scan Complete.

----------------------------------------------------
Host : 50.116.1.184 (scan.nmap.org)
State : up

Protocol : tcp
  Port : 80     State : open    Service : http
  Port : 443    State : open    Service : https
----------------------------------------------------

[*] Type 'r' to scan another hostname or 'Enter' to exit:
```
### **All Command-Line Arguments**
```
| \-t,  --target  | Target IP or hostname.                           |  
| \-p,  --ports   | Port range, e.g., '1-1024' or '80,443'.          |  
| \-o,  --options | Custom arguments to pass to Nmap (e.g. "sV sC"). |  
| \-h,  --help    | Display the help message and exit.               |
```
## **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## **Ethical Use Disclaimer**


This tool is provided for educational purposes and authorized security assessments **exclusively**. This utility must be used **only** on systems for which the operator possesses explicit, written authorization to scan. Unauthorized scanning constitutes a potential violation of local, state, or federal laws and organizational policies. The author assumes no liability for any misuse or damage resulting from this script's operation.

