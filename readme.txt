CSC 361 - Fall 2024
Programming Assignment 3
Luke Kuligowicz
V01019209

---------------------------------------------------

FILES

    --- Code Files -----------
    connection_class.py
    header_class.py
    packet_struct.py

    linux_handler.py
    windows_handler.py

    P3_Fall2024.py

    --- Output Files ---------
    readme.txt
    R2.pdf
    screenshots
        Folder for screenshoting outputs
    output.txt

    --- Test Files -----------
    Any file ending in a .pcap extention that is included here should work,
    there are many files listed


---------------------------------------------------

COMPILATION / USAGE

    This is the submission for CSC 361 - Assignment 3, were we were tasked to parse and gather information about a traceroute command,
    done in windows or linux, and answer various questions about it.

    In the directory of the project
    1) open a bash terminal
    2) go to the directory where the files are kept
    2) run this command into the terminal.

    ```
    python3 P3_Fall2024.py <.pcap file location>
    ```

    Example Input
    ```
    python3 P3_Fall2024.py win_trace1.pcap
    ```

---------------------------------------------------

OUTPUT

    The program outputs questions 1 - 10 Dynamically based on the input test file you provided

    Question 11 is hard coded in to output based on the group-trace files
    Questions 11-12 can be found in R2.pdf, also based on the group-trace files

    output.txt contains a sample output using the usage case denoted above

---------------------------------------------------

Notes:

    Screenshots included use a subdirectory, there is no need here, these show my work done for R2,
    as well as additional evidence

    Ordering of the intermediate nodes is based on TTL values, shorter comes first,
    larger comes later. Same TTL are determined by the order they appear in wireshark