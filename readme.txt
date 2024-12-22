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

    --- Test Files -----------
    Any file ending in a .pcap extension


---------------------------------------------------

COMPILATION / USAGE
    In the directory of the project
    1) open a bash terminal
    2) go to the directory where the files are kept
    2) run this command into the terminal.

    ```
    python3 trace_route_a.py <.pcap file location>
    ```

    Example Input
    ```
    python3 trace_route_a.py win_trace1.pcap
    ```

---------------------------------------------------

OUTPUT

    The program outputs 10 parts dynamically based on the input test file you provided

    Question 11 is hard-coded in to output based on the original use of the program
---------------------------------------------------

Notes:

    Screenshots included use a subdirectory, there is no need here, these show my work done for R2,
    as well as additional evidence

    Ordering of the intermediate nodes is based on TTL values, shorter comes first,
    larger comes later. Same TTL are determined by the order they appear in wireshark
