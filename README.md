# :computer: Ciphered KeyLogger Server-Client

This project contains one keylogger using only HTTP requests.

## :hammer: Project Structure

The project is structured in the following way:

``` bash
ciphered-keylogger.git
├── logs                # Directory where all clients keystrokes are stored
├── double_ratchet.py   # Double Ratchet encryption mechanism implementation
├── http_server.py      # Server python script to receive keystrokes
├── auth                # Endpoint for getting servers public key
├── login               # Endpoint for pair Double Ratchet session
├── logout              # Endpoint for disconnection
├── home                # Endpoint for sending keystrokes
├── keylogger.py        # Client python script to send keystrokes to the server
└── README.md
```

## :wrench: How to use