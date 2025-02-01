# HTTP Login Simulator

A Python-based tool for simulating HTTP login requests, designed for testing and educational purposes.

## Features

- Simulates HTTP POST login requests
- Generates random usernames and passwords
- Supports multiple login attempts
- Provides detailed response feedback

## Requirements

- Python 3.x

## Installation

1. Clone the repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Start your HTTP server (should be listening on http://localhost/login )

```bash
python server.py
```
2. Run the simulator:

```bash
python simulator.py
 ```

The script will:

- Generate random credentials
- Send login requests to the specified endpoint
- Display the results of each attempt

## Configuration
You can modify the following parameters in simulator.py :

- login_url : The target login endpoint
- num_attempts : Number of login attempts to make
- Username and password generation parameters

## Security Notice
This tool is intended for educational and testing purposes only. Do not use it against systems without proper authorization.