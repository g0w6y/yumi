
<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/a8c0925f-57dc-4f7c-8e6d-edb7f7b7c5d0" />

![Version](https://img.shields.io/badge/version-0.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- Automatic enumeration of subdomains and JavaScript files
- Bulk download and scanning of JS files for sensitive keys, secrets, and endpoints
- Detects vulnerabilities such as API keys, tokens, hardcoded passwords, and more
- Fancy terminal UI with ASCII art logo and loading animations
- JSON and console report generation
- Extensible plugin system for custom scanning rules

---

## Installation

Ensure you have Python 3.8+ installed, then run:

```
pip install -r requirements.txt
```

Or install in editable mode for development:

```
pip install -e .
```

---

## Usage

Run the tool from the command line with a target domain:

```
yumi example.com
```

You will see a colorful loading screen, followed by enumeration and scan results. A detailed JSON report is saved as `report.json`.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Authors and Acknowledgments

- Developed by `David PS Abraham ` 
- Inspired by the needs of the bug bounty community  
- Thanks to open source projects like `requests`, `rich`, and `pyfiglet`

---

## Contact


GitHub: [https://github.com/cypherdavy/yumi](https://github.com/cypherdavy/yumi)
