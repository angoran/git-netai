# netai - Network AI Operations MCP Server

A Model Context Protocol (MCP) server that provides unified access to multiple network infrastructure platforms through asynchronous connectors. Supports management of Cisco APIC, NDFC, MikroTik, Palo Alto, Aruba, LibreNMS, Graylog, and generic SSH devices.

## Quick Start

- **Windows**: [Installation Guide](#installation-windows)
- **macOS**: [Installation Guide](#installation-macos)
- **Linux**: [Installation Guide](#installation-linux)

---

## Prerequisites

Before installing netai, ensure you have:

1. **Python 3.12 or higher** - [Download here](https://www.python.org/downloads/)
2. **UV Package Manager** - Install with:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   Or on Windows using PowerShell:
   ```powershell
   powershell -ExecutionPolicy BypassUser -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```
3. **Git** (optional, for cloning the repository) - [Download here](https://git-scm.com/)

---

## Installation

### Installation (Windows)

#### Step 1: Clone or Download the Repository

**Option A: Using Git**
```cmd
git clone <repository-url> netai
cd netai
```

**Option B: Manual Download**
1. Download the repository as a ZIP file
2. Extract it to a folder (e.g., `C:\Users\YourUsername\netai`)
3. Open Command Prompt and navigate to that folder:
   ```cmd
   cd C:\Users\YourUsername\netai
   ```

#### Step 2: Install Dependencies

```cmd
uv sync
```

#### Step 3: Configure Environment Variables

1. Open the `.env` file in a text editor (e.g., Notepad)
2. Add your network device credentials and endpoints:
   ```
   # SSH credentials
   SSH_USERNAME=your_username
   SSH_PASSWORD=your_password

   # MikroTik API credentials
   MIKROTIK_USERNAME=your_username
   MIKROTIK_PASSWORD=your_password
   MIKROTIK_PORT=58080

   # Add other platform credentials as needed
   ```
3. Save the file

#### Step 4: Verify Installation

Test the server starts correctly:
```cmd
uv run python server.py
```

You should see the server running without errors. Press `Ctrl+C` to stop it.

---

### Installation (macOS)

#### Step 1: Clone or Download the Repository

**Option A: Using Git**
```bash
git clone <repository-url> netai
cd netai
```

**Option B: Manual Download**
1. Download the repository as a ZIP file
2. Extract it to a folder (e.g., `~/netai`)
3. Open Terminal and navigate to that folder:
   ```bash
   cd ~/netai
   ```

#### Step 2: Install Dependencies

```bash
uv sync
```

#### Step 3: Configure Environment Variables

1. Open the `.env` file using your preferred editor:
   ```bash
   nano .env
   # or
   open -e .env
   ```
2. Add your network device credentials and endpoints:
   ```
   # SSH credentials
   SSH_USERNAME=your_username
   SSH_PASSWORD=your_password

   # MikroTik API credentials
   MIKROTIK_USERNAME=your_username
   MIKROTIK_PASSWORD=your_password
   MIKROTIK_PORT=58080

   # Add other platform credentials as needed
   ```
3. Save the file (Ctrl+O, then Enter, then Ctrl+X if using nano)

#### Step 4: Verify Installation

Test the server starts correctly:
```bash
uv run python server.py
```

You should see the server running without errors. Press `Ctrl+C` to stop it.

---

### Installation (Linux)

#### Step 1: Clone or Download the Repository

**Option A: Using Git**
```bash
git clone <repository-url> netai
cd netai
```

**Option B: Manual Download**
1. Download the repository as a ZIP file
2. Extract it to a folder (e.g., `~/netai`)
3. Open a terminal and navigate to that folder:
   ```bash
   cd ~/netai
   ```

#### Step 2: Install Dependencies

```bash
uv sync
```

#### Step 3: Configure Environment Variables

1. Open the `.env` file using your preferred editor:
   ```bash
   nano .env
   # or
   vi .env
   ```
2. Add your network device credentials and endpoints:
   ```
   # SSH credentials
   SSH_USERNAME=your_username
   SSH_PASSWORD=your_password

   # MikroTik API credentials
   MIKROTIK_USERNAME=your_username
   MIKROTIK_PASSWORD=your_password
   MIKROTIK_PORT=58080

   # Add other platform credentials as needed
   ```
3. Save the file (Ctrl+O, then Enter, then Ctrl+X if using nano)

#### Step 4: Verify Installation

Test the server starts correctly:
```bash
uv run python server.py
```

You should see the server running without errors. Press `Ctrl+C` to stop it.

---

## Client Configuration

### Warp Configuration

#### macOS

1. Open Warp configuration file:
   ```bash
   nano ~/.warp/config.json
   # or open it manually at ~/.warp/config.json
   ```

2. Add the netai server configuration:
   ```json
   {
     "netai": {
       "command": "uv",
       "args": [
         "run",
         "python",
         "server.py"
       ],
       "env": {},
       "working_directory": "/Users/YourUsername/netai"
     }
   }
   ```

3. **Important**: Replace `/Users/YourUsername/netai` with the actual path to your netai folder

4. Save and close the editor (Ctrl+O, then Enter, then Ctrl+X if using nano)

5. Restart Warp

#### Windows

1. Open Warp configuration file:
   ```cmd
   notepad %APPDATA%\Warp\config.json
   ```

2. Add the netai server configuration:
   ```json
   {
     "netai": {
       "command": "uv",
       "args": [
         "run",
         "python",
         "server.py"
       ],
       "env": {},
       "working_directory": "C:/netai"
     }
   }
   ```

3. **Important**: Replace `C:/netai` with the actual path to your netai folder

4. Save and close the editor

5. Restart Warp

#### Linux

1. Open Warp configuration file:
   ```bash
   nano ~/.warp/config.json
   # or nano ~/.config/warp/config.json (depending on Warp installation)
   ```

2. Add the netai server configuration:
   ```json
   {
     "netai": {
       "command": "uv",
       "args": [
         "run",
         "python",
         "server.py"
       ],
       "env": {},
       "working_directory": "/home/YourUsername/netai"
     }
   }
   ```

3. **Important**: Replace `/home/YourUsername/netai` with the actual path to your netai folder

4. Save and close the editor (Ctrl+O, then Enter, then Ctrl+X if using nano)

5. Restart Warp

---

### Claude Desktop Configuration

#### macOS

1. Open Claude Desktop configuration file:
   ```bash
   nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

   Or manually open it at: `~/Library/Application Support/Claude/claude_desktop_config.json`

2. Add the netai server configuration:
   ```json
   {
     "mcpServers": {
       "netai": {
         "command": "uv",
         "args": [
           "--directory",
           "/Users/YourUsername/netai",
           "run",
           "python",
           "server.py"
         ]
       }
     }
   }
   ```

3. **Important**: Replace `/Users/YourUsername/netai` with the actual path to your netai folder

4. Save and close the editor (Ctrl+O, then Enter, then Ctrl+X if using nano)

5. Restart Claude Desktop completely (quit and reopen the application)

#### Windows

1. Open Claude Desktop configuration file:
   ```cmd
   notepad "%APPDATA%\Claude\claude_desktop_config.json"
   ```

   Or navigate manually to: `C:\Users\YourUsername\AppData\Roaming\Claude\claude_desktop_config.json`

2. Add the netai server configuration:
   ```json
   {
     "mcpServers": {
       "netai": {
         "command": "uv",
         "args": [
           "--directory",
           "C:\netai",
           "run",
           "python",
           "server.py"
         ]
       }
     }
   }
   ```

3. **Important**: On Windows `C:\netai` (use backslashes)

4. Save and close the editor

5. Restart Claude Desktop completely (quit and reopen the application)

#### Linux

1. Open Claude Desktop configuration file:
   ```bash
   nano ~/.config/Claude/claude_desktop_config.json
   ```

   Or navigate manually to: `~/.config/Claude/claude_desktop_config.json`

2. Add the netai server configuration:
   ```json
   {
     "mcpServers": {
       "netai": {
         "command": "uv",
         "args": [
           "--directory",
           "/home/YourUsername/netai",
           "run",
           "python",
           "server.py"
         ]
       }
     }
   }
   ```

3. **Important**: Replace `/home/YourUsername/netai` with the actual path to your netai folder

4. Save and close the editor (Ctrl+O, then Enter, then Ctrl+X if using nano)

5. Restart Claude Desktop completely

---

## Verifying Your Setup

After configuration, verify that everything works:

### For Claude Desktop
1. Open Claude Desktop
2. Start a conversation and mention "netai" or ask about network operations
3. You should see netai tools available in the tool use indicator

### For Warp
1. Open Warp
2. Invoke the netai server in a prompt context
3. You should be able to use netai tools in your workflow

---

## Troubleshooting

### Issue: "uv command not found"
**Solution**: UV is not installed or not in your PATH
- Reinstall UV using the instructions in [Prerequisites](#prerequisites)
- Restart your terminal/command prompt after installation

### Issue: "Python 3.12 or higher required"
**Solution**: Check your Python version
```bash
python --version
# or
python3 --version
```
- If you have an older version, download and install Python 3.12+ from [python.org](https://www.python.org/downloads/)

### Issue: Server fails to start with credential errors
**Solution**: Check your `.env` file
1. Ensure all required credentials are filled in
2. Check that credentials are correct (no extra spaces)
3. Ensure the `.env` file is in the root directory of the project

### Issue: Claude Desktop doesn't show netai tools
**Solution**:
1. Verify the configuration file is in the correct location
2. Check that the path in the configuration is correct and uses proper syntax (backslashes on Windows, forward slashes on macOS/Linux)
3. Completely restart Claude Desktop (don't just refresh)
4. Check the Claude Desktop console for error messages (Help > Logs)

### Issue: Warp can't find the configuration
**Solution**:
1. Verify the Warp configuration file exists at the correct location
2. Ensure the JSON syntax is valid (no missing commas or brackets)
3. Restart Warp completely
4. Check Warp logs for error messages

---

## Environment Variables Reference

The following environment variables can be configured in your `.env` file:

```
# Generic SSH
SSH_USERNAME=your_username
SSH_PASSWORD=your_password

# MikroTik REST API
MIKROTIK_USERNAME=your_username
MIKROTIK_PASSWORD=your_password
MIKROTIK_PORT=58080

# MikroTik SSH
MIKROTIK_SSH_USERNAME=your_username
MIKROTIK_SSH_PASSWORD=your_password
MIKROTIK_SSH_PORT=22

# Cisco APIC
APIC_HOST=apic.example.com
APIC_USERNAME=your_username
APIC_PASSWORD=your_password
APIC_VERIFY_SSL=false
APIC_TIMEOUT=30
APIC_TOKEN_CACHE_DURATION=3600

# Cisco NDFC
NDFC_HOST=ndfc.example.com
NDFC_USERNAME=your_username
NDFC_PASSWORD=your_password
NDFC_VERIFY_SSL=false

# Aruba WiFi Controller
ARUBA_IP=aruba.example.com
ARUBA_USERNAME=your_username
ARUBA_PASSWORD=your_password

# Palo Alto Firewall
PALOALTO_IP=firewall.example.com
PALOALTO_SSH_USERNAME=your_username
PALOALTO_SSH_PASSWORD=your_password

# Graylog
GRAYLOG_API_URL=http://graylog.example.com:9000/api/
GRAYLOG_USERNAME=your_username
GRAYLOG_PASSWORD=your_password

# LibreNMS
LIBRENMS_URL=http://librenms.example.com
LIBRENMS_API_TOKEN=your_api_token
```

---

## Additional Resources

- **CLAUDE.md**: Architecture and development guide for Claude Code
- **Project Repository**: For updates and contributing

---

## Support

For issues, questions, or feedback:
- Check the [Troubleshooting](#troubleshooting) section above
- Review the `CLAUDE.md` file for technical details
- Check your configuration files for syntax errors

---

## License

[Add your license information here]
