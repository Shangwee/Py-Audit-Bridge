import paramiko
from fastmcp import FastMCP
from utilities.batFileContentHandler import handle_bat_file_content
from utilities.manualGuidesHandler import manual_check_guide, symantec_manual_guide
import tempfile
import os
import re
import datetime


mcp = FastMCP("My MCP Server")

# initialize the ssh handler
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# You can also add instructions for how to interact with the server
mcp_with_instructions = FastMCP(
    name="Audit unhardening machine",
    instructions="""
You are an AI security assistant integrated with an MCP-compatible system. Your role is to assist users in performing security configuration checks, remote audits, and hardening actions on Windows systems through the Audit Bridge MCP tool.

When asked to perform a task (e.g., check if Symantec is running, enable firewall, or revert registry changes), you must:
1. Identify the relevant tool from the MCP tool list.
2. Construct a valid MCP `tools/call` request using the tool name and required arguments (e.g., `host`, `username`, `password`).
3. Explain what the tool does and what the user should expect.
4. Present the results clearly using plain language, and include the raw output if useful.
5. If an error occurs, explain the cause and recommend next steps (e.g., check credentials or network access).
    """,
    tools=[mcp.tool(name="audit_setup", description="Perform initial setup for the audit unhardening machine"), 
           mcp.tool(name="check_registry", description="Check registry settings on the machine"),
           mcp.tool(name="add_registry_keys", description="Add registry keys using the add-registry-keys.bat script"),
           mcp.tool(name="delete_registry_keys", description="Delete registry keys using the delete-registry-keys.bat script"),
           mcp.tool(name="revert_registry_keys", description="Revert registry keys using the revert-registry-keys.bat script"),
           mcp.tool(name="check_symantec_service", description="Check if the Symantec service is running"),
           mcp.tool(name="check_firewall", description="Check the firewall status on the machine"),
           mcp.tool(name="enable_firewall", description="Enable the firewall on the machine"),
           mcp.tool(name="disable_firewall", description="Disable the firewall on the machine"),
           mcp.tool(name="view_log_file", description="View the log file for the audit unhardening machine")]
)

def log_and_run(log_file: str, label: str, raw_command: str):
    """
    Log a command execution with label to a file and then execute it.
    
    Args:
        log_file: Path to the log file
        label: Label for this command execution
        raw_command: The command to execute
    
    Returns:
        The output of the command execution
    """
    # Escape quotes in command for PowerShell
    escaped_cmd = raw_command.replace('"', '`"')
    
    # Create PowerShell command that logs and executes
    powershell_command = f"""
    Add-Content -Path '{log_file}' '[{label}]';
    Add-Content -Path '{log_file}' 'Command: {raw_command.replace("'", "''")}';
    {escaped_cmd};
    """.strip()
    
    # Remove newlines for the final encoded command
    encoded = powershell_command.replace('\n', ' ')
    
    # Execute the command
    stdin, stdout, stderr = ssh.exec_command(f'powershell -NoProfile -Command "{encoded}"')
    output = stdout.read()
    error = stderr.read()
    
    return output, error

@mcp.tool(
    name = "audit_setup", 
    description = "Perform initial setup for the audit unhardening machine."
)
async def audit_setup(host: str, username: str, password: str):
    """
    Perform initial setup for the audit unhardening machine.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the results of the setup, including registry exports and values for SMB1, AutoShareWks, AutoShareServer, and LocalAccountTokenFilterPolicy.
        If an error occurs, it will include an 'error' key with the error message.  
    """

    toolsDir = "C:\\Tools"

    registryKeyExport = {
        "parameter": f"reg export HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters {toolsDir}\\Parameters.reg /y",
        "System": f"reg export HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System {toolsDir}\\System.reg /y"
    }

    registryQueryCommands = {
        "SMB1": f"reg query \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB1",
        "AutoShareWks": f"reg query \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v AutoShareWks",
        "AutoShareServer": f"reg query \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v AutoShareServer",
        "LocalAccountTokenFilterPolicy": f"reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy"
    }

    # Generate timestamp and log file paths
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"
    
    results = {}

    try: 
        ssh.connect(hostname=host, username=username, password=password)

        # create log directory if it doesn't exist
        stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "New-Item -ItemType Directory -Path \'{log_dir}\' -Force"')

        # ** import bat tools
        addbat = handle_bat_file_content("add")
        deleteBatContent = handle_bat_file_content("delete")
        removeBatContent = handle_bat_file_content("remove")

        # Create temporary files for the BAT scripts
        with tempfile.NamedTemporaryFile(suffix='.bat', delete=False) as add_bat_file:
            add_bat_path = add_bat_file.name
            add_bat_file.write(addbat.encode())

        with tempfile.NamedTemporaryFile(suffix='.bat', delete=False) as delete_bat_file:
            delete_bat_path = delete_bat_file.name
            delete_bat_file.write(deleteBatContent.encode())

        with tempfile.NamedTemporaryFile(suffix='.bat', delete=False) as revert_bat_file:
            revert_bat_path = revert_bat_file.name
            revert_bat_file.write(removeBatContent.encode())

        # Ensure tools directory exists
        stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "New-Item -ItemType Directory -Path \'{toolsDir}\' -Force"')

        # log command execution
        log_and_run(log_file, "Create Tools Directory", f"New-Item -ItemType Directory -Path '{toolsDir}' -Force")

        stdout.read()

        # Define remote paths
        remote_add_bat = f"{toolsDir}\\add-registry-keys.bat"
        remote_delete_bat = f"{toolsDir}\\delete-registry-keys.bat"
        remote_revert_bat = f"{toolsDir}\\revert-registry-keys.bat"

        # Upload the files using SFTP
        sftp = ssh.open_sftp()
        sftp.put(add_bat_path, remote_add_bat)
        sftp.put(delete_bat_path, remote_delete_bat)
        sftp.put(revert_bat_path, remote_revert_bat)
        sftp.close()

        # Log the upload of .bat files
        log_and_run(log_file, "Upload Bat Files", f"copy '{add_bat_path}' '{remote_add_bat}'; copy '{delete_bat_path}' '{remote_delete_bat}'; copy '{revert_bat_path}' '{remote_revert_bat}'")

        # Clean up local temporary files
        os.unlink(add_bat_path)
        os.unlink(delete_bat_path)
        os.unlink(revert_bat_path)

        results['Upload Bat Files for execution'] = f"Successfully uploaded .bat files to {toolsDir}"

        # ** export registry keys
        for key, command in registryKeyExport.items():
            stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "{command}"')
            # Log the export command
            log_and_run(log_file, f"Export Registry Key: {key}", command)
            # Export registry keys and log the results
            results['registry_exports'] = {}
            for key, command in registryKeyExport.items():
                stdout.read()  # Read any output
                error_output = stderr.read().decode().strip()
                if error_output:
                    results[f'Export Registry Key: {key}'] = f"Error: {error_output}"
                else:
                    
                    results[f'Export Registry Key: {key}'] = f"Successfully exported {key} registry key"
                    results['registry_exports'][key] = f"{toolsDir}\\{key}.reg"

        # ** query registry keys
        # Query registry keys and store results
        results['registry_values'] = {}
        for key, command in registryQueryCommands.items():
            stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "{command}"')
            # Log the query command
            log_and_run(log_file, f"Export Registry Key: {key}", command)
            output = stdout.read().decode()
            error = stderr.read().decode().strip()
            
            if "unable to find" in error or "ERROR" in output:
                results['registry_values'][key] = "not found"
            else:
                match = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)', output)
                if match:
                    results['registry_values'][key] = str(int(match.group(1), 16))
                else:
                    results['registry_values'][key] = "unknown"

        # ** Check Symantec service
        stdin, stdout, stderr = ssh.exec_command('powershell -Command "sc query SepMasterService"')
        # log the command execution
        log_and_run(log_file, "Check Symantec Service", "sc query SepMasterService")
        sep_output = stdout.read().decode()
        
        # Extract service state using regex
        state_match = re.search(r'STATE\s+:\s+\d+\s+(\w+)', sep_output)
        results['services'] = results.get('services', {})
        results['services']["SepMasterService"] = state_match.group(1) if state_match else "Not found"

        # ** check firewall
        stdin, stdout, stderr = ssh.exec_command('netsh advfirewall show allprofiles state')
        fw_output = stdout.read().decode()

        profile_states = {
            "DomainProfile": "unknown",
            "PrivateProfile": "unknown",
            "PublicProfile": "unknown"
        }

        lines = fw_output.split('\n')
        current_profile = None

        for line in lines:
            if "Domain Profile Settings" in line:
                current_profile = "DomainProfile"
            elif "Private Profile Settings" in line:
                current_profile = "PrivateProfile"
            elif "Public Profile Settings" in line:
                current_profile = "PublicProfile"
            elif current_profile and re.search(r'^\s*State\s*:?', line, re.IGNORECASE):
                match = re.search(r'State\s*:?\s*(\w+)', line, re.IGNORECASE)
                if match:
                    profile_states[current_profile] = match.group(1).upper()
                current_profile = None

        results['firewall'] = profile_states

        # ** check IP address
        # Get IPv4 addresses command
        ipcmd = "(Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -notlike '169.*' }).IPAddress"
        # Log the command execution
        log_and_run(log_file, "Get IPv4 Addresses", ipcmd)

        # Execute command to get IP addresses
        stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "{ipcmd}"')
        ip_output = stdout.read().decode().strip()

        # Process IP addresses - split by newlines and filter out empty strings
        if ip_output:
            results['network'] = results.get('network', {})
            results['network']['IPv4Addresses'] = [ip for ip in ip_output.split('\n') if ip]
        else:
            results['network'] = results.get('network', {})
            results['network']['IPv4Addresses'] = []

        # return results
        return results
    except Exception as e:
        # Log the error
        results['error'] = str(e)
        results['registry_exports'] = {}
        results['registry_values'] = {}
        results['services'] = {}
        results['firewall'] = {}
        results['network'] = {}
        return results
    finally:
        # Ensure SSH connection is closed
        ssh.close()

@mcp.tool(
    name = "check_registry", 
    description = "Check registry settings on the machine."
)
async def check_registry(host: str, username: str, password: str):
    '''
    Check registry settings on the machine.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the results of the registry checks, including values for SMB1, AutoShareWks, AutoShareServer, and LocalAccountTokenFilterPolicy.
        If an error occurs, it will include an 'error' key with the error message.
    '''


    # timestamp and log file paths
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    registryQueryCommands = {
        "SMB1": f"reg query \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB1",
        "AutoShareWks": f"reg query \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v AutoShareWks",
        "AutoShareServer": f"reg query \"HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v AutoShareServer",
        "LocalAccountTokenFilterPolicy": f"reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy"
    }

    results = {}

    try:
        ssh.connect(hostname=host, username=username, password=password)

        # Query registry keys and store results
        results['registry_values'] = {}
        for key, command in registryQueryCommands.items():
            stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "{command}"')
            # Log the query command
            log_and_run(log_file, f"Export Registry Key: {key}", command)
            output = stdout.read().decode()
            error = stderr.read().decode().strip()
            
            if "unable to find" in error or "ERROR" in output:
                results['registry_values'][key] = "not found"
            else:
                match = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)', output)
                if match:
                    results['registry_values'][key] = str(int(match.group(1), 16))
                else:
                    results['registry_values'][key] = "unknown"

        return results
    except Exception as e:
        # Log the error
        results['error'] = str(e)
        results['registry_values'] = {}
        return results
    finally:
        # Ensure SSH connection is closed
        ssh.close()

@mcp.tool(
    name = "add_registry_keys",
    description = "Add registry keys using the add-registry-keys.bat script."
)
async def add_registry_keys(host: str, username: str, password: str):
    """
    Add registry keys using the add-registry-keys.bat script.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the output of the command execution.
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    toolsDir = "C:\\Tools"
    remote_bat_path = f"{toolsDir}\\add-registry-keys.bat"
    
    try:
        ssh.connect(hostname=host, username=username, password=password)
        # Execute the BAT file
        output, error = log_and_run(log_file, "Add Registry Keys", f"cmd /c {remote_bat_path}")

        if error:
            return {"error": error.decode().strip()}
        return {"output": output.decode().strip()}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "delete_registry_keys",
    description = "Delete registry keys using the delete-registry-keys.bat script."
)
async def delete_registry_keys(host: str, username: str, password: str):
    """
    Delete registry keys using the delete-registry-keys.bat script.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the output of the command execution.
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    toolsDir = "C:\\Tools"
    remote_bat_path = f"{toolsDir}\\delete-registry-keys.bat"
    
    try:
        ssh.connect(hostname=host, username=username, password=password)
        # Execute the BAT file
        output, error = log_and_run(log_file, "Delete Registry Keys", f"cmd /c {remote_bat_path}")

        if error:
            return {"error": error.decode().strip()}
        return {"output": output.decode().strip()}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "revert_registry_keys",
    description = "Revert registry keys using the revert-registry-keys.bat script."
)
async def revert_registry_keys(host: str, username: str, password: str):
    """
    Revert registry keys using the revert-registry-keys.bat script.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the output of the command execution.
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    toolsDir = "C:\\Tools"
    remote_bat_path = f"{toolsDir}\\revert-registry-keys.bat"
    
    try:
        ssh.connect(hostname=host, username=username, password=password)
        # Execute the BAT file
        output, error = log_and_run(log_file, "Revert Registry Keys", f"cmd /c {remote_bat_path}")

        if error:
            return {"error": error.decode().strip()}
        return {"output": output.decode().strip()}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "check_symantec_service",
    description = "Check if the Symantec service is running."
)
async def check_symantec_service(host: str, username: str, password: str):
    """
    Check if the Symantec service is running.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the state of the Symantec service.
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    try:
        ssh.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command('powershell -Command "sc query SepMasterService"')
        # Log the command execution
        log_and_run(log_file, "Check Symantec Service", 'powershell -Command "sc query SepMasterService"')
        sep_output = stdout.read().decode()
        
        # Extract service state using regex
        state_match = re.search(r'STATE\s+:\s+\d+\s+(\w+)', sep_output)
        return {"SepMasterService": state_match.group(1) if state_match else "Not found"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "check_firewall",
    description = "Check the firewall status on the machine."
)
async def check_firewall(host: str, username: str, password: str):
    """
    Check the firewall status on the machine.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the firewall status for each profile (Domain, Private, Public).
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    try:
        ssh.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command('netsh advfirewall show allprofiles state')
        # Log the command execution
        log_and_run(log_file, "Check Firewall Status", 'netsh advfirewall show allprofiles state')
        fw_output = stdout.read().decode()

        profile_states = {
            "DomainProfile": "unknown",
            "PrivateProfile": "unknown",
            "PublicProfile": "unknown"
        }

        lines = fw_output.split('\n')
        current_profile = None

        for line in lines:
            if "Domain Profile Settings" in line:
                current_profile = "DomainProfile"
            elif "Private Profile Settings" in line:
                current_profile = "PrivateProfile"
            elif "Public Profile Settings" in line:
                current_profile = "PublicProfile"
            elif current_profile and re.search(r'^\s*State\s*:?', line, re.IGNORECASE):
                match = re.search(r'State\s*:?\s*(\w+)', line, re.IGNORECASE)
                if match:
                    profile_states[current_profile] = match.group(1).upper()
                current_profile = None

        return {"firewall": profile_states}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "enable_firewall",
    description = "Enable the firewall on the machine."
)
async def enable_firewall(host: str, username: str, password: str):
    """
    Enable the firewall on the machine.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the result of the firewall enable operation.
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    try:
        ssh.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command('netsh advfirewall set allprofiles state on')
        # Log the command execution
        log_and_run(log_file, "Enable Firewall", 'netsh advfirewall set allprofiles state on')
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            return {"error": error}
        return {"output": output}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "disable_firewall",
    description = "Disable the firewall on the machine."
)
async def disable_firewall(host: str, username: str, password: str):
    """
    Disable the firewall on the machine.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the result of the firewall disable operation.
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    try:
        ssh.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command('netsh advfirewall set allprofiles state off')
        # Log the command execution
        log_and_run(log_file, "Disable Firewall", 'netsh advfirewall set allprofiles state off')
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            return {"error": error}
        return {"output": output}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "view_log_file",
    description = "View the log file for the audit unhardening machine."
)
async def view_log_file(host: str, username: str, password: str):
    """
    View the log file for the audit unhardening machine.

    Args:
        host: The hostname or IP address of the machine.
        username: The username for SSH authentication.
        password: The password for SSH authentication.

    Returns:
        A dictionary containing the contents of the log file.
        If an error occurs, it will include an 'error' key with the error message.
    """
    # log file path
    log_dir = f"C:\\AuditLogs\\{datetime.datetime.now().strftime('%Y%m%d')}"
    log_file = f"{log_dir}\\audit-log.txt"

    try:
        ssh.connect(hostname=host, username=username, password=password)
        # Ensure the log file exists
        stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "Test-Path -Path \'{log_file}\'"')
        log_exists = stdout.read().decode().strip() == "True"
        if not log_exists:
            return {"error": "Log file does not exist."}
        # Read the log file contents
        stdin, stdout, stderr = ssh.exec_command(f'powershell -Command "Get-Content -Path \'{log_file}\'"')
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error:
            return {"error": error}
        return {"log_contents": output}
    except Exception as e:
        return {"error": str(e)}
    finally:
        ssh.close()

@mcp.tool(
    name = "manual_check_guide",
    description = "Get manual guides for the audit unhardening machine."
)
async def manual_check_guide_tool(GuideType: str):
    """
    Get manual guides for the audit unhardening machine.

    Args:
        GuideType (str): The type of guide to return. Options are "locals", "service", or "network".

    Returns:
        A string containing the content of the requested guide.
    """
    return manual_check_guide(GuideType)

@mcp.tool(
    name = "symantec_manual_guide",
    description = "Get manual guides for checking the Symantec service."
)
async def symantec_manual_guide_tool(GuideType: str):
    """
    Get manual guides for checking the Symantec service.

    Args:
        GuideType (str): The type of guide to return. Options are "disable" or "enable".

    Returns:
        A string containing the content of the requested guide.
    """
    return symantec_manual_guide(GuideType)


if __name__ == "__main__":
    mcp.run()