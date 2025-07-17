def manual_check_guide(GuideType: str):
    """
    Handles manual guides for the audit unhardening machine.

    Args:
        GuideType (str): The type of guide to return. Options are "locals", "service", or "network".
    
    Returns:
        str: The content of the requested guide.
    """

    locals = """
[Local Group Policy Check Guide]
-------------------------------------------------------------------------------------------------------------
Remember to check that these group policies are set properly to ensure that your nessus results are accurate
-------------------------------------------------------------------------------------------------------------
To start, Enter "Edit Group Policy" to access the group policy window (gpedit.msc)

[Path] User Configuration/Administrative/Templates/System
[Policy] Prevent Access to registry editing tools
[Security Settings] Disabled

[Path] Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/Deny access to this computer from the network
[Policy] Deny access to this computer from the network
[Security Settings] Ensure the account used is not in the list
[Futher information] If the account that is provided as credentials is in this list, Nessus will not work properly

[Path] Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/Access this computer from the network
[Policy] Access this computer from the network
[Security Settings] Ensure the account used is added in the list
[Futher information] If the account that is provided as credentials is not in this list, Nessus will not work properly

[Path] Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options
[Policy] Microsoft network server: Server SPN target name validation level
[Security Settings] Off

[Path] Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security
[Security Settings] Disabled all Firewall Or Add new rule to allow incoming and outgoing traffic from Tester to Host
"""

    Service = """
[Services]
-------------------------------------------------------------------------------------------------------------
If the following options are different, please take note of the configurations and amend them back to the original
settings after the audit.
-------------------------------------------------------------------------------------------------------------

Using services.msc, Ensure that "RemoteRegistry" is set to Automatic.

[Special Cases to take note]
If the following cases exists, please ensure they are set to Automatic as well.
Netlogon - Only if host is in a domain
Server - For Windows10 with Nessus Authentication Error
Security Account Manager - For Windows 10 with Nessus authentication Error
"""

    Network = """
[Network Adapter]
------------------------------------------------------------------------------------------------------------------
If the following options are different, please take note of the configurations and amend them back to the original
settings.
------------------------------------------------------------------------------------------------------------------
1.Right Click on the Local Area Connection used and click Properties
2.Ensure the following are ticked:
- QoS Packet Schedulers
- Internet Protocol Version 4 (TCP/IPV4)
- Clients for Microsoft Networks
- File and printer sharing for Microsoft Networks
"""

    if GuideType.lower() == "locals":
        return locals
    elif GuideType.lower() == "service":
        return Service
    elif GuideType.lower() == "network":
        return Network
    
def symantec_manual_guide(GuideType: str):
    """
    Provides a manual guide for checking the Symantec service.

    Args:
        GuideType (str): The type of guide to return. Options are "disable" or "enable".

    Returns:
        str: The content of the Symantec manual guide.
    """

    disable = """
Due to Symantec's protection against disabling its services through command prompt. Manual intervention is required to disable Symantec for Nessus.
If the status is for "(STATE" is 4 RUNNING), Auditor can follow these steps to disable Symantec
1. Press the Windows Key and R, User can also type "run" in the start menu.
2. Type "smc -stop"
3. Recheck the status of Symantec with the tool, double check manually that Symantec is completely disabled as well. The tool is not perfect D:
"""
    enable = """
Due to Symantec's protection against enabling its services through command prompt. Manual intervention is required to enable Symantec for Nessus.
If the status is for "(STATE" is 1 STOPPED), Auditor can follow these steps to enable Symantec
1. Press the Windows Key and R, User can also type "run" in the start menu.
2. Type "smc -start"
3. Recheck the status of Symantec with the tool, double check manually that Symantec is enabled as well. The tool is not perfect D:
"""
    if GuideType.lower() == "disable":
        return disable
    elif GuideType.lower() == "enable":
        return enable
