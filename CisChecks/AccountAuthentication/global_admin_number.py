from CisChecks.cis_check_model import AbstractCisCheck
import json

ROLES_LINK="https://graph.microsoft.com/v1.0/directoryRoles"

class AdminMFACheck(AbstractCisCheck):
    
    # https://blog.atwork.at/medium.aspx?id=65b221f9-f6e3-402f-a166-2ba789d64efa&date=/post/2020/07/16/

    # Initialization with code and a short description
    def __init__(self):
        self.code = "1.1.3"
        self.title = "Ensure that between two and four global admins are designated"
    
    # Retrieve from the security score the specific score and verify the compliance 
    def check_compliance(self, graph_explorer_bearer):
        return 0

    def get_global_admin_role_id(self, session, graph_explorer_headers):
        print("[*] Retrieving the directory roles...")
        res = session.get(ROLES_LINK, headers = graph_explorer_headers)
        # Check the response status code
        if(res.status_code == 200):
            print("[V] The directory roles has been correctly obtained")
            roles=json.loads(res.text)
            for role in roles["value"]:
                if role["displayName"] == "Global Administrator":
                    print("[V] Found the Global Administrator role id")
                    return role["id"]
            print("[X] Could not find the global administrator role among the roles obtained")
            exit(1)
        else:
            print("[X] A problem was encountered while sending the secure score request")
            print(res.text)
            exit(1)    
    
    def get_global_admins(self, session, global_admin_role_id):
        return 0