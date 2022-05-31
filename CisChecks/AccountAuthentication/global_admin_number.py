from CisChecks.cis_check_model import AbstractCisCheck
import json

ROLES_LINK="https://graph.microsoft.com/v1.0/directoryRoles"
USERS_WITH_ROLE_LINK="https://graph.microsoft.com/v1.0/directoryRoles/{}/members?$select=id,userPrincipalName"

class GlobalAdminNumberCheck(AbstractCisCheck):
    
    # https://blog.atwork.at/medium.aspx?id=65b221f9-f6e3-402f-a166-2ba789d64efa&date=/post/2020/07/16/

    # Initialization with code and a short description
    code = "1.1.3"
    title = "Ensure that between two and four global admins are designated"

    # Retrieve from the security score the specific score and verify the compliance 
    @classmethod
    def check_compliance(self, session, graph_explorer_headers):
        global_admin_role_id = self.__get_global_admin_role_id(session, graph_explorer_headers)
        admins = self.__get_global_admins(session, graph_explorer_headers, global_admin_role_id)
        n_of_admins=len(admins)
        if(2 <= n_of_admins <= 4):
            print("[V] In the organization there is the recommended number of global admins")
        return 0

    def __get_global_admin_role_id(self, session, graph_explorer_headers):
        print("[*] Retrieving the directory roles...")
        res = session.get(ROLES_LINK, headers = graph_explorer_headers)
        # Check the response status code
        if(res.status_code == 200):
            print("[V] The directory roles has been correctly obtained")
            roles=json.loads(res.text)
            # Cycle over the roles until I find the one I am searching for
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
    
    def __get_global_admins(self, session, graph_explorer_headers, global_admin_role_id):
        print("[*] Retrieving the global administrators in the organization...")
        res = session.get(USERS_WITH_ROLE_LINK.format(global_admin_role_id), headers = graph_explorer_headers)
        # Check the response status code
        if(res.status_code == 200):
            print("[V] The directory roles has been correctly obtained")
            return json.loads(res.text)["value"]
        else:
            print("[X] A problem was encountered while sending the secure score request")
            print(res.text)
            exit(1)  