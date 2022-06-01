from CisChecks.cis_check_model import AbstractCisCheck

class AdminMFACheck(AbstractCisCheck):
    
    # Initialization with code and a short description
    code = "1.1.1"
    title = "Ensure multifactor authentication is enabled for all users in administrative roles"
    
    # TODO
    # Make again the check by verifying if an admin has associated an MFA authentication method
    # https://graph.microsoft.com/beta/users/[email]/authentication/methods
    # 

    # Retrieve from the security score the specific score and verify the compliance 
    @classmethod
    def check_compliance(self, security_score_object):
        try:
            # Cycle over the control scores
            for score in security_score_object["value"][0]["controlScores"]:
                # Check 
                if score["controlName"] == "AdminMFAV2":
                    print("[*] Found the admin MFA control score...")
                    if score["IsEnforced"] == "true":
                        print("--> [V] Every admin has the MFA enabled")
                        res = True
                    else:
                        print("--> [X] Not every admin has the MFA enabled")
                        res = False
                    return res
        except KeyError:
            print("--> [X] Could not find the correct control score")