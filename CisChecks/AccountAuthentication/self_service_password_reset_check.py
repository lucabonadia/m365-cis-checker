from CisChecks.cis_check_model import AbstractCisCheck
import json

import requests
requests.packages.urllib3.disable_warnings()

PROXY = "http://127.0.0.1:8080"
VERIFY_CERTS = False

SELF_PASSWORD_RESET_LINK="https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=true"

class SelfServicePasswordResetCheck(AbstractCisCheck):
    
    # Initialization with code and a short description
    code = "1.1.4"
    title = "Ensure self-service password reset is enabled"

    # Retrieve from the security score the specific score and verify the compliance 
    @classmethod
    def check_compliance(self, session, azure_portal_headers):
        response_content = self.__get_self_service_password_enablement_status(session, azure_portal_headers)
        self_service_password_reset_status = response_content["enablementType"]
        if (self_service_password_reset_status == 0):
                print("--> [V] Every user has the self service password reset enabled")
                return True
        elif (self_service_password_reset_status == 1):
                print("--> [X] Only a subgroup of users has the self service password reset enabled")
                return False
        else:
            print("--> [X] No user has the self service password reset enabled")
            return False

    def __get_self_service_password_enablement_status(session, azure_portal_headers):
        print("[*] Retrieving the status of self service password reset...")
        print(azure_portal_headers)
        # Proxied request
        # res = session.get(SELF_PASSWORD_RESET_LINK, headers = azure_portal_headers, proxies={"http": PROXY, "https": PROXY}, verify=VERIFY_CERTS)
        res = session.get(SELF_PASSWORD_RESET_LINK, headers = azure_portal_headers)
        # Check the response status code
        if (res.status_code == 200):
            print("[*] The status of self service password reset has been obtained")
            return json.loads(res.text)
        else:
            print("--> [X] A problem was encountered while sending the service password reset status request")
            print(res.text)
            exit(1)    