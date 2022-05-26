from cgi import test
from seleniumwire import webdriver
import requests
import json
from CisChecks.AccountAuthentication.admin_mfa_enabled import AdminMFACheck

GRAPH_EXPLORER_LINK = "https://developer.microsoft.com/en-us/graph/graph-explorer"
SECURE_SCORE_LINK = "https://graph.microsoft.com:443/beta/security/secureScores"

def retrieve_graph_explorer_headers():
    
    # Create the webdriver
    firefox_webdriver = webdriver.Firefox()
    firefox_webdriver.get(GRAPH_EXPLORER_LINK)
    
    # Here the user has to perform the login on the exploerer

    input("[*] Perform the login, then press Enter to continue...")

    while(True):
        # It's better to cycle over the requests in reverse order, this avoid the function 
        # from retrieving an outdated Bearer
        for request in firefox_webdriver.requests[::-1]:
            # Check for the presence of the Bearer
            curr_auth_header = str(request.headers["Authorization"])
            if (curr_auth_header.startswith("Bearer")):
                print("[V] The authorization Bearer has been correctly retrieved")
                header_dict = dict(request.headers)
                # If the Bearer is found, return every header of that request, doing so makes the 
                # request flow less "artificial" from Microsoft perspective
                return header_dict
        
        # If the Bearer was not found, force its presence by sending any request on the Graph Explorer
        print("[X] Could not find the authorization Bearer in the performed requests")
        print("[*] Send any request with the graph explorer and try again...")
        input("[*] Perform a request, then press Enter to continue or Ctrl+C to exit...")

# Retrieve the security score calculated by Microsoft, as many checks can be done with it
def get_security_score(session, graph_explorer_headers):

    print("[*] Trying to retrieve the security score...")
    res = session.get(SECURE_SCORE_LINK, headers = graph_explorer_headers)
    # Check the response status code
    if(res.status_code == 200):
        print("[V] The secure score has been correctly obtained")
        return json.loads(res.text)
    else:
        print("[X] A problem was encountered while sending the secure score request")
        print(res.text)
        exit(1)

def main():

    graph_explrer_session = requests.session()
    graph_explorer_headers = retrieve_graph_explorer_headers()
    security_score = get_security_score(graph_explrer_session, graph_explorer_headers) 
    test_check = AdminMFACheck()
    test_check.make_check(security_score)

if __name__ == "__main__":
    main()