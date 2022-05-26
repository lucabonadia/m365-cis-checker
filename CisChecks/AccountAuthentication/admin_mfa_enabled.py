from CisChecks.cis_check_model import AbstractCisCheck

class AdminMFACheck(AbstractCisCheck):
    
    def __init__(self):
        self.code = "1.1.1"
        self.title = "Ensure multifactor authentication is enabled for all users in administrative roles"
    
    def make_check(security_score_object):
        print(score for score in security_score_object["value"]["controlScores"] if score["controlName"] == "AdminMFAV2")
        