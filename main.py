from seleniumwire import webdriver

wd = webdriver.Firefox()
res=wd.get("https://developer.microsoft.com/en-us/graph/graph-explorer")
input("Press Enter to continue...")
for request in wd.requests:
    print(request.headers.split("\n"))