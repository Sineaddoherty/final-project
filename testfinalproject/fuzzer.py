import requests
import threading


class URlFuzz(threading.Thread):
 #-- connecting to URL
    def __init__(connect, website):
        threading.Thread.__init__(connect)
        connect.website = website
        connect.count = 0
        connect.results = []
        connect.current = ""

    def run(self):
     #-- connecting to listforfuzzer.txt, finding those on the url printing off
        for line in open('listforfuzzzer.txt').readlines():
            result = line
            self.current = self.website+result
            self.count = self.count
            request = requests.get(self.website+result)
        #-- public or private     
            if request.status_code == 200:
                self.results.append((result, 'OK'))
            elif request.status_code == 403:
                self.results.append((result, 'LOCKED'))
          


