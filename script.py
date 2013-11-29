import requests
import httplib2
from bs4 import BeautifulSoup, SoupStrainer
import re

# Takes input from the user
url=raw_input("Enter the url: ")

class iframe:
    def __init__(self, url, height, width, obj):
        ''' Init function to receive all the inputs '''
        self.url=url
        self.height=width
        self.width=width
        self.url_count=len(url)
        self.obj=obj
        self.obj_count=len(obj)

    def display(self):
        ''' Display function '''
        for i in range(self.url_count):
            print "link: ", self.url[i]
            print "Height: ", self.height[i]
            print "Width: ", self.width[i]

        for i in range(self.obj_count):
            print "Data: ", self.obj[i]

        print "No of object tags: ", self.obj_count

if __name__=="__main__":
    ''' Main function '''

    source=[]
    height=[]
    width=[]
    obj=[]

    http = httplib2.Http()
    status, response = http.request(url)
    print 'Link: ', status['content-location']
    print 'Content type: ', status['content-type']
    print 'Status Code: ', status['status']

    # Parses only iframes lines from the response
    for link in BeautifulSoup(response, parse_only=SoupStrainer('iframe')):
        if hasattr(link, 'src'):
            source.append(link['src'])

        if hasattr(link, 'height'):
            height.append(link['height'])

        if hasattr(link, 'width'):
            width.append(link['width'])
        
    for link in BeautifulSoup(response, parse_only=SoupStrainer('object')):
        if hasattr(link, 'data'):
            obj.append(link['data'])

    frame = iframe(source, height, width, obj)
    frame.display()


