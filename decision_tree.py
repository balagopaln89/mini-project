#!/usr/bin/python
import Tkinter
import urllib2
from bs4 import BeautifulSoup
import os
import re

class simpleapp(Tkinter.Tk):
    def __init__(self,parent):
        Tkinter.Tk.__init__(self,parent)
        self.parent = parent
        self.initialize()

    def initialize(self):
        #Setting up the graphical user interface
        self.grid()
        frame = Tkinter.Frame(self, relief="sunken", width=1200, height=700)
        frame.grid(column=0,row=0)
        frame.rowconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)
        frame.columnconfigure(0, weight=3)
        frame.columnconfigure(1, weight=3)
        frame.columnconfigure(2, weight=1)
        self.textinput = Tkinter.Entry(frame,width=80)
        button1 = Tkinter.Button(frame,text="Click to execute",command=self.OnButtonClick)
        self.textinput.grid(column=1,row=0,padx=(5,0),pady=(20,0))
        button1.grid(column=2,row=0,pady=(20,0), sticky='W',padx=(5,0))
        self.labelvariable1=Tkinter.StringVar()
        self.labelvariable2=Tkinter.StringVar()
        self.labelvariable3=Tkinter.StringVar()
        self.labelvariable4=Tkinter.StringVar()
        self.labelvariable5=Tkinter.StringVar()
        self.labelvariable6=Tkinter.StringVar()
        self.labelvariable7=Tkinter.StringVar()
        self.labelvariable8=Tkinter.StringVar()
        self.labelvariable9=Tkinter.StringVar()
        mycolor = '#%02x%02x%02x' % (238, 238, 238)
        self.label1 = Tkinter.Label(frame,textvariable=self.labelvariable1,fg="white")
        self.label1.grid(column=0,row=1,sticky='E')
        self.label2 = Tkinter.Label(frame,textvariable=self.labelvariable2,fg="white")
        self.label2.grid(column=1,row=1,sticky='W')
        self.label4 = Tkinter.Label(frame,textvariable=self.labelvariable4,fg="white", wraplength=150)
        self.label4.grid(column=2,row=1,sticky='W')
        self.label5 = Tkinter.Label(frame,textvariable=self.labelvariable5,wraplength=150, fg="white")
        self.label5.grid(column=3,row=1,sticky='W')
        self.label6 = Tkinter.Label(frame,textvariable=self.labelvariable6,fg="white", wraplength=150)
        self.label6.grid(column=4,row=1,sticky='W')
        self.label7 = Tkinter.Label(frame,textvariable=self.labelvariable7,fg="white", wraplength=150)
        self.label7.grid(column=5,row=1,sticky='W')
        self.label8 = Tkinter.Label(frame,textvariable=self.labelvariable8,fg="white", wraplength=150)
        self.label8.grid(column=6,row=1,sticky='W')
        self.label9 = Tkinter.Label(frame,textvariable=self.labelvariable9,fg="white")
        self.label9.grid(column=0,row=3,sticky=('N', 'S', 'E', 'W'))
        self.label3 = Tkinter.Label(frame,textvariable=self.labelvariable3,fg="white")
        self.label3.grid(column=0,row=0,sticky='W', pady=(20,0))
        self.labelvariable3.set("URL to analyse :")
        self.label3.configure(bg='gray', fg='white')

    def OnButtonClick(self):
        #handling the button click
        url_input = self.textinput.get()
        frames_cnt = 0
        script_cnt = 0
        static_frames = 0
        if url_input != "":
            """txdata = None
            txheaders = {   
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
            'Accept-Language': 'en-us',
            'Accept-Encoding': 'gzip, deflate, compress;q=0.9',
            'Keep-Alive': '300',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            }
            req_site = urllib2.Request(url_input, txdata, txheaders)"""
            get = urllib2.urlopen(url_input).read()
            dom = BeautifulSoup(get)
            #fetching all iframes in page
            iframe_data = dom.findAll('iframe')
            iframe_analysis = []
            for i in iframe_data:
                frames_cnt = int(frames_cnt)+1
                #calling function to analyse each frame
                res = self.analyze_iframe(i)
                if isinstance(res,list):
                    iframe_analysis.append(res)
                else:
                    static_frames = int(static_frames)+1			

            label_var = "Total of "+ str(frames_cnt) +" frame(s) found.\n\n\n"
            frames_cnt=0
            mal_frames=0
            tot_object=0
            tot_embed=0
            iframe_no_size=0
            links_label = "Suspicious URL's\n"
            for i in iframe_analysis:
                if i!= None:
                    frames_cnt = int(frames_cnt)+1
                    try:
                        label_var = label_var + "iFrame " + str(frames_cnt) + " Height :"+str(i[0][0])+" Width :"+str(i[0][1])+"\n"
                        if ((int(i[0][0]) < 10) or (int(i[0][1]) < 10)):
                            mal_frames = int(mal_frames)+1
                            links_label = links_label+"\n"+str(i[3])
                        if(int(i[1])>0):
                            tot_object = int(tot_object)+1
                        if(int(i[2])>=4):
                            tot_embed = int(tot_embed)+1
                    except IndexError:
                        pass		

            self.labelvariable1.set(label_var)
            self.labelvariable4.set(links_label)
            
            escape_label="Escape functions status: \n"
            self.labelvariable5.set(escape_label)
            escape_count=0
            space_label="White space status: \n"
            self.labelvariable5.set(space_label)
            space_count=0
            char_count=0
            script_data = dom.findAll('script')
            for script in script_data:
                for line in script:
                    char_count = char_count + len(line)
                    space_count = space_count + (len(line) - len(line.lstrip()))

            escape_fun="Escape functions\n"
            escape_data = dom.findAll('escape')
            for escape in escape_data:
                escape_count = escape_count + 1
                escape_fun + escape_fun + escape
            self.label7.configure(bg='black', fg='white')
            self.labelvariable9.set(escape_fun)

            space_percent = ( space_count / char_count ) * 100
            
            eval_data = dom.findAll('eval')
            eval_count = 0
            for i in eval_data:
                eval_count = eval_count + 1

            eval_label="No of eval functions: " + str(eval_count) + "\n"
            self.label7.configure(bg='black', fg='white')
            self.labelvariable7.set(eval_label) 

            vb_data = dom.findAll('VBScript')
            vb_count = 0
            vb_label="Malicious VB scripts\n"
            for i in vb_data:
                vb_count = vb_count + 1
            if vb_count > 0:
                vb_label=vb_label + "We have found " + str(vb_count) + " VB Scripts. There's a possibility of malicious code injection\n"
            else:
                vb_label=vb_label + "No VB Scripts found\n"

            self.labelvariable8.set(vb_label)
            self.label8.configure(bg='black', fg='white')


            self.labelvariable7.set(eval_label) 
            if((mal_frames >= 1) or (tot_object > 0) or (tot_embed >= 4)):
                self.label1.configure(bg='blue')
                self.label2.configure(bg='red')
                self.label4.configure(bg='blue')
                self.label5.configure(bg='black')
                self.label6.configure(bg='white',fg='black')
                self.label7.configure(bg='white',fg='black')
                self.label8.configure(bg='white',fg='black')
                lab_var1 = "Suspicious content found !\n"
                lab_var1 = lab_var1+"\n\n Total of "+str(mal_frames)+" suspiciously \n"
                lab_var1 = lab_var1+"small frames found !\n\n"
                lab_var1 = lab_var1+"Total of "+str(tot_object)+" object tags \n\n"
                lab_var1 = lab_var1+"Total of "+str(tot_embed)+" embed tags"
                lab_var1 = lab_var1+"\n\n Total of "+str(static_frames)+ " static frames\n\n"
                self.labelvariable2.set(lab_var1)

            else:
                self.label2.configure(bg='green')
                self.label1.configure(bg='blue')
                lab_var1 = "Advertisement is safe !"
                lab_var4 = "No Suspicious URL found!"
                self.labelvariable4.set(lab_var4)
                self.labelvariable2.set(lab_var1)

            if escape_count > 0:
                escape_label = escape_label + "Found " + str(escape_count) + " escape functions\n"
            else:
                escape_label = escape_label + "Couldn't find any escape functions\n"
            self.labelvariable5.set(escape_label)
            if space_percent > 30:
                space_label = space_label + "There are " + str(space_count) + " white spaces\nHeavily obfuscated\n"
            else:
                space_label = space_label + "There are " + str(space_count) + " white spaces\nNo white space obfuscation found\n"
            self.labelvariable6.set(space_label)

    def getContentType(self,pageUrl):
        try:
            page = urllib2.urlopen(pageUrl)
            pageHeaders = page.headers
            contentType = pageHeaders.getheader('content-type')
            return contentType
        except Exception:
            return "unknown"

    def analyze_iframe(self,iframe_ana):
        iframe_child_ans=[]
        iframe_size=[]
        object_cnt=0
        embed_cnt=0
        h = iframe_ana.get('height')
        w = iframe_ana.get('width') 
        try:
            if((h.isdigit()) and (w.isdigit())):
                iframe_size.append(h)
                iframe_size.append(w)
            elif((len(h)>0) and (len(w)>0)):
                iframe_escaped = True		
        except Exception:
            pass
        new_url = iframe_ana.get('src')
        file_type = self.getContentType(new_url)
        #checking if the url points to an html page
        if('html' in file_type):
            iframe_child_ans.append(iframe_size)
            child_get = urllib2.urlopen(new_url).read()
            child_dom = BeautifulSoup(child_get)
            object_data = child_dom.findAll('object')
            embed_data = child_dom.findAll('embed')
            for i in object_data:
                object_cnt = int(object_cnt)+1
            for i in embed_data:
                embed_cnt = int(embed_cnt)+1
            iframe_child_ans.append(object_cnt)
            iframe_child_ans.append(embed_cnt)
            iframe_src = iframe_ana.get('src')
            iframe_child_ans.append(iframe_src)
            return iframe_child_ans
        else:
            return "not_dynamic"

    def analyze_javascript(self):
        print 

if __name__ == "__main__":
    app = simpleapp(None)
    app.title('Amrita - Malicious Advertisement Analyzer')
    app.mainloop()
