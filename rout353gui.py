import boto3 as aws
from botocore import exceptions
import tkinter as tk
from tkinter import ttk
from tkinter.ttk import Combobox
from IPy import IP

LARGE_FONT = ("Verdana", 12)
NORM_FONT = ("Verdana", 10)
# creates the aws Session and client for access to route53 api
session = aws.Session(aws_access_key_id='AWS_KEY_ID',
                      aws_secret_access_key='AWS_KEY')
route53 = session.client('route53')


# Error popup for any exception to be handled
def errorpopup(message):
    popup = tk.Tk()
    popup.wm_title("!")
    label = ttk.Label(popup, text=message, font=NORM_FONT)
    label.pack(side="top", fill="x", pady=10)
    B1 = ttk.Button(popup, text="Okay", command=popup.destroy)
    B1.pack()
    popup.mainloop()


# popup message for testing if the hostname is being used and if there is a reverse for the ip address
def popupmsg(host_name, message):
    popup = tk.Tk()
    popup.wm_title("!")
    host_label = ttk.Label(popup, text=host_name + " is Available")
    host_label.pack()
    label = ttk.Label(popup, text=message, font=NORM_FONT)
    label.pack(side="top", fill="x", pady=10)
    B1 = ttk.Button(popup, text="Okay", command=popup.destroy)
    B1.pack()
    popup.mainloop()


# dropdown box for the domain names
class NewCombobox(Combobox):
    """
    Because the classic ttk Combobox does not take a dictionary for values.
    """

    def __init__(self, master, dictionary, *args, **kwargs):
        Combobox.__init__(self, master,
                          values=sorted(list(dictionary.keys())),
                          *args, **kwargs)
        self.dictionary = dictionary

    def get(self):
        if Combobox.get(self) == '':
            return ''
        else:
            return self.dictionary[Combobox.get(self)]


# Main Class to created the window for the application
class Route53Gui(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        #tk.Tk.iconbitmap(self, default="route53_Bas_icon.ico")
        tk.Tk.wm_title(self, "Route53Gui")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        menubar = tk.Menu(container)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Exit", command=exit)
        menubar.add_cascade(label="File", menu=filemenu)

        tk.Tk.config(self, menu=menubar)

        self.frame = {}

        for F in (StartPage, DNS_INPUT_PAGE):
            frame = F(container, self)

            self.frame[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)

    def show_frame(self, cont):
        frame = self.frame[cont]
        frame.tkraise()


# main page for the app to either accept or decline using this app, if declined i will quit the app
class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="""ALPHA DNS Entry Tool for Route53
        Please verify Entry is correct
        before submitting""", font="LARGE_FONT")
        label.pack(pady=10, padx=10)

        button1 = ttk.Button(self, text="Agree",
                             command=lambda: controller.show_frame(DNS_INPUT_PAGE))
        button1.pack()

        button2 = ttk.Button(self, text="Disagree",
                             command=quit)
        button2.pack()


class PageOne(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Page 1", font="LARGE_FONT")
        label.pack(pady=10, padx=10)

        button1 = ttk.Button(self, text="Back to Home",
                             command=lambda: controller.show_frame(StartPage))
        button1.pack()


# This is the function to test the Hostname and created the reverse ip for a reccord
# and check the reverse to she if it is active aswell.
def test(domain_name, domain, host, dns_record_type, host_or_ip):
    host = host.get()
    test = ''
    for key, name in domain.items():
        if name == domain_name.get():
            test = key
    domain = domain_name.get()
    host_name = host + '.' + test
    if dns_record_type.get() == 'A':

        try:
            # gets the host based of the domain selected and the host input in the main page of the app
            # if all fields are input
            alist = route53.list_resource_record_sets(HostedZoneId=domain, StartRecordType=dns_record_type.get(),
                                                      StartRecordName=host_name, MaxItems='1')
            # if not all the required fields are input then it will throw this error and produce a popup message
        except exceptions.ClientError:
            errorpopup(message='Please make sure you have supplyed all values needed')

            # this is to validate the ip adress is vaild if not i will throw an error popup

        try:
            i = IP(host_or_ip.get())
        except ValueError:
            errorpopup(message='Unknow IP address value')
            # this get the reverse of the ip address submmited with the in-addr.arpa. added to it
        addy = i.reverseName()
        # this is the for loop to check the record to see if hostname submited is available if not it will
        # throw an error popup
        for record in alist['ResourceRecordSets']:
            if record['Name'] == host_name:
                print('pass')
                print(record['Name'])
                for value in record['ResourceRecords']:
                    print(value['Value'])
                errorpopup(message=host_name + ' is not Available')

            else:
                # If elif statement to check to see if there a reverse for the ip address give, has already
                # been added to the
                # reverse zone.
                if '(first 3 octect of ipaddress)' in host_or_ip.get():
                    addy2 = route53.list_resource_record_sets(HostedZoneId='(reverse/hostzone file_name)',
                                                                StartRecordName=addy,
                                                                MaxItems='1')
                    #print(addy2)
                    for test2 in addy2['ResourceRecordSets']:
                        if test2['Name'] == addy:
                            message = addy + ' already there'
                            popupmsg(host_name, message)
                        else:
                            message = addy + " no record found"
                            popupmsg(host_name, message)
                    #print('ip')
                    #print(addy)
                elif '(first 3 octect of ipaddress)' in host_or_ip.get():
                    addy3 = route53.list_resource_record_sets(HostedZoneId='(reverse/hostzone file_name)',
                                                                StartRecordName=addy,
                                                                MaxItems='1')
                    #print(addy3)
                    for test1 in addy3['ResourceRecordSets']:
                        if test1['Name'] == addy:
                            message = addy + ' already there'
                            popupmsg(host_name, message)
                        else:
                            message = addy + " no record found"
                            popupmsg(host_name, message)
                    #print('ip')
                    #print(addy)
                    # popupmsg(host_name, addy, dns_record_type, domain, message)
    elif dns_record_type.get() == 'CNAME':
        #errorpopup(message='Not yet implumented ')
        try:
            # gets the host based of the domain selected and the host input in the main page of the app
            # if all fields are input
            cnamelist = route53.list_resource_record_sets(HostedZoneId=domain, StartRecordType=dns_record_type.get(),
                                                      StartRecordName=host_name, MaxItems='1')
            # if not all the required fields are input then it will throw this error and produce a popup message
        except exceptions.ClientError:
            errorpopup(message='Please make sure you have supplyed all values needed')
        for record in cnamelist['ResourceRecordSets']:
            if record['Name'] == host_name:
                print(record['Name'])
                errorpopup(message='there is a CNAME with that name')
            else:
                popupmsg(host_name, message='no CNAME found')

        # print(list)


def createawptr(domain_name, domain, host, dns_record_type, host_or_ip, TTL):
    hostzone = ''
    ip = IP(host_or_ip.get())
    addy = ip.reverseName()
    for key, name in domain.items():
        if name == domain_name.get():
            hostzone = key
    host_name = host.get() + '.' + hostzone
    domain_zone = domain_name.get()
    if '(first 3 octect of ipaddress)' in host_or_ip.get():
        responseA = route53.change_resource_record_sets(
            HostedZoneId=domain_zone,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': host_name,
                            'Type': 'A',
                            'TTL': int(TTL.get()),
                            'ResourceRecords': [
                                {
                                    'Value': host_or_ip.get()
                                },
                                ],
                            },
                        },
                        ]
            }
        )
        responseR = route53.change_resource_record_sets(
            HostedZoneId='(reverse/hostzone file_name)',
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': addy,
                            'Type': 'PTR',
                            'TTL': int(TTL.get()),
                            'ResourceRecords': [
                                {
                                    'Value': host_name
                                },
                                ],
                            },
                        },
                        ]
            }
        )
        #addy2 = route53.list_resource_record_sets(HostedZoneId='(reverse/hostzone file_name)',
                                                    #StartRecordName=addy,
                                                    #MaxItems='1')
        message = ("DNS record status %s " % responseA['ChangeInfo']['Status'] + '\n' +
                   "PTR record status " + responseR['ChangeInfo']['Status'])
        errorpopup(message)
    elif'(first 3 octect of ipaddress)' in host_or_ip.get():
        responseA = route53.change_resource_record_sets(
            HostedZoneId=domain_zone,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': host_name,
                            'Type': 'A',
                            'TTL': int(TTL.get()),
                            'ResourceRecords': [
                                {
                                    'Value': host_or_ip.get()
                                },
                            ],
                        },
                    },
                ]
            }
        )
        responseR = route53.change_resource_record_sets(
            HostedZoneId=(reverse/hostzone file_name),
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': addy,
                            'Type': 'PTR',
                            'TTL': int(TTL.get()),
                            'ResourceRecords': [
                                {
                                    'Value': host_name
                                },
                            ],
                        },
                    },
                ]
            }
        )
        # addy3 = route53.list_resource_record_sets(HostedZoneId='(reverse/hostzone file_name)',
        # StartRecordName=addy,
        # MaxItems='1')
        message = ("DNS record status %s " % responseA['ChangeInfo']['Status'] + '\n' +
                   "PTR record status " + responseR['ChangeInfo']['Status'])
        errorpopup(message)


def createcnameora(domain_name, domain, host, dns_record_type, host_or_ip, TTL):
    hostzone = ''
    for key, name in domain.items():
        if name == domain_name.get():
            hostzone = key
    host_name = host.get() + '.' + hostzone
    domain_zone = domain_name.get()
    if dns_record_type.get() == 'A':
        responseA = route53.change_resource_record_sets(
            HostedZoneId=domain_zone,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': host_name,
                            'Type': 'A',
                            'TTL': int(TTL.get()),
                            'ResourceRecords': [
                                {
                                    'Value': host_or_ip.get()
                                },
                            ],
                        },
                    },
                ]
            }
        )
        message = ("DNS record status %s " % responseA['ChangeInfo']['Status'])
        errorpopup(message)
    elif dns_record_type.get() == 'CNAME':
        responseA = route53.change_resource_record_sets(
            HostedZoneId=domain_zone,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'CREATE',
                        'ResourceRecordSet': {
                            'Name': host_name,
                            'Type': 'CNAME',
                            'TTL': int(TTL.get()),
                            'ResourceRecords': [
                                {
                                    'Value': host_or_ip.get()
                                },
                            ],
                        },
                    },
                ]
            }
        )
        message = ("DNS record status %s " % responseA['ChangeInfo']['Status'])
        errorpopup(message)


# Main page of the app where all the inputs and submits are done from.
class DNS_INPUT_PAGE(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="DNS Entry", font="LARGE_FONT")
        label.pack(pady=10, padx=10)
        aval = ''
        # button1 = ttk.Button(self, text="Back to Home",
        #                     command=lambda: controller.show_frame(StartPage))
        # button1.pack(side="bottom", fill="both", expand=False)

        hostedzones = route53.list_hosted_zones()
        # print(hostedzones)
        dns_record_type = tk.StringVar()
        dns_record = ttk.Combobox(self, textvariable=dns_record_type)
        dns_record.bind('<<ComboboxSelected>>')
        dns_record['values'] = ('A', 'CNAME')
        dns_record_label = ttk.Label(self, text="DNS Record Type")
        dns_record_label.pack()
        dns_record.pack(pady=10)

        zones = hostedzones['HostedZones']
        domains = {}
        for t in zones:
            domains.update({t['Name']: t['Id']})

        newcb = NewCombobox(self, dictionary=domains)
        newcb.pack()

        host = tk.StringVar()
        host_label = ttk.Label(self, text="Host")
        host_label.pack()
        host_entry = ttk.Entry(self, width=40, textvariable=host)
        host_entry.pack()
        TTL = tk.StringVar()
        TTL.set(value='86400')
        TTL_label = ttk.Label(self, text="TTL")
        TTL_label.pack()
        TTL_entry = ttk.Entry(self, width=40, textvariable=TTL)
        TTL_entry.get()
        TTL_entry.pack()
        host_or_ip = tk.StringVar()
        # label2 = tk.StringVar()
        host_or_ip_label = ttk.Label(self, text="IP Address or Existing Host")
        host_or_ip_label.pack()
        host_or_ip_entry = ttk.Entry(self, width=40, textvariable=host_or_ip)
        host_or_ip_entry.pack()

        buttontest = ttk.Button(self, text="test ip address and host name ",
                                command=lambda: test(newcb, domains, host, dns_record_type, host_or_ip))
        buttontest.pack()
        buttoncreateA= ttk.Button(self, text="create A record with PTR",
                                  command=lambda: createawptr(newcb, domains, host, dns_record_type, host_or_ip,
                                                              TTL))
        buttoncreateA.pack()
        buttoncrateCname = ttk.Button(self, text="Create CNAME or A record with no PTR",
                                      command=lambda: createcnameora(newcb, domains, host, dns_record_type, host_or_ip,
                                                              TTL))
        buttoncrateCname.pack()


app = Route53Gui()
app.mainloop()
