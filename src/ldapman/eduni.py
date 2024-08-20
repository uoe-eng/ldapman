#!/usr/bin/python

"""Constants for use with the Edinburgh University Central Authorisation service
defined at:

    https://www.wiki.ed.ac.uk/display/insite/IDM+Service+IDs+and+Codes

"""

codes = {'100': 'Active Directory',
 '105': 'Archive',
 '106': 'UoE (OCS) eDiary Service',
 '107': 'StaffMail',
 '108': 'StudentMail',
 '115': 'Dialup',
 '116': 'VPN',
 '117': 'Wireless',
 '118': 'LapLan',
 '120': 'Athens',
 '124': 'EASE',
 '125': 'Unix TimeShare',
 '127': 'Central Authorisation',
 '128': 'WebCT',
 '131': 'MIS MyEd Portal',
 '134': 'Central Wiki Service',
 '136': 'Exchange2007',
 '137': 'DiscussionForums',
 '139': 'PebblePad',
 '200': 'Office of Lifelong Learning Course Booking website',
 '202': 'CCD',
 '210': 'UNIDESK IDM Feed',
 '215': 'ECA Portal Feed',
 '220': 'eTime',
 '251': 'eRecruitment Employee Check',
 '252': 'Main HR Feed',
 '253': 'Learn 9'}

def genTable(s):
    """Given a string copied from the wiki while holding down ctrl (to copy in
    table mode) generate a dict definition."""

    codes = {}
    first = True
    for a in s.split('\n'):
        a = a.strip()
        if not a: continue
        if a[0] in '1234567890':
            key = a.strip()
        else:
            if first: # Skip the first line after a number. It's the service code.
                first = False
            else: # Store the second non-blank line. It's the english description.
                codes[key] = a.strip()
                first = True
    return codes

if __name__ == '__main__':
    import pprint
    import sys
    codes = genTable(sys.stdin.read())
    print('codes = ', end='')
    pprint.pprint(codes)
