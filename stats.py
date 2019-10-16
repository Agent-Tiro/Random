import sys
import pandas as pd
import numpy as np

#Take filename as cmdline arg or prompt user for it
if len(sys.argv) == 1:
    print("You can also give the filename as a command line argument")
    filename = input("Enter Filename: ")
else:
    filename = sys.argv[1]

#Load csv up with only the relevant columns
df = pd.read_csv(
        filename,
        usecols=['CVSS', 'Risk', 'Host', 'Name']
        )

#Remove all NaN / informational items / and duplicate rows                                            
df = df.dropna(subset=['CVSS'])         
df = df.drop_duplicates()               

#only displays rows of that Risk level
#df = df.loc[(df['Risk'] == 'Critical')] 
#df = df.loc[(df['Risk'] == 'High')]
#df = df.loc[(df['Risk'] == 'Medium')]
df1 = df.loc[(df['CVSS'] > 6.9)]

#Create Excel Writer object
with pd.ExcelWriter('test.xlsx') as writer:

    #Display Hosts with most High and above vulnerabilities
    HostsHighVuln = df1.groupby(['Host'])['Host']\
            .count()\
            .reset_index(name='Number of Vulnerabilities')\
            .sort_values(['Number of Vulnerabilities'], ascending=False)\
            .head(5)

    HostsHighVuln.to_excel(writer,
            sheet_name='Hosts High+ Vuln')

    #Display Hosts with most vulnerabilities
    HostsAllVuln = df.groupby(['Host'])['Host']\
            .count()\
            .reset_index(name='Number of Vulnerabilities')\
            .sort_values(['Number of Vulnerabilities'], ascending=False)\
            .head(5)

    HostsAllVuln.to_excel(writer,
            sheet_name='Hosts All Vuln')

    #Hosts with counts of vulnerabilities by risk
    VulnsByRisk = df.groupby(['Host'])['Risk']\
            .value_counts()

    VulnsByRisk.to_excel(writer,
            sheet_name='VulnsByRisk')

    #Display most common vulnerabilities on the network
    CommonVulns = df.groupby(['Name'])['Host']\
            .count()\
            .reset_index(name='Affected Hosts')\
            .sort_values(['Affected Hosts'], ascending=False)\
            .head(5)

    CommonVulns.to_excel(writer,
            sheet_name='CommonVulns')

    #Display most common high and above vulnerabilities on the network
    HighCommonVuln = df1.groupby(['Name'])['Host']\
            .count()\
            .reset_index(name='Affected Hosts')\
            .sort_values(['Affected Hosts'], ascending=False)\
            .head(5)

    HighCommonVuln.to_excel(writer,
            sheet_name='HighCommonVuln')

    #Display total risk (all cvss added together)
    TotalRisk = df.groupby(['Host'])['CVSS']\
            .sum()\
            .reset_index(name='Risk Score')\
            .sort_values(['Risk Score'], ascending =False)\
            .head(10)

    TotalRisk.to_excel(writer,
            sheet_name='TotalRisk')

    #Display hosts with most unique vulnerabilities
    df2 = (df.drop_duplicates(subset='Name'))
    UniqueVulns = df2.groupby(['Host'])['Host']\
            .count()\
            .reset_index(name='Unique Vulnerabilities')\
            .sort_values(['Unique Vulnerabilities'], ascending=False)\
            .head(5)

    UniqueVulns.to_excel(writer,
            sheet_name='UniqueVulns')


