#!python3

from falconpy import SpotlightVulnerabilities, Hosts, OAuth2
import requests, keyring, os, pandas as pd
from datetime import datetime, timedelta
import sqlite3, ldap3
import src.ldap as l

CS_ID = "" #keyring.get_password('crowdstrike', 'id')
CS_Secret = "" #keyring.get_password('crowdstrike', 'secret') 
base_url = "https://api.us-2.crowdstrike.com/"

auth = OAuth2(client_id=CS_ID,
              client_secret=CS_Secret,
              base_url=base_url
              )

spotlight = SpotlightVulnerabilities(auth_object=auth)
hosts = Hosts(auth_object=auth)

#convert to a sql fetchall 
filter_string = '''
    cve.id:['CVE-2005-1983','CVE-2008-4250','CVE-2009-3103','CVE-2013-4810','CVE-2014-6271',
    'CVE-2015-2342','CVE-2016-5535','CVE-2017-0148','CVE-2017-7269','CVE-2017-3066','CVE-2017-12542',
    'CVE-2017-10271','CVE-2019-2725','CVE-2019-0708','CVE-2020-0796','CVE-2020-3952','CVE-2020-5902',
    'CVE-2020-1337','CVE-2021-21972','CVE-2021-27078', 'CVE-2021-34523', 'CVE-2021-36942','CVE-2021-21991','CVE-2021-44228','CVE-2022-22012',
    'CVE-2022-22022,','CVE-2022-37958','CVE-2022-27510','CVE-2023-23397',' CVE-2009-2532',' CVE-2009-2526','CVE-2022-22013',
    'CVE-2022-22014','CVE-2022-29128','CVE-2022-29129','CVE-2022-29130','CVE-2022-29137','CVE-2022-29139','CVE-2022-29141',
    'CVE-2022-30226','CVE-2022-30206','CVE-2022-22041','CVE-2021-22015', 'CVE-2023-33145', 'CVE-2023-3079']
    '''

#usage is df = get_all_vulnerabilites_from_account(filter_string="cve.id:['CVE-2023-23397', 'CVE-####-####']")
#https://github.com/CrowdStrike/falconpy/blob/f43190b383f7036b756c9d76033464ba2d1001c4/samples/spotlight/spotlight_grab_cves_for_cid.py

def get_all_vulnerabilites_from_account(filter,verbose):
    print('[+] Grabbing Spotlight Vulnerabilities, this may take some time for larger environments...')
    time_start = datetime.now()

    iterations = 0
    facet = {"cve", "host_info", "remediation", "evaluation_logic"}
    spotlight_results = spotlight.query_vulnerabilities_combined(filter=filter, facet=facet, limit=400)
    after = 'blah'
    rows_dict_list = []
    while after != None:
        # Retrieve a list of vulns
        # Confirm we received a success response back from the CrowdStrike API
        if spotlight_results["status_code"] == 200:
            spotlight_list = spotlight_results["body"]["resources"]
            for resource in spotlight_list:
                rows_dict_list.append(resource)
        else:
            # Retrieve the details of the error response
            error_detail = spotlight_results["body"]["errors"]
            for error in error_detail:
                #error structure may be different and not include a code if the lib
                #didn't actually make an HTTP request, so let's just print the whole error for now
                raise SystemExit(error)

        # Stop as we've received less results than we requested
        if len(spotlight_results["body"]["resources"]) < 400:
            break

        after = None
        if 'after' in spotlight_results['body']['meta']['pagination']:
            after = spotlight_results['body']['meta']['pagination']['after']
        
        iterations += 1
        if iterations % 20 == 0 and verbose:
            elapsed_time = datetime.now() - time_start 
            elapsed_minutes = elapsed_time.seconds / 60
            elapsed_seconds = elapsed_time.seconds % 60
            print("[+] Total API Calls: %d" % iterations)
            print("[+] Total Records Pulled: %d" % len(rows_dict_list))
            print("[+] Elapsed Time (seconds): %d minutes %d seconds" % (elapsed_minutes, elapsed_seconds))
            
        spotlight_results = spotlight.query_vulnerabilities_combined(filter=filter, limit=400, after=after)

    return pd.json_normalize(rows_dict_list)

conn = sqlite3.connect(os.path.join('.','src','patchManagment.db'))
cursor = conn.cursor()

def crowdstrikeTable(assetuuid, hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS,BU, geo, deviceType, Alastseen, exattrb11, pluginID, firstFound, lastFound, remedDate, state, riskMod, source, cve):
     # Check if asset_uuid already exists in the table
    cursor.execute("SELECT COUNT(*) FROM crowdstrike WHERE assetuuid = ?", (assetuuid,))
    results = cursor.fetchone()[0]

    if results != 0:

        cursor.execute("SELECT assetuuid, hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS,BU, geo, deviceType, Alastseen, exattrb11, pluginID, firstFound, lastFound, remedDate, state, riskMod, source, cve FROM crowdstrike WHERE assetuuid = ? AND hostname = ? AND fqdn = ? AND ipv4 = ? AND macAddress = ? AND netbios = ? AND workgroup = ? AND OS = ? AND BU = ? AND geo = ? AND deviceType = ? AND Alastseen = ? AND exattrb11 = ? AND pluginID = ? AND firstFound = ? AND lastFound = ? AND remedDate = ? AND state = ? AND riskMod = ? AND source = ? AND cve = ?", 
                        (assetuuid, hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS,BU, geo, deviceType, Alastseen, exattrb11, pluginID, firstFound, lastFound, remedDate, state, riskMod, source, cve))
        result = cursor.fetchone()

        if result is not None:
            existing_record = dict(zip(['assetuuid', 'hostname', 'fqdn', 'ipv4', 'macAddress', 'netbios', 'workgroup', 'OS','BU', 'geo', 'deviceType', 'Alastseen', 'exattrb11', 'pluginID', 'firstFound', 'lastFound', 'remedDate', 'state', 'riskMod', 'source', 'cve'], result)) # Creating dictionary of the existing record
        else:
            existing_record = {}

        new_record = dict(zip(['assetuuid', 'hostname', 'fqdn', 'ipv4', 'macAddress', 'netbios', 'workgroup', 'OS','BU', 'geo', 'deviceType', 'Alastseen', 'exattrb11', 'pluginID', 'firstFound', 'lastFound', 'remedDate', 'state', 'riskMod', 'source', 'cve'], [assetuuid, hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS,BU, geo, deviceType, Alastseen, exattrb11, pluginID, firstFound, lastFound, remedDate, state, riskMod, source, cve])) # creating dictionary of record being pulled from Tenable


        if existing_record == new_record: # Checking for changes between records
            dbAssetStatement = f"     - There is no changes to {assetuuid} asset record in the assets table.\n         >>> Skipping Record..."
            

        else:
            # If the record exists, update it
            update_query = '''
                UPDATE crowdstrike 
                SET hostname = ?,
                fqdn = ?,
                ipv4 = ?,
                macAddress = ?,
                netbios = ?,
                workgroup = ?,
                OS = ?,
                BU = ?,
                geo = ?,
                deviceType = ?,
                Alastseen = ?,
                exattrb11 = ?,
                pluginID = ?,
                firstFound = ?,
                lastFound = ?,
                remedDate = ?,
                state = ?,
                riskMod = ?,
                source = ?,
                cve = ?
                WHERE assetuuid = ?
            '''

            dbAssetStatement = f"     - Changes found in asset record. Updating asset {assetuuid} in assets table.\n         >>> Updated Successfully..."
            conn.execute(update_query, (hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS,BU, geo, deviceType, Alastseen, exattrb11, pluginID, firstFound, lastFound, remedDate, state, riskMod, source, cve, assetuuid))
            

    else:
    # If the record does not exist, insert a new one
        insert_query = '''
            INSERT INTO crowdstrike (assetuuid, hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS,BU, geo, deviceType, Alastseen, exattrb11, pluginID, firstFound, lastFound, remedDate, state, riskMod, source, cve)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''

        dbAssetStatement = f"     - No record found. Adding {assetuuid} to the assets table.\n          >>> Record Added Successfully..."
        conn.execute(insert_query, (assetuuid, hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS, BU, geo, deviceType, Alastseen, exattrb11, pluginID, firstFound, lastFound, remedDate, state, riskMod, source, cve))
        


    # Commit the changes and close the connection
    conn.commit()

#PoC getter 
#usage - PoC = get_poc(BU=BU, deviceType=deviceType, ipv4=ipv4, geo=geo)
def get_poc(BU, deviceType, ipv4=None, geo=''):

    INTL = [] #international geo locations
    if BU == 'SAC':
        if deviceType == 'Workstation':
            PoC = 'Zach Darold'
            if ipv4 != None:
                #anything 10.69. is SAC Process Automation
                ipv4 = ipv4.split('.')
                ipv4 = f"{ipv4[0]}.{ipv4[1]}."
                if ipv4 == '10.69.':
                    PoC = 'Josh Webster'
        if deviceType == 'Servers':
            PoC = 'Jay Inocente'

    elif BU == 'FP':
        if deviceType == 'Workstation':
            #still WIP
            if geo in INTL:
                PoC = 'Richard Fairclough'
            else:
                PoC = 'Lauren Bartoshevich'
        if deviceType == 'Servers':
            PoC = 'Lauren Bartoshevich'

    elif BU == 'SM':
        if deviceType == 'Workstation':
            PoC = 'Daniel Richardson'
        if deviceType == 'Servers':
            PoC = 'Jay Inocente'

    elif BU == 'SRP':
        if deviceType == 'Workstation':
            PoC = 'Cary Gossett'
        if deviceType == 'Servers':
            PoC = 'Tony Lozzi'
    #default is Jay
    else:
        PoC = 'Jay Inocente'

    return PoC
    
#---Usage--- 
#newDF = push_toDB(get_all_vulnerabilities_from_account(filter_string))
def push_toDB(dataframe, conn): 
    conn = conn
    #available columns for dataframe
    ''' ['id', 'cid', 'aid', 'created_timestamp', 'updated_timestamp', 'status', 'apps', 'suppression_info.is_suppressed', 
        'host_info.hostname', 'host_info.local_ip', 'host_info.machine_domain', 'host_info.os_version', 
        'host_info.ou', 'host_info.site_name', 'host_info.system_manufacturer', 'host_info.tags', 'host_info.platform', 
        'host_info.os_build', 'host_info.product_type_desc',
        'remediation.entities', 
        'cve.id', 'cve.base_score', 'cve.severity', 'cve.exploit_status', 'cve.exprt_rating', 'cve.remediation_level',
        'cve.cisa_info.is_cisa_kev', 'cve.description', 'cve.published_date', 'cve.vendor_advisory', 'cve.exploitability_score',
        'cve.impact_score', 'cve.vector', 'cve.spotlight_published_date', 'closed_timestamp', 'cve.cisa_info.due_date', 
        'cve.actors', 'cve.references', 
        'host_info.groups', 'host_info.host_last_seen_timestamp', 'suppression_info.reason']
    '''
    #create return DF 
    returnDF = pd.DataFrame(columns=['aid','hostname', 'fqdn', 'ipv4', 'macAddress', 'netbios', 'workgroup', 'Alastseen', 'BU', 'geo', 'deviceType','pluginID', 'firstFound', 'lastFound', 'remedDate', 'state', 'riskMod', 'source'])
    print(f'Iterating over {len(dataframe.index)} rows')
    for index, row in dataframe.iterrows():
###Asset table###
        #host details to fill in where there are gaps - host details options
        """
        'device_id', 'cid', 'agent_load_flags', 'agent_local_time', 'agent_version', 'bios_manufacturer', 'bios_version',
         'build_number', 'config_id_base', 'config_id_build', 'config_id_platform', 'cpu_signature', 'external_ip', 
         'mac_address', 'hostname', 'first_seen', 'last_seen', 'local_ip', 'machine_domain', 'major_version', 
         'minor_version', 'os_version', 'os_build', 'ou', 'platform_id', 'platform_name', 'policies', 
         'reduced_functionality_mode', 'device_policies', 'groups', 'group_hash', 'product_type', 'product_type_desc', 
         'provision_status', 'serial_number', 'service_pack_major', 'service_pack_minor', 'pointer_size', 'site_name', 
         'status', 'system_manufacturer', 'system_product_name', 'tags', 'modified_timestamp', 'meta', 'kernel_version', 
         'os_product_name', 'chassis_type', 'chassis_type_desc', 'last_reboot', 'connection_ip', 'default_gateway_ip', 
         'connection_mac_address'
         """
        #input(row['aid'])
        hostDetails = hosts.get_device_details_v2(ids=[row['aid']])['body']['resources'][0]
        try:
            macAddress = hostDetails['mac_address']
        except KeyError:
            macAddress = ''
        #Compare the macAddress to asset table to determine the asset.
        if macAddress != '':
            queryHost = conn.execute('SELECT * FROM assets where mac like ?', (f'%{macAddress}%',)).fetchone()
        #for testing
        # if queryHost != None:
        #     input(f'{queryHost}\n& MAC: {macAddress}')
        '''
        if query == 0:
            #insert information into the db
            input("placeholder for ")
        elif:
            #take the asset information from the asset table to add a new finding
            #check to see if the finding already exists
        '''

        hostname = row['host_info.hostname']
        if pd.isna(hostname):
            hostname = hostDetails['hostname']
        
        ipv4 = row['host_info.local_ip']
        if pd.isna(ipv4):
            try:
                ipv4 = hostDetails['local_ip']
            except KeyError:
                ipv4 = ''

        netbios = ''
        workgroup = row['host_info.machine_domain']
        if pd.isna(workgroup):
            try:
                workgroup = hostDetails['machine_domain']
            except KeyError:
                pass
        if pd.notna(hostname) and pd.notna(workgroup):
            fqdn = f'{hostname}.{workgroup}' #maybe combine hostname and workgroup
        OS = row['host_info.os_version']
        if pd.isna(OS):
            OS = hostDetails['os_version']
            
        try:
            BU, geo = row['host_info.site_name'].split('-', maxsplit=1)
            if pd.isna(BU) and pd.isna(geo):
                BU, geo = hostDetails['site_name'].split('-', maxsplit=1)
        except:
            BU, geo = '', ''
        #this acts like a bunch of ifs
        bu_dict = {'FRP': 'SRP', 'WC': 'SAC', 'ATI': 'Corp', 'SM':'SM', 'ALV': 'SM'}
        if BU not in bu_dict.values():
            BU = bu_dict.get(BU)
            if BU == None: BU = ''

        deviceType = row['host_info.product_type_desc']
        if pd.isna(deviceType):
            deviceType = hostDetails['product_type_desc']
        #make the name uniform with Tenable
        if deviceType == 'Server':
            deviceType += 's'
        
        PoC = get_poc(BU=BU, deviceType=deviceType, ipv4=ipv4, geo=geo)

        Alastseen = row['host_info.host_last_seen_timestamp'] #(date object)

        exattrb11 = '' 
        if workgroup != "":
            try:
                if hostname != '' :
                    ADvals = l.searchLDAP(hostname, workgroup)
                    exattrb11 = ADvals['exattr11']
                    
                else:
                    exattrb11 = ""

            except (ldap3.core.exceptions.LDAPSocketOpenError, IndexError) as e:
                pass
        else:
            exattrb11 = ""
       
    
###Finding table###
        assetuuid = row['aid'] 

        firstFound = row['created_timestamp']#(date object)
        lastFound = row['updated_timestamp']#(date object)
        #remedDate = row['closed_timestamp']#(date object)

        if row['closed_timestamp'] == 'NaN':
            remedDate = ''
        else:
            remedDate = row['closed_timestamp'] #(date object)

        #dictionary to grab the status
        stati = {'open': 'Reported', 'reopen': 'Reported', 'closed': 'Fixed'}
        state = stati.get(row['status']) #convert
        riskMod = row['suppression_info.is_suppressed'] #(boolean)
        if riskMod == True:
            state = 'Accepted'
        else:
            riskMod = 'NONE'
        #Offline checker
        difdays = (datetime.now().date() - datetime.fromisoformat(lastFound[:-1]).date()) 
        if state == 'Reported' and difdays.days > 4: 
            state = "Offline"
            
        reportedDate = ''
        source = 'Crowdstrike'

        #Get the plugin associated with the CVE
        cve = row['cve.id']
        #The application being used with the vulnerability is what I am using to identify the best fit plugin
        app = row['apps'][0]['product_name_version']
        appsplit = app.split(' ') #split the name up into parts
        appval = ''
        #adding ifs to catch miss matching, this will probably expand
        if app == '365 Apps':
            appsplit = 'Outlook'
        
        #iterate through the parts and break if we have 1 result as the output, meaning it found a match
        for ind, word in enumerate(appsplit): 
            if ind == 0:
                appval = f"%{word}%"
            elif ind == 1:
                appval = appval[:-1]
                appval += f"_{word}%"
            else:
                appval += f"{word}%"
            #print(f'{cve} - {app} - {appval}', end='\r')
            #make sure this is only returning 1 val
            pluginID = ""
            pluginID = conn.execute('SELECT pluginID FROM vulnplugin where cve like ? and pluginName like ?', (f'%{cve}%', f'{appval}')).fetchall()
            if len(pluginID) == 1:
                pluginID = pluginID[0]
                break
        pluginID = pluginID.strip('(),')
        print(f'{index} - {pluginID}', end='\r')
##Vuln table###       
        #pluginName = '' #???????
        '''description = row['cve.description']
        try:
            solution = row['remediation.entities'][0]['action']
        except:
            solution = ''
        type = '' #???????       
        
        try:
            see_also = row['remediation.entities'][0]['link']
        except:
            see_also = 
        '''
###Data for DB
        #fields for Philip
        #input(f"{assetuuid, hostname, fqdn, ipv4, macAddress, workgroup, Alastseen, BU, geo, deviceType}") 
        #input(f"{assetuuid, pluginID, firstFound, lastFound, remedDate, state, riskMod, source}")
        
        #append rows to DF
        returnDF = returnDF.append({'aid': assetuuid, 'hostname': hostname, 'fqdn': fqdn, 'ipv4': ipv4, 'macAddress': macAddress, 'netbios': netbios, 'workgroup': workgroup,
                        'Alastseen': Alastseen, 'exattrb11': exattrb11, 'BU':BU, 'geo':geo, 'deviceType':deviceType, 'pluginID':pluginID, 'firstFound':firstFound, 
                        'OS': OS, 'lastFound': lastFound, 'remedDate':remedDate, 'state':state, 'riskMod':riskMod, 'source':source, 'cve': cve},
                        ignore_index = True)

    #OUT For loop   
    return returnDF #return the whole set of data

#s
df = get_all_vulnerabilites_from_account(filter=filter_string, verbose=True)
#might cause issues in the future, but for now we will get rid of them
df = df.loc[df['status'] != 'expired']
#df = df.loc[df['status'] == 'open']
#fill in the blanks with todays date
df['host_info.host_last_seen_timestamp'] = df['host_info.host_last_seen_timestamp'].fillna(f'{datetime.today().strftime("%Y-%m-%d")}T00:00:00Z')
#looking to pull only recent findings
# minusTen = (datetime.today() - timedelta(days=10)).strftime("{%Y-%m-%d}")
# df = df[df['host_info.host_last_seen_timestamp'].dt.strftime("{%Y-%m-%d}") > 'minusTen']
returnedDF = push_toDB(df, conn)

# Iterate over the rows and replace the existing data with the new print statements
for index, row in returnedDF.iterrows():
    print("Row Index:", index)
    print("Data:")
    print(row)
    print("=" * 50)

    assetuuid = row['aid']
    hostname = row['hostname']
    fqdn = row['fqdn']
    ipv4 = row['ipv4']
    macAddress = row['macAddress']
    netbios = row['netbios']
    workgroup = row['workgroup']
    OS = row['OS']
    BU = row['BU']
    geo = row['geo']
    deviceType = row['deviceType']
    Alastseen = row['Alastseen']
    exattrb11 = row['exattrb11']
    pluginID = str(row['pluginID'])
    firstFound = row['firstFound']
    lastFound = row['lastFound']
    remedDate = row['remedDate']
    state = row['state']
    riskMod = row['riskMod']
    source = row['source']
    CVE = row['cve']


    crowdstrikeTable(assetuuid, hostname, fqdn, ipv4, macAddress, netbios, workgroup, OS, BU, geo, deviceType, Alastseen, exattrb11, str(pluginID), firstFound, lastFound, remedDate, state, riskMod, source, CVE)

conn.close()
