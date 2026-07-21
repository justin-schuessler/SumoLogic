import os
import json
import requests
import logging
import base64
from requests.auth import HTTPBasicAuth
import sys
import get_1password_field


lists = [
    {'name': 'admin_ips', 'description': 'Hosts that are known to be involved with specific administrative or privileged activity on the network. Can be used for tracking hosts that are operated by admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'SrcIp'},
    {'name': 'admin_accounts', 'description': 'Accounts that are known to be involved with specific administrative or privileged activity.', 'targetColumn': 'Username'},
    {'name': 'admin_username', 'description': 'Hosts that are known to be involved with specific administrative or privileged activity on the network. Can be used for tracking hosts that are operated by admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'Username'},
    {'name': 'Alibaba_admin_ips', 'description': 'IPs that are known to be involved with specific administrative or privileged activity on the network.', 'targetColumn': 'Ip'},
    {'name': 'Alibaba_admin_users', 'description': 'Users that are known to be involved with specific administrative or privileged activity on the network.', 'targetColumn': 'Username'},
    {'name': 'authorized_third_party_domains', 'description': 'Authorized third party domains.', 'targetColumn': 'Domain'},
    {'name': 'auth_servers', 'description': 'Network authentication servers, including Active Directory, LDAP, Kerberos, RADIUS/TACACS, and NIS servers. May be used in analytics designed to detect DCSync attacks.', 'targetColumn': 'Ip'},
    {'name': 'auth_servers_dst', 'description': 'Copy of the auth_servers Match List for directional matches.', 'targetColumn': 'DstIp'},
    {'name': 'auth_servers_src', 'description': 'Copy of the auth_servers Match List for directional matches.', 'targetColumn': 'SrcIp'},
    {'name': 'AWS_admin_ips', 'description': 'Hosts that are known to be involved with specific administrative or privileged activity in AWS. Can be used for tracking hosts that are operated by admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'SrcIp'},
    {'name': 'AWS_admin_users', 'description': 'Users that are known to be involved with specific administrative or privileged activity in AWS. Can be used for tracking users that are admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'Username'},
    {'name': 'business_asns', 'description': 'Remote ASNs supporting business processes.', 'targetColumn': 'Asn'},
    {'name': 'business_domains', 'description': 'DNS domain names that are known business-related domains. This is intended to capture domains related to validated, expected, or critical business functions and may be used for allowlisting or filtering related uninteresting results from query result sets.', 'targetColumn': 'Domain'},
    {'name': 'business_hostnames', 'description': 'DNS hostnames that are known to be business-related FQDNs.', 'targetColumn': 'Hostname'},
    {'name': 'business_ips', 'description': 'Remote IP addresses supporting business processes. Can be used for things like SSH servers for SFTP file exchanges (similarly, FTP servers).', 'targetColumn': 'Ip'},
    {'name': 'domain_controllers', 'description': 'Domain controllers', 'targetColumn': 'Ip'},
    {'name': 'dns_servers', 'description': 'DNS caching resolvers/authoritative content servers in customer environments.', 'targetColumn': 'Ip'},
    {'name': 'dns_servers_dst', 'description': 'Copy of the dns_servers Match List for directional matches.', 'targetColumn': 'SrcIp'},
    {'name': 'dns_servers_src', 'description': 'Copy of the dns_servers Match List for directional matches.', 'targetColumn': 'DstIp'},
    {'name': 'downgrade_krb5_etype_authorized_users', 'description': 'Known account names that utilize downgraded encryption types with multiple SPNs. This is an exception Match List that should be populated with a list of Kerberos principal names (for example,  jdoe@EXAMPLE.COM) matched in endpoint username that are known to trigger content around legacy downgraded encryption types. This is directly related to the detection of Kerberoasting attacks.', 'targetColumn': 'Username'},
    {'name': 'ds_replication_authorized_users', 'description': 'Authorized account names to initiate Directory Service Replication requests to Active Directory.', 'targetColumn': 'Username'},
    {'name': 'dyndns_exception_domains', 'description': 'Authorized domains.', 'targetColumn': 'Domain'},
    {'name': 'dyndns_exception_hostnames', 'description': 'Authorized hostnames.', 'targetColumn': 'Hostname'},
    {'name': 'ftp_servers', 'description': 'Known FTP servers.', 'targetColumn': 'Ip'},
    {'name': 'gcp_admin', 'description': 'Users or hosts that are known to be involved with specific administrative or privileged activity in GCP. Can be used for tracking users or hosts that are admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'Username'},
    {'name': 'GCP_admin_ips', 'description': 'Hosts that are known to be involved with specific administrative or privileged activity in GCP. Can be used for tracking hosts that are operated by admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'SrcIp'},
    {'name': 'GCP_admin_users', 'description': 'Users that are known to be involved with specific administrative or privileged activity in GCP. Can be used for tracking users that are admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'Username'},
    {'name': 'Google_Workspace_admin_ips', 'description': 'Hosts that are known to be involved with specific administrative or privileged activity in Google Workspace. Can be used for tracking hosts that are operated by admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'SrcIp'},
    {'name': 'Google_Workspace_admin_users', 'description': 'Users that are known to be involved with specific administrative or privileged activity in Google Workspace. Can be used for tracking users that are admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'Username'},
    {'name': 'guest_networks', 'description': 'Known guest WLAN and other guests/BYOD network addresses.', 'targetColumn': 'Ip'},
    {'name': 'honeypot_ip_addresses', 'description': 'List of IPs for Honeypots.', 'targetColumn': 'Ip'},
    {'name': 'http_servers', 'description': 'Web servers in your environment.', 'targetColumn': 'Ip'},
    {'name': 'lan_scanner_exception_ips', 'description': 'IP addresses excepted from analytics identifying LAN protocol scanning activity. Used in specific cases to exclude hosts from flagging particular types of rule content, primarily around scanning of commonly targeted LAN service ports, etc. Not an across-the-board allowlist. This Match List is not intended for vulnerability scanners, which should be listed instead in vuln scanners.', 'targetColumn': 'Ip'},
    {'name': 'nat_ips', 'description': 'Source NAT addresses. Can be used as an exception Match List to block content relying on the evaluation of data per-host from applying to hosts that are translated or aggregations of other hosts. Note that this can also be applied using proxy_servers as an example of a specific case.', 'targetColumn': 'Ip'},
    {'name': 'nms_ips', 'description': 'Hosts known to be Network Management System (NMS) nodes.', 'targetColumn': 'Ip'},
    {'name': 'Okta_Admins', 'description': 'Users that are known to be involved with specific administrative or privileged activity.', 'targetColumn': 'Username'},
    {'name': 'palo_alto_sinkhole_ips', 'description': 'IP addresses for the sinkhole IP or IPs configured for Palo Alto DNS sinkhole.', 'targetColumn': 'Ip'},
    {'name': 'proxy_servers', 'description': 'Forward proxy servers, including HTTP and SOCKS proxies.', 'targetColumn': 'Ip'},
    {'name': 'proxy_servers_dst', 'description': 'Copy of the proxy_servers Match List for directional matches.', 'targetColumn': 'DstIp'},
    {'name': 'proxy_servers_src', 'description': 'Copy of the proxy_server Match List for directional matches.', 'targetColumn': 'SrcIp'},
    {'name': 'public_ips', 'description': 'Public Ip Addresses.', 'targetColumn': 'Ip'},
    {'name': 'salesforce_admin_ips', 'description': 'Hosts that are known to be involved with specific administrative or privileged activity in Salesforce. Can be used for tracking hosts that are operated by admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'SrcIp'},
    {'name': 'salesforce_admin_users', 'description': 'Users that are known to be involved with specific administrative or privileged activity in Salesforce. Can be used for tracking users that are admins and other privileged users, or are often the source of restricted, privileged or suspicious authorized actions, and so on. This sort of tracking is useful for baselining activity and as a result, surfacing more suspicious activity.', 'targetColumn': 'Username'},
    {'name': 'sandbox_ips', 'description': 'Malware sandboxes or security devices interacting with malicious infrastructure.', 'targetColumn': 'Ip'},
    {'name': 'scanner_targets', 'description': 'Destination networks that are authorized/standard targets of vulnerability scans in customer environment.', 'targetColumn': 'Ip'},
    {'name': 'smtp_servers', 'description': 'SMTP sending/receiving hosts in customer environment.', 'targetColumn': 'Ip'},
    {'name': 'sql_servers', 'description': 'Database servers in customer environment.', 'targetColumn': 'Ip'},
    {'name': 'ssh_servers', 'description': 'Known SSH servers.', 'targetColumn': 'Ip'},
    {'name': 'ssl_exception_ips', 'description': 'SSL exception IPs.', 'targetColumn': 'Ip'},
    {'name': 'telnet_servers', 'description': 'Telnet servers in your environment.', 'targetColumn': 'Ip'},
    {'name': 'threat', 'description': 'A record flagged an IP address from a threat intelligence Match List.', 'targetColumn': 'Ip'},
    {'name': 'unauthorized_external_media', 'description': 'A list of devices that should not have external media installed on them.', 'targetColumn': 'Hostname'},
    {'name': 'verified_applications', 'description': 'A list of devices that should not have external media installed on them.', 'targetColumn': 'Custom'},
    {'name': 'verified_domains', 'description': 'Reviewed and validated legitimate or non-threat domains.', 'targetColumn': 'Domain'},
    {'name': 'verified_hostnames', 'description': 'Reviewed and validated legitimate or non-threat hostnames.', 'targetColumn': 'Hostname'},
    {'name': 'verified_ips', 'description': 'Reviewed and validated legitimate or non-threat ips.', 'targetColumn': 'Ip'},
    {'name': 'verified_uri_ips', 'description': 'Reviewed and validated legitimate or non-threat IP addresses.', 'targetColumn': 'Ip'},
    {'name': 'verified_uri_paths', 'description': 'Reviewed and validated legitimate or non-threat Paths.', 'targetColumn': 'Custom'},
    #{'name': 'verified_uri_paths', 'description': 'Reviewed and validated legitimate or non-threat domains.', 'targetColumn': 'HttpURLPath'},
    {'name': 'vpn_networks', 'description': 'VPN/remote access user address pools and DHCP scopes.', 'targetColumn': 'Ip'},
    {'name': 'vpn_servers', 'description': 'VPN/remote access servers, including IKE/IPsec/SSL VPN concentrators, OpenVPN endpoints, and so on.', 'targetColumn': 'Ip'},
    {'name': 'web_servers', 'description': 'List of webserver hostnames or IPs.', 'targetColumn': 'Hostname'},
    {'name': 'vuln_scanners', 'description': 'Vulnerability scanner and network mapping hosts.', 'targetColumn': 'Ip'},
    {'name': 'zoom_admins', 'description': 'Known admin users of Zoom.', 'targetColumn': 'Username'},
]


def create_match_lists(lists, base_url, AccessID, AccessKey):
    match_list_url = base_url + '/sec/v1/match-lists'
    for l in lists:
        payload = {
                "fields": {
                    "active": True,
                    "defaultTtl": 0,
                    "description": l['description'],
                    "name": l['name'],
                    "targetColumn": l['targetColumn']
                }
            }
        name = l['name']
        print(f'Creating {name}')
        logging.info(f'Creating {name}')
        r = requests.post(match_list_url, auth=HTTPBasicAuth(AccessID, AccessKey), json=payload)
        status = r.status_code
        if(status < 201):
            logging.info(f'Successfully created {name}. Status Code: {status}')
        else:
            logging.info(f'Error creating {name}.  Status Code: {status}')
        #if r.status_code
    # need to add https://help.sumologic.com/Cloud_SIEM_Enterprise/Match_Lists/Standard_Match_Lists#verified_uri_paths-1
    #create_intel_sources()


if __name__ == '__main__':
    original_stdout = sys.stdout
    path = "C:/Users/justin.schuessler/Documents/API_Output/Sumo/"
    access_id = get_1password_field.get_1password_field("Pathfinder Bank Sumo API Credentials", "Access ID", "API")
    secret_key = get_1password_field.get_1password_field("Pathfinder Bank Sumo API Credentials", "Access Key", "API")
    BASE_URL = get_1password_field.get_1password_field("Pathfinder Bank Sumo API Credentials", "url", "API")

    accessID = access_id
    accessKey = secret_key

    logging.basicConfig(level=logging.INFO, filename='C:/Users/justin.schuessler/Documents/API_Output/Sumo/createStandardMatchLists.log')
    create_match_lists(lists, BASE_URL, accessID, accessKey)

