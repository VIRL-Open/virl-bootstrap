#!/usr/bin/python
#__author__ = 'ejk'

"""virl install.

Usage:
  vinstall.py zero | first | second | third | fourth | salt | test | test1 | iso | bridge | desktop | rehost | renumber | compute | all | upgrade | nova | vmm | routervms | users | vinstall | host | mini | highstate | defrost | kvm | cluster

Options:
  --version             shows program's version number and exit
  -h, --help            show this help message and exit
"""

import configparser
import subprocess
import logging
import envoy
import json
import sys
import re
import yaml
from time import sleep
from tempfile import mkstemp
from shutil import move, copy, copystat
from os import remove, close, mkdir, path
from docopt import docopt


#TODO old pos logging style for now
#Setting up logging
log = logging.getLogger('install')
log.setLevel(logging.DEBUG)
fhand = logging.FileHandler('/tmp/install.out')
fhand.setLevel(logging.WARNING)
# console messages
conhand = logging.StreamHandler()
conhand.setLevel(logging.ERROR)
# formatter
frmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fhand.setFormatter(frmt)
conhand.setFormatter(frmt)
log.addHandler(fhand)
log.addHandler(conhand)


safeparser = configparser.ConfigParser()
safeparser_file = '/etc/virl.ini'
# safeparser_backup_file = '/home/virl/vsettings.ini'
if path.exists(safeparser_file):
    safeparser.read(safeparser_file)
# elif path.exists(safeparser_backup_file):
#     safeparser.read('/home/virl/vsettings.ini')
else:
    print "No config exists at /etc/virl.ini.  Hope you know what your doing"
    # safeparser.read('./settings.ini')
DEFAULT = safeparser['DEFAULT']
# install = safeparser['install']
# operational = safeparser['operational']
# packaging = safeparser['packaging']
# testing = safeparser['testing']
# cluster = safeparser['cluster']


hostname = safeparser.get('DEFAULT', 'hostname', fallback='virl')
fqdn = safeparser.get('DEFAULT', 'domain_name', fallback='virl.info')

dhcp_public = safeparser.getboolean('DEFAULT', 'using_dhcp_on_the_public_port', fallback=True)
public_port = safeparser.get('DEFAULT', 'public_port', fallback='eth0')
public_ip = safeparser.get('DEFAULT', 'Static_IP', fallback='127.0.0.1')
public_network = safeparser.get('DEFAULT', 'public_network', fallback='172.16.6.0')
public_netmask = safeparser.get('DEFAULT', 'public_netmask', fallback='255.255.255.0')
public_gateway = safeparser.get('DEFAULT', 'public_gateway', fallback='172.16.6.1')
proxy = safeparser.getboolean('DEFAULT', 'proxy', fallback=False)
http_proxy = safeparser.get('DEFAULT', 'http_proxy', fallback='http://proxy-wsa.esl.cisco.com:80/')
ntp_server = safeparser.get('DEFAULT', 'ntp_server', fallback='ntp.ubuntu.com')
dns1 = safeparser.get('DEFAULT', 'first_nameserver', fallback='8.8.8.8')
dns2 = safeparser.get('DEFAULT', 'second_nameserver', fallback='171.70.168.183')


l2_port = safeparser.get('DEFAULT', 'l2_port', fallback='eth1')
l2_mask = safeparser.get('DEFAULT', 'l2_mask', fallback='255.255.255.0')
l2_bridge_port = safeparser.get('DEFAULT', 'l2_bridge_port', fallback='br-eth1')
l2_address = safeparser.get('DEFAULT', 'l2_address', fallback='172.16.1.254')
l2_network = safeparser.get('DEFAULT', 'l2_network', fallback='172.16.1.0/24')
l2_gate = safeparser.get('DEFAULT', 'l2_network_gateway', fallback='172.16.1.1')
l2_s_address = safeparser.get('DEFAULT', 'l2_start_address', fallback='172.16.1.50')
l2_e_address = safeparser.get('DEFAULT', 'l2_end_address', fallback='172.16.1.250')
# address_l2_port = safeparser.getboolean('DEFAULT', 'address l2 port', fallback=True)
address_l2_port = True
flat_dns1 = safeparser.get('DEFAULT', 'first_flat_nameserver', fallback='8.8.8.8')
flat_dns2 = safeparser.get('DEFAULT', 'second_flat_nameserver', fallback='8.8.4.4')

#l2_port2_enabled = safeparser.getboolean('DEFAULT', 'l2_port2_enabled', fallback=True)
l2_port2_enabled = True
l2_port2 = safeparser.get('DEFAULT', 'l2_port2', fallback='eth2')
l2_mask2 = safeparser.get('DEFAULT', 'l2_mask2', fallback='255.255.255.0')
l2_bridge_port2 = safeparser.get('DEFAULT', 'l2_bridge_port2', fallback='br-eth2')
l2_address2 = safeparser.get('DEFAULT', 'l2_address2', fallback='172.16.2.254')
l2_network2 = safeparser.get('DEFAULT', 'l2_network2', fallback='172.16.2.0/24')
l2_gate2 = safeparser.get('DEFAULT', 'l2_network_gateway2', fallback='172.16.2.1')
l2_s_address2 = safeparser.get('DEFAULT', 'l2_start_address2', fallback='172.16.2.50')
l2_e_address2 = safeparser.get('DEFAULT', 'l2_end_address2', fallback='172.16.2.250')
# address_l2_port2 = safeparser.getboolean('DEFAULT', 'address l2 port2', fallback=True)
address_l2_port2 = True
flat2_dns1 = safeparser.get('DEFAULT', 'first_flat2_nameserver', fallback='8.8.8.8')
flat2_dns2 = safeparser.get('DEFAULT', 'second_flat2_nameserver', fallback='8.8.4.4')

dist_upgrade = safeparser.getboolean('DEFAULT', 'dist_upgrade', fallback=True)
masterless = safeparser.getboolean('DEFAULT', 'salt_masterless', fallback=False)
RAMDISK = safeparser.getboolean('DEFAULT', 'ramdisk', fallback=False)
ank = safeparser.get('DEFAULT', 'ank', fallback='19401')
uwm_port = safeparser.get('DEFAULT', 'virl_user_management', fallback='19400')
wsgi_port = safeparser.get('DEFAULT', 'virl_webservices', fallback='19399')
serial_start = safeparser.get('DEFAULT', 'Start_of_serial_port_range', fallback='17000')
serial_end = safeparser.get('DEFAULT', 'End_of_serial_port_range', fallback='18000')

guest_account = safeparser.getboolean('DEFAULT', 'guest_account', fallback=True)
user_list = safeparser.get('DEFAULT', 'user_list', fallback='')
user_list_limited = safeparser.get('DEFAULT', 'restricted_users', fallback='')

l3_port = safeparser.get('DEFAULT', 'l3_port', fallback='eth3')
l3_mask = safeparser.get('DEFAULT', 'l3_mask', fallback='255.255.255.0')
l3_bridge_port = safeparser.get('DEFAULT', 'l3_bridge_port', fallback='br-ex')
l3_s_address = safeparser.get('DEFAULT', 'l3_floating_start_address', fallback='172.16.3.50')
l3_e_address = safeparser.get('DEFAULT', 'l3_floating_end_address', fallback='172.16.3.250')
l3_address = safeparser.get('DEFAULT', 'l3_address', fallback='172.16.3.254')
l3_gate = safeparser.get('DEFAULT', 'l3_network_gateway', fallback='172.16.3.1')
l3_network = safeparser.get('DEFAULT', 'l3_network', fallback='172.16.3.0/24')
snat_dns1 = safeparser.get('DEFAULT', 'first_snat_nameserver', fallback='8.8.8.8')
snat_dns2 = safeparser.get('DEFAULT', 'second_snat_nameserver', fallback='8.8.4.4')
location_region = safeparser.get('DEFAULT', 'location_region', fallback='US')
vnc = safeparser.getboolean('DEFAULT', 'vnc', fallback=False)
vnc_passwd = safeparser.get('DEFAULT', 'vnc_password', fallback='letmein')

#Install section
uwm_username = safeparser.get('DEFAULT', 'uwm_username', fallback='uwmadmin')
uwmadmin_passwd = safeparser.get('DEFAULT', 'uwmadmin_password', fallback='password')
guest_passwd = safeparser.get('DEFAULT', 'guest_password', fallback='guest')
ospassword = safeparser.get('DEFAULT', 'password', fallback='password')
mypassword = safeparser.get('DEFAULT', 'mysql_password', fallback='password')
ks_token = safeparser.get('DEFAULT', 'keystone_service_token', fallback='fkgjhsdflkjh')
keystone_auth_version = safeparser.get('DEFAULT', 'keystone_auth_version', fallback='v2')

ganglia = safeparser.getboolean('DEFAULT', 'ganglia', fallback=False)

debug = safeparser.getboolean('DEFAULT', 'debug', fallback=False)
horizon = safeparser.getboolean('DEFAULT', 'enable_horizon', fallback=False)
ceilometer = safeparser.getboolean('DEFAULT', 'ceilometer', fallback=False)
heat = safeparser.getboolean('DEFAULT', 'enable_heat', fallback=True)
cinder = safeparser.getboolean('DEFAULT', 'enable_cinder', fallback=False)
cinder_file = safeparser.getboolean('DEFAULT', 'cinder_file', fallback=True)
cinder_device = safeparser.get('DEFAULT', 'cinder_device', fallback=False )
cinder_size = safeparser.get('DEFAULT', 'cinder_size', fallback=2000 )
cinder_loc = safeparser.get('DEFAULT', 'cinder_location', fallback='/var/lib/cinder/cinder-volumes.lvm')
neutron_switch = safeparser.get('DEFAULT', 'neutron_switch', fallback='linuxbridge')
desktop = safeparser.getboolean('DEFAULT', 'desktop', fallback=False)
desktop_manager = safeparser.get('DEFAULT', 'desktop_manager', fallback='lubuntu')

#Packaging section
cariden = safeparser.getboolean('DEFAULT', 'cariden', fallback=False)
NNI = safeparser.getboolean('DEFAULT', 'NNI', fallback=False)
GITBRANCH = safeparser.get('DEFAULT', 'GIT_branch', fallback='grizzly')
NOVABRANCH = safeparser.get('DEFAULT', 'Nova_branch', fallback='grizzly-virl-telnet')
BASEDIR = safeparser.get('DEFAULT', 'virl.standalone_is_in_what_directory', fallback='/home/virl/virl.standalone/')
GITBASE = safeparser.get('DEFAULT', 'base_of_the_git_tree_is_in_what_directory',
                         fallback='/home/virl/virl.standalone/glocal')
multiuser = safeparser.getboolean('DEFAULT', 'multiuser', fallback=True)
install1q = safeparser.getboolean('DEFAULT', 'Install_1q', fallback=True)
packer_calls = safeparser.getboolean('DEFAULT', 'packer', fallback=False)
vagrant_calls = safeparser.getboolean('DEFAULT', 'vagrant', fallback=False)
vagrant_pre_fourth = safeparser.getboolean('DEFAULT', 'vagrant_before_fourth', fallback=False)
vagrant_keys = safeparser.getboolean('DEFAULT', 'vagrant_keys', fallback=False)
cml = safeparser.getboolean('DEFAULT', 'cml', fallback=False)


#Operational Section
image_set = safeparser.get('DEFAULT', 'image_set', fallback='internal')
salt = safeparser.getboolean('DEFAULT', 'salt', fallback=True)
salt_master = safeparser.get('DEFAULT', 'salt_master', fallback='us-1.virl.info,us-2.virl.info,us-3.virl.info,us-4.virl.info')
salt_master_tcp = safeparser.get('DEFAULT', 'salt_master_tcp', fallback='us-1-tcp.virl.info,us-2-tcp.virl.info,us-3-tcp.virl.info,us-4-tcp.virl.info')
salt_id = safeparser.get('DEFAULT', 'salt_id', fallback='virl')
salt_domain = safeparser.get('DEFAULT', 'salt_domain', fallback='virl.info')
multi_salt_key = safeparser.getint('DEFAULT', 'multi_salt_key', fallback=1)
salt_id2 = safeparser.get('DEFAULT', 'salt_id2', fallback='virl')
salt_domain2 = safeparser.get('DEFAULT', 'salt_domain2', fallback='virl.info')
salt_id3 = safeparser.get('DEFAULT', 'salt_id3', fallback='virl')
salt_domain3 = safeparser.get('DEFAULT', 'salt_domain3', fallback='virl.info')
salt_id4 = safeparser.get('DEFAULT', 'salt_id4', fallback='virl')
salt_domain4 = safeparser.get('DEFAULT', 'salt_domain4', fallback='virl.info')
salt_env = safeparser.get('DEFAULT', 'salt_env', fallback='none')
salt_tcp = safeparser.getboolean('DEFAULT', 'salt_transport_tcp', fallback=False)

virl_type = safeparser.get('DEFAULT', 'Is_this_a_stable_or_testing_server', fallback='stable')
cisco_internal = safeparser.getboolean('DEFAULT', 'inside_cisco', fallback=False)
onedev = safeparser.getboolean('DEFAULT', 'onedev', fallback=False)
dummy_int = safeparser.getboolean('DEFAULT', 'dummy_int', fallback=False)
jumbo_frames = safeparser.getboolean('DEFAULT', 'jumbo_frames', fallback=False)
ram_overcommit = safeparser.get('DEFAULT', 'ram_overcommit', fallback='2')
cpu_overcommit = safeparser.get('DEFAULT', 'cpu_overcommit', fallback='3')
download_proxy = safeparser.get('DEFAULT', 'download_proxy', fallback='')
download_no_proxy = safeparser.get('DEFAULT', 'download_no_proxy', fallback='')
download_proxy_user = safeparser.get('DEFAULT', 'download_proxy_user', fallback='')

#Testing Section
icehouse = safeparser.getboolean('DEFAULT', 'icehouse', fallback=False)
kilo = safeparser.getboolean('DEFAULT', 'kilo', fallback=True)
mitaka = safeparser.getboolean('DEFAULT', 'mitaka', fallback=False)

testingank = safeparser.getboolean('DEFAULT', 'testing_ank', fallback=False)
testingstd = safeparser.getboolean('DEFAULT', 'testing_std', fallback=False)
testingvmm = safeparser.getboolean('DEFAULT', 'testing_vmm', fallback=False)
#ankstable = safeparser.getboolean('DEFAULT', 'stable ank', fallback=False)
v144 = safeparser.getboolean('DEFAULT', 'v144', fallback=True)

#devops section
testingdevops = safeparser.getboolean('DEFAULT', 'testing_devops', fallback=False)

#cluster section
virl_cluster = safeparser.getboolean('DEFAULT', 'virl_cluster', fallback=False)
controller = safeparser.getboolean('DEFAULT', 'this_node_is_the_controller', fallback=True)
internalnet_controller_ip = safeparser.get('DEFAULT', 'internalnet_controller_IP', fallback='172.16.10.250')
internalnet_controller_hostname = safeparser.get('DEFAULT', 'internalnet_controller_hostname', fallback='controller')
internalnet_port = safeparser.get('DEFAULT', 'internalnet_port', fallback='eth4')
internalnet_ip = safeparser.get('DEFAULT', 'internalnet_IP', fallback='172.16.10.250')
internalnet_network = safeparser.get('DEFAULT', 'internalnet_network', fallback='172.16.10.0')
internalnet_netmask = safeparser.get('DEFAULT', 'internalnet_netmask', fallback='255.255.255.0')
internalnet_gateway = safeparser.get('DEFAULT', 'internalnet_gateway', fallback='172.16.10.1')

#routervms
iosv = safeparser.getboolean('DEFAULT', 'iosv', fallback=True)
iosvl2 = safeparser.getboolean('DEFAULT', 'iosvl2', fallback=False)
csr1000v = safeparser.getboolean('DEFAULT', 'csr1000v', fallback=True)
iosxrv432 = safeparser.getboolean('DEFAULT', 'iosxrv432', fallback=False)
iosxrv = safeparser.getboolean('DEFAULT', 'iosxrv', fallback=True)
nxosv = safeparser.getboolean('DEFAULT', 'nxosv', fallback=True)
vpagent = safeparser.getboolean('DEFAULT', 'vpagent', fallback=True)
server = safeparser.getboolean('DEFAULT', 'server', fallback=True)

#vmm clients
vmm_mac = safeparser.getboolean('DEFAULT', 'vmm_mac', fallback=True)
vmm_win32 = safeparser.getboolean('DEFAULT', 'vmm_win32', fallback=True)
vmm_win64 = safeparser.getboolean('DEFAULT', 'vmm_win64', fallback=True)
vmm_linux = safeparser.getboolean('DEFAULT', 'vmm_linux', fallback=True)


if dhcp_public or packer_calls:
    public_ip = '127.0.1.1'


host_sls = ['hostname','domain','public_port','using_dhcp_on_the_public_port','static_ip','public_gateway','public_netmask',
            'l2_port','l2_address','l2_address2','l3_address','l2_port2','l2_port2_enabled','l3_port','first_nameserver',
            'second_nameserver','internalnet_port','inernalnet_netmask','l3_mask','l2_mask2','l2_mask','dummy_int',
            'jumbo_frames']

host_sls_values = [hostname,fqdn,public_port,dhcp_public,public_ip,public_gateway,public_netmask,
            l2_port,l2_address,l2_address2,l3_address,l2_port2,l2_port2_enabled,l3_port,dns1,
            dns2,internalnet_port,internalnet_netmask,l3_mask,l2_mask2,l2_mask,dummy_int,
            jumbo_frames]

if mitaka:
    keystone_auth_url = 'http://127.0.0.1:5000/v3'
    keystone_client = 'openstack'
    keystone_project_list = 'project list'
    keystone_auth_version = 'v3'
else:
    keystone_client = 'keystone'
    keystone_auth_url = 'http://127.0.0.1:5000/v2.0'
    keystone_project_list = 'tenant-list'
    keystone_auth_version = 'v2.0'

qadmincall = ['/usr/bin/neutron', '--os-tenant-name', 'admin', '--os-username', 'admin', '--os-password',
              '{0}'.format(ospassword), '--os-user-domain-id=default', '--os-project-domain-id=default', '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
nadmincall = ['/usr/bin/nova', '--os-tenant-name', 'admin', '--os-username', 'admin', '--os-password',
              '{0}'.format(ospassword), '--os-user-domain-id=default', '--os-project-domain-id=default', '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
kcall = ['/usr/bin/openstack', '--os-tenant-name=admin', '--os-username=admin', '--os-user-domain-id=default', '--os-domain-id=default',  '--os-identity-api-version=3',
              '--os-password={0}'.format(ospassword), '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
cpstr = 'sudo -S cp -f "%(from)s" "%(to)s"'
lnstr = 'sudo -S ln -sf "%(orig)s" "%(link)s"'


def replace(file_path, pattern, subst):
    #Create temp file
    fh, abs_path = mkstemp()
    new_file = open(abs_path, 'w')
    old_file = open(file_path)
    for line in old_file:
        new_file.write(line.replace(pattern, subst))
        #close temp file
    new_file.close()
    close(fh)
    old_file.close()
    #Save permission state
    copystat(file_path, abs_path)
    #Remove original file
    remove(file_path)
    #Move new file
    move(abs_path, file_path)



def building_salt_extra():
    with open(("/tmp/extra"), "w") as extra:
        if not masterless or vagrant_pre_fourth:
            if len(salt_master.split(',')) >= 2:
                if salt_tcp:
                  extra.write("""master: [{salt_master}]\n""".format(salt_master=salt_master_tcp))
                else:
                  extra.write("""master: [{salt_master}]\n""".format(salt_master=salt_master))
                extra.write("""master_type: failover \n""")
                extra.write("""master_shuffle: True \n""")
                extra.write("""random_master: True \n""")
                extra.write("""auth_tries: 1 \n""")
                extra.write("""auth_timeout: 15 \n""")
                extra.write("""master_alive_interval: 180 \n""")
                extra.write("""retry_dns: 0 \n""")
            else:
                if salt_tcp:
                  extra.write("""master: {salt_master}\n""".format(salt_master=salt_master_tcp))
                else:
                  extra.write("""master: {salt_master}\n""".format(salt_master=salt_master))
            if controller:
              extra.write("""verify_master_pubkey_sign: True \n""")
              extra.write("""always_verify_signature: True \n""")
        else:
            if cml:
                extra.write("""file_client: local

fileserver_backend:
  - roots\n""")
            elif path.exists('/usr/local/lib/python2.7/dist-packages/pygit2'):
                extra.write("""gitfs_provider: pygit2\n""")
                extra.write("""file_client: local

fileserver_backend:
  - git
  - roots

gitfs_remotes:
  - https://github.com/Snergster/virl-salt.git\n""")
            elif path.exists('/usr/local/lib/python2.7/dist-packages/dulwich'):
                extra.write("""gitfs_provider: dulwich\n""")
                extra.write("""file_client: local

fileserver_backend:
  - git
  - roots

gitfs_remotes:
  - https://github.com/Snergster/virl-salt.git\n""")
            else:
                extra.write("""file_client: local

fileserver_backend:
  - roots\n""")
        extra.write("""log_level: quiet \n""")
        extra.write("""id: '{salt_id}'\n""".format(salt_id=salt_id))
        extra.write("""append_domain: {salt_domain}\n""".format(salt_domain=salt_domain))
    subprocess.call(['sudo', 'mv', '-f', ('/tmp/extra'), '/etc/salt/minion.d/extra.conf'])
    if salt_tcp:
        with open(("/tmp/tcp.conf"), "w") as stcp:
            stcp.write("""transport: tcp\n""")
            stcp.write("""hash_type: sha256\n""")
        subprocess.call(['sudo', 'mv', '-f', ('/tmp/tcp.conf'), '/etc/salt/minion.d/tcp.conf'])
    else:
        subprocess.call(['sudo', 'rm', '-f', '/etc/salt/minion.d/tcp.conf'])

def building_salt_extras(count):
    with open(("/tmp/extra{count}".format(count=count)), "w") as extra:
        if not masterless or vagrant_pre_fourth:
            if len(salt_master.split(',')) >= 2:
                extra.write("""master: [{salt_master}]\n""".format(salt_master=salt_master))
                extra.write("""master_type: failover \n""")
                extra.write("""master_shuffle: True \n""")
                extra.write("""random_master: True \n""")
                extra.write("""auth_tries: 1 \n""")
                extra.write("""auth_timeout: 15 \n""")
                extra.write("""master_alive_interval: 180 \n""")
                extra.write("""retry_dns: 0 \n""")
            else:
                extra.write("""master: {salt_master}\n""".format(salt_master=salt_master))
            if controller:
              extra.write("""verify_master_pubkey_sign: True \n""")
              extra.write("""always_verify_signature: True \n""")
        else:
            if path.exists('/usr/local/lib/python2.7/dist-packages/pygit2'):
                extra.write("""gitfs_provider: pygit2\n""")
                extra.write("""file_client: local

fileserver_backend:
  - git
  - roots

gitfs_remotes:
  - https://github.com/Snergster/virl-salt.git\n""")
            elif path.exists('/usr/local/lib/python2.7/dist-packages/dulwich'):
                extra.write("""gitfs_provider: dulwich\n""")
                extra.write("""file_client: local

fileserver_backend:
  - git
  - roots

gitfs_remotes:
  - https://github.com/Snergster/virl-salt.git\n""")
            else:
                extra.write("""file_client: local

fileserver_backend:
  - roots\n""")
        extra.write("""log_level: quiet \n""")
        extra.write("""hash_type: md5 \n""")
        if count == 2:
          extra.write("""id: '{salt_id}'\n""".format(salt_id=salt_id2))
          extra.write("""append_domain: {salt_domain}\n""".format(salt_domain=salt_domain2))
        elif count == 3:
          extra.write("""id: '{salt_id}'\n""".format(salt_id=salt_id3))
          extra.write("""append_domain: {salt_domain}\n""".format(salt_domain=salt_domain3))
        elif count == 4:
          extra.write("""id: '{salt_id}'\n""".format(salt_id=salt_id4))
          extra.write("""append_domain: {salt_domain}\n""".format(salt_domain=salt_domain4))          
        extra.write("""pki_dir: /etc/salt{count}/pki/minion \n""".format(count=count))
    subprocess.call(['sudo', 'mkdir', '-p', '/etc/salt{count}/pki/minion'.format(count=count)])
    subprocess.call(['sudo', 'mkdir', '-p', '/etc/salt{count}/minion.d'.format(count=count)])
    subprocess.call(['sudo', 'mv', '-f', ('/tmp/extra{count}'.format(count=count)), '/etc/salt{count}/minion.d/extra.conf'.format(count=count)])
    subprocess.call(['sudo', 'cp', '-f', '/etc/salt/pki/minion/master_sign.pub', '/etc/salt{count}/pki/minion/master_sign.pub'.format(count=count)])
    subprocess.call(['sudo', 'cp', '-f', '/etc/salt/minion', '/etc/salt{count}/minion'.format(count=count)])

def building_salt_all():
    if not path.exists('/etc/salt/virl'):
        subprocess.call(['sudo', 'mkdir', '-p', '/etc/salt/virl'])
    if path.exists('/usr/bin/openstack') or path.exists('/usr/bin/neutron-server'):
        admin_tenid = (subprocess.check_output(['{keystone_client} --os-tenant-name admin --os-username admin'
                                            ' --os-password {ospassword} --os-auth-url={auth_url} --os-user-domain-id default --os-domain-id default  --os-identity-api-version 3'
                                            ' {project} | grep -w "admin" | cut -d "|" -f2'
                                           .format(ospassword=ospassword,auth_url=keystone_auth_url,keystone_client=keystone_client,project=keystone_project_list)], shell=True)[1:33])
        service_tenid = (subprocess.check_output(['{keystone_client} --os-tenant-name admin --os-username admin'
                                            ' --os-password {ospassword} --os-auth-url={auth_url} --os-user-domain-id default --os-domain-id default  --os-identity-api-version 3'
                                            ' {project} | grep -w "service" | cut -d "|" -f2'
                                           .format(ospassword=ospassword,auth_url=keystone_auth_url,keystone_client=keystone_client,project=keystone_project_list)], shell=True)[1:33])
        neutron_extnet_id = (subprocess.check_output(['openstack --os-tenant-name admin --os-username admin'
                                            ' --os-password {ospassword} --os-auth-url={auth_url} --os-user-domain-id default --os-domain-id default  --os-identity-api-version 3'
                                            ' network list | grep -w "ext-net" | cut -d "|" -f2'
                                           .format(ospassword=ospassword,auth_url=keystone_auth_url)], shell=True)[1:33])
    else:
        admin_tenid = ''
        service_tenid = ''
    if path.exists('/usr/bin/neutron-server'):
        neutron_extnet_id = (subprocess.check_output(['openstack --os-tenant-name admin --os-username admin'
                                            ' --os-password {ospassword} --os-auth-url={auth_url} --os-user-domain-id default --os-domain-id default  --os-identity-api-version 3'
                                            ' network list | grep -w "ext-net" | cut -d "|" -f2'
                                           .format(ospassword=ospassword,auth_url=keystone_auth_url)], shell=True)[1:33])
    else:
        neutron_extnet_id = ''
    building_salt_extra()

    with open(("/tmp/openstack"), "w") as openstack:
        openstack.write("""keystone.user: admin
keystone.password: {ospassword}
keystone.tenant: admin
keystone.tenant_id: {tenid}
keystone.auth_url: {auth_url}/
keystone.token: {kstoken}
keystone.region_name: 'RegionOne'
keystone.service_type: 'network'

mysql.user: root
mysql.pass: {mypass}

virl:
  keystone.user: admin
  keystone.password: {ospassword}
  keystone.tenant: admin
  keystone.tenant_id: {tenid}
  keystone.auth_url: 'http://127.0.0.1:5000/v2.0/'
  keystone.region_name: 'RegionOne'
  keystone.service_type: 'network'\n""".format(ospassword=ospassword, kstoken=ks_token, tenid=admin_tenid, mypass=mypassword, auth_url=keystone_auth_url))

    grains = {}
    for key, value in safeparser.items('DEFAULT'):
        if key == 'domain':
            key = 'domain_name'
        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        grains[key] = value

    if cml:
        grains['cinder_enabled'] = False
    else:
        grains['cinder_enabled'] = cinder_device or cinder_file

    if not uwm_port == '14000':
        grains['uwm_url'] = "http://{0}:{1}".format(public_ip,uwm_port)

    if mitaka:
        grains['kilo'] = False

    # Save old mysql password for password changed
    if 'old_mysql_password' in grains:
        del grains['old_mysql_password']
    old_password = get_grains('mysql_password')
    if old_password != mypassword:
        grains['old_mysql_password'] = old_password

    grains['neutron_extnet_id'] = neutron_extnet_id
    grains['service_id'] = service_tenid
    grains['OS_AUTH_URL'] = keystone_auth_url
    grains['admin_id'] = admin_tenid

    if path.exists('/usr/bin/salt-call'):
        grains_json = json.dumps(grains)
        subprocess.check_call(['sudo', 'salt-call', '--local', 'grains.setvals', grains_json])
    else:
        grains_yaml = yaml.safe_dump(grains, default_flow_style=False)
        with open('/tmp/grains', 'w') as grains_file:
            grains_file.write(grains_yaml)
        subprocess.check_call(['sudo', 'mv', '-f', '/tmp/grains', '/etc/salt/grains'])

    subprocess.call(['sudo', 'mv', '-f', ('/tmp/openstack'), '/etc/salt/minion.d/openstack.conf'])
    if not masterless:
        subprocess.call(['sudo', 'service', 'salt-minion', 'restart'])
    else:
        subprocess.call(['sudo', 'service', 'salt-minion', 'stop'])


def create_basic_networks():
    user = 'admin'
    password = ospassword
    qcall = ['/usr/bin/neutron', '--os-tenant-name', '{0}'.format(user), '--os-username', '{0}'.format(user),
             '--os-password', '{0}'.format(password), '--os-user-domain-id=default', '--os-project-domain-id=default',
             '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
    subprocess.call(qcall + ['quota-update', '--router', '-1'])
    try:
        if not varg['iso']:
            # system(cpstr % {'from': (BASEDIR + 'install_scripts/init.d/virl-uwm.init'), 'to': '/etc/init.d/virl-uwm'})
            # system(lnstr % {'orig': '/etc/init.d/virl-uwm', 'link': '/etc/rc2.d/S98virl-uwm'})

            if 'ext-net' not in subprocess.check_output(qcall + ['net-list']):
                subprocess.call(qcall + ['net-create', 'ext-net', '--shared', '--provider:network_type', 'flat',
                                         '--router:external', 'true', '--provider:physical_network', 'ext-net'])
            if 'flat' not in subprocess.check_output(qcall + ['net-list']):
                subprocess.call(qcall + ['net-create', 'flat', '--shared', '--provider:network_type', 'flat',
                                         '--provider:physical_network', 'flat'])
            if 'flat1' not in subprocess.check_output(qcall + ['net-list']) and l2_port2_enabled:
                subprocess.call(qcall + ['net-create', 'flat1', '--shared', '--provider:network_type', 'flat',
                                         '--provider:physical_network', 'flat1'])

        if 'ext-net' not in subprocess.check_output(qcall + ['subnet-list']):
            subprocess.call(qcall + ['subnet-create', 'ext-net', '{0}'.format(l3_network), '--allocation-pool',
                            'start={0},end={1}'.format(l3_s_address, l3_e_address), '--gateway',
                            '{0}'.format(l3_gate), '--name', 'ext-net', '--dns-nameservers', 'list=true',
                            '{0}'.format(snat_dns2), '{0}'.format(snat_dns1)])
        if 'flat' not in subprocess.check_output(qcall + ['subnet-list']):
            subprocess.call(qcall + ['subnet-create', 'flat', '{0}'.format(l2_network), '--allocation-pool',
                            'start={0},end={1}'.format(l2_s_address, l2_e_address), '--gateway',
                            '{0}'.format(l2_gate), '--name', 'flat ', '--dns-nameservers', 'list=true',
                            '{0}'.format(flat_dns2), '{0}'.format(flat_dns1)])
        if 'flat1' not in subprocess.check_output(qcall + ['subnet-list']) and l2_port2_enabled:
            subprocess.call(qcall + ['subnet-create', 'flat1', '{0}'.format(l2_network2), '--allocation-pool',
                            'start={0},end={1}'.format(l2_s_address2, l2_e_address2), '--gateway',
                            '{0}'.format(l2_gate2), '--name', 'flat1', '--dns-nameservers', 'list=true',
                            '{0}'.format(flat2_dns2), '{0}'.format(flat2_dns1)])
    except OSError:
        log.error('Error in basic network creation')


def set_hostname(hostname, fqdn, public_ip):
    host = ('s/controller/{0}/g'.format(hostname))
    etc_dir = str(BASEDIR + 'install_scripts/etc/')
    copy((etc_dir + 'hosts.orig'), (etc_dir + 'hosts'))
    copy((etc_dir + 'hostname.orig'), (etc_dir + 'hostname'))
    subprocess.call(['sed', '-i', host, (etc_dir + 'hosts')])
    subprocess.call(['sed', '-i', host, (etc_dir + 'hostname')])

    if fqdn:
        full_hostname = ('s/#placeholder/{0}/g'.format(public_ip + '    ' + hostname + '    ' + hostname + '.' + fqdn))
        subprocess.call(['sed', '-i', full_hostname, (etc_dir + 'hosts')])

#TODO currently doing nothing with api or compute only nodes
netdir = (BASEDIR + 'install_scripts/etc/network/')


def apache_write():

    with open(("/tmp/apache.conf"), "w") as apache:
        apache.write("""Alias /download /var/www/download\n

<Directory \"/var/www/download\">
    Options Indexes FollowSymLinks MultiViews
    IndexOptions NameWidth=*
</Directory>

Alias /doc /var/www/doc

<Directory \"/var/www/doc\">
    Options Indexes FollowSymLinks MultiViews
    IndexOptions NameWidth=*
</Directory>\n

Alias /training /var/www/training

<Directory \"/var/www/training\">
    Options Indexes FollowSymLinks MultiViews
    IndexOptions NameWidth=*
</Directory>\n

Alias /videos /var/www/videos

<Directory \"/var/www/videos\">
    Options Indexes FollowSymLinks MultiViews
    IndexOptions NameWidth=*
</Directory>\n""")
    subprocess.call(['sudo', 'cp', '-f', ('/tmp/apache.conf'),
                         '/etc/apache2/sites-enabled/apache.conf'])


def User_Creator(user_list, user_list_limited):
    UNET = True
    user_check = subprocess.check_output(kcall + ['user list'])

    if user_list:
        for each_user in user_list.split(','):
            (user, password) = each_user.split(':')
            print ('user creation section for user {0}'.format(user))
            subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'virl_core.project_present', user, 'user_password={0}'
                .format(password), 'user_os_password={0}'.format(password)])
            subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'virl_core.user_present', 'name={0}'.format(user),
                             'project={0}'.format(user),'password={0}'.format(password), 'role=admin'])

    if user_list_limited:
        for each_limited_user in user_list_limited.split(','):
            (user, password, limit) = each_limited_user.split(':')
            subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'virl_core.project_present', user, 'user_password={0}'
                .format(password), 'user_os_password={0}'.format(password), 'quota_instances={0}'.format(limit)])


def set_vnc_password(vnc_password):
    if not path.exists('/home/virl/.vnc'):
        mkdir('/home/virl/.vnc')
    if vnc_passwd == 'letmein':
        subprocess.call(['cp', '-f', (BASEDIR + 'install_scripts/vnc.passwd'), '/home/virl/.vnc/passwd'])
    else:
        subprocess.call(['cp', '-f', (BASEDIR + 'install_scripts/vnc.passwd'), '/home/virl/.vnc/passwd'])
        _vnc = envoy.run('vncpasswd -f', data=vnc_password, timeout=4)
        _f = open("/home/virl/.vnc/passwd", "w")
        _f.write(_vnc.std_out)
        _f.close()



def Net_Creator(user, password):
    qcall = ['neutron', '--os-tenant-name', '{0}'.format(user), '--os-user-domain-id=default', '--os-project-domain-id=default', '--os-username', '{0}'.format(user), '--os-password',
             '{0}'.format(password), '--os-user-domain-id=default', '--os-project-domain-id=default', '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
    try:
        if user not in subprocess.check_output(qadmincall + ['net-list']) and not user == 'flat':
            subprocess.call(qcall + ['net-create', '{0}'.format(user)])
            subprocess.call(qcall + ['net-create', '{0}_snat'.format(user)])
        else:
            print('network already exists')

        if user not in subprocess.check_output(qadmincall + ['subnet-list']) and not user == 'flat':
            subprocess.call(qcall + ['subnet-create', '{0}'.format(user), '10.11.12.0/24', '--gateway', '10.11.12.1',
                                     '--dns-nameserver', '10.11.12.1', '--name', '{0}'.format(user)])
            subprocess.call(qcall + ['subnet-create', '{0}_snat'.format(user), '10.11.11.0/24', '--gateway',
                                     '10.11.11.1', '--dns-nameserver', '10.11.11.1', '--name', '{0}_snat'.format(user)])
        else:
            log.warning('subnet already exists')

        if user not in subprocess.check_output(qadmincall + ['router-list']):
            subprocess.call(qcall + ['router-create', '{0}'.format(user)])
            subprocess.call(qcall + ['router-interface-add', '{0}'.format(user), '{0}'.format(user)])
            subprocess.call(qcall + ['router-interface-add', '{0}'.format(user), '{0}_snat'.format(user)])
            subprocess.call(qadmincall + ['router-gateway-set', '{0}'.format(user), 'ext-net'])
        else:
            log.debug('router already exists')

    except:
        log.error('Error in net create')



def call_salt(slsfile):
    print 'Please be patient file {slsfile} is running'.format(slsfile=slsfile)
    if masterless:
        subprocess.call(['sudo', 'salt-call', '--local', '-l', 'quiet', 'state.sls', slsfile])
    else:
        subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'state.sls', slsfile])
    sleep(5)

def call_salt_quiet(slsfile):
    print 'Please be patient file {slsfile} is running'.format(slsfile=slsfile)
    if masterless:
        subprocess.call(['sudo', 'salt-call', '--local', '-l', 'quiet', 'state.sls', slsfile])
    else:
        subprocess.call(['sudo', 'salt-call', '--state-output=terse', '-l', 'quiet', 'state.sls', slsfile])
    sleep(5)


def get_grains(variable_name):
    proc = subprocess.Popen(['sudo', 'salt-call', '--out', 'json', 'grains.get', variable_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = proc.communicate()
    if error:
        print('Unable to load %s from grains:' % variable_name)
        print(error)
    output = json.loads(output)

    return output.get('local')


def get_pillar(variable_name):
    proc = subprocess.Popen(['sudo', 'salt-call', '--out', 'json', 'pillar.get', variable_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = proc.communicate()
    if error:
        print('Unable to load %s from pillar:' % variable_name)
        print(error)
    output = json.loads(output)

    return output.get('local')


def parse_version_info(version_str):
    """Parse version info from string, e.g. "0.1.2.3" ~> (0, 1, 2, 3)"""
    version_str = version_str.strip()
    version_info = []
    for part in re.split(r'[\.-]', version_str):
        try:
            part = int(part)
            version_info.append(part)
        except ValueError:
            pass
    return tuple(version_info)


def check_versions(new_version, old_version):
    new_versions = parse_version_info(new_version)
    old_versions = parse_version_info(old_version)
    max_versions = max(len(new_versions), len(old_versions))
    for id in range(max_versions):
        new_ver = new_versions[id] if id < len(new_versions) else 0
        old_ver = old_versions[id] if id < len(old_versions) else 0
        if new_ver > old_ver:
            return True
        if new_ver < old_ver:
            return False
    return None


def get_virl_version_key():
    out = subprocess.check_output('lsb_release -cs', shell=True)
    ubuntu_codename = out.strip()
    key = 'virl_%s' % ubuntu_codename
    return key


def determine_upgrade_type():
    # major.minor.maintenance
    virl_current = get_grains('virl_release')
    if virl_current:
        virl_available = get_pillar('version:%s' % get_virl_version_key())
        if not virl_available:
            return None

        check_result = check_versions(virl_available, virl_current)

        if check_result is None:
            return 'reinstall'

        if not check_result:
            return 'downgrade'

        maj1 = re.match("([0-9]+)\.", virl_current)
        maj2 = re.match("([0-9]+)\.", virl_available)
        if maj1.group(1) != maj2.group(1):
            # not upgradable
            return 'major'

        min1 = re.match("[0-9]+\.([0-9]+)\.", virl_current)
        min2 = re.match("[0-9]+\.([0-9]+)\.", virl_available)
        if min1.group(1) != min2.group(1):
            return 'minor'

        # not identical version and not major version change
        return 'maintenance'

    # no current version available, disallow upgrade
    return None

if __name__ == "__main__":

    varg = docopt(__doc__, version='vinstall .8')

    if varg['upgrade']:
        upgrade_type = determine_upgrade_type()

        if upgrade_type is None:
            virl_available = get_pillar('version:%s' % get_virl_version_key())
            print(
                'We are sorry, but in-place upgrades from/to an unknown '
                'release are not supported. Please back up any data you wish '
                'to keep (e.g. custom images, subtypes, LXC templates, '
                'projects and users, the /etc/virl.ini initialization file, '
                'topology files created in VMMaestro installed on the host). '
                'You will need to download and install %s release from '
                'scratch.' % virl_available
            )
            sys.exit(1)

        if upgrade_type == 'major' or upgrade_type == 'downgrade':
            virl_current = get_grains('virl_release')
            virl_available = get_pillar('version:%s' % get_virl_version_key())
            print(
                'We are sorry, but in-place upgrades from the current release '
                '%(current)s to release %(available)s are not supported '
                'anymore. Please back up any data you wish to keep (e.g. '
                'custom images, subtypes, LXC templates, projects and users, '
                'the /etc/virl.ini initialization file, topology files '
                'created in VMMaestro installed on the host). You will need '
                'to download and install %(available)s release from scratch.'
                % {'current': virl_current, 'available': virl_available}
            )
            sys.exit(1)

    if varg['zero']:
        if proxy:
            subprocess.call(['sudo', 'env', 'https_proxy={0}'.format(http_proxy),
                             '{0}install_scripts/install_salt.sh'.format(BASEDIR)])
        else:
            subprocess.call(['sudo', '{0}install_scripts/install_salt.sh'.format(BASEDIR)])
        sleep(10)
        building_salt_all()
        subprocess.call(['sudo', 'rm', '/etc/apt/sources.list.d/saltstack*'])
        for i in range(20):
            print '*'*50
        print ' Your salt key needs to be accepted by salt master before continuing\n'
        print ' You can test with salt-call test.ping for ok result'

    if varg['highstate'] or varg['upgrade'] or varg['rehost']:
        if masterless:
            subprocess.call(['sudo', 'salt-call', '--local', '-l', 'quiet', 'state.highstate'])
        else:
            subprocess.call(['sudo', 'salt-call', 'state.highstate'])
        sleep(10)

    if varg['vinstall'] or varg['upgrade']:
        call_salt('virl.vinstall')
        sleep(2)

    if varg['upgrade'] or varg['rehost']:
        call_salt('common.pip')
        building_salt_all()
        sleep(10)

    if varg['first']:
        for _each in ['common.virl,virl.basics']:
            call_salt(_each)
        if not masterless:
            subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'saltutil.sync_all'])
        building_salt_all()
        call_salt('virl.openrc')
        print 'Please validate the contents of /etc/network/interfaces before rebooting!'

    if varg['second'] or varg['all'] :
        building_salt_all()
        sleep(10)
        # for _each in ['openstack.mysql', 'openstack.rabbitmq', 'openstack.keystone.install', 'openstack.keystone.setup',
        #               'openstack.keystone.endpoint', 'openstack.osclients', 'virl.openrc', 'openstack.glance']:
        #     call_salt(_each)
        call_salt('openstack')
        call_salt('openstack.setup')

        admin_tenid = (subprocess.check_output(['{keystone_client} --os-tenant-name admin --os-username admin'
                                            ' --os-password {ospassword} --os-auth-url=http://localhost:5000/{auth_version}'
                                            ' {project_list} | grep -w "admin" | cut -d "|" -f2'
                                           .format(ospassword=ospassword,auth_version=keystone_auth_version,project_list=keystone_project_list,keystone_client=keystone_client)], shell=True)[1:33])
        service_tenid = (subprocess.check_output(['{keystone_client} --os-tenant-name admin --os-username admin'
                                            ' --os-password {ospassword} --os-auth-url=http://localhost:5000/{auth_version}'
                                            ' {project_list}| grep -w "service" | cut -d "|" -f2'
                                           .format(ospassword=ospassword,auth_version=keystone_auth_version,project_list=keystone_project_list,keystone_client=keystone_client)], shell=True)[1:33])
        subprocess.call(['sudo', 'crudini', '--set','/etc/salt/minion.d/openstack.conf', '',
                         'keystone.tenant_id', (' ' + admin_tenid)])
        building_salt_all()
        sleep(8)
        # call_salt('openstack.neutron')
        novaclient = '/home/virl/.novaclient'
        if path.exists(novaclient):
            subprocess.call(['sudo', 'chown', '-R', 'virl:virl', '/home/virl/.novaclient'])

    if varg['third'] or varg['all'] :
        # if cinder:
        #     # call_salt('openstack.cinder.install')
        #     if cinder_file:
        #         subprocess.call(['sudo', '/bin/dd', 'if=/dev/zero', 'of={0}'.format(cinder_loc), 'bs=1M',
        #                          'count={0}'.format(cinder_size)])
        #         subprocess.call(['sudo', '/sbin/losetup', '-f', '--show', '{0}'.format(cinder_loc)])
        #         subprocess.call(['sudo', '/sbin/pvcreate', '/dev/loop0'])
        #         subprocess.call(['sudo', '/sbin/vgcreate', 'cinder-volumes', '/dev/loop0'])
        #         # subprocess.call(['sudo', '/sbin/vgcreate', 'cinder-volumes', '{0}'.format(cinder_loc)])
        #     elif cinder_device:
        #         subprocess.call(['sudo', '/sbin/pvcreate', '{0}'.format(cinder_loc)])
        #         subprocess.call(['sudo', '/sbin/vgcreate', 'cinder-volumes', '{0}'.format(cinder_loc)])
        #     else:
        #         print 'No cinder file or drive created'

        #
        # if horizon:
        #     call_salt('openstack.dash')
        #

        admin_tenid = (subprocess.check_output(['{keystone_client} --os-tenant-name admin --os-username admin'
                                            ' --os-password {ospassword} --os-auth-url=http://localhost:5000/{auth_version}'
                                            ' {project_list} | grep -w "admin" | cut -d "|" -f2'
                                           .format(ospassword=ospassword,auth_version=keystone_auth_version,project_list=keystone_project_list,keystone_client=keystone_client)], shell=True)[1:33])
        subprocess.call(['sudo', 'crudini', '--set','/etc/salt/minion.d/openstack.conf', '',
                          'keystone.tenant_id', (' ' + admin_tenid)])
        create_basic_networks()
        apache_write()
        if vnc:
            if masterless:
                call_salt('common.tightvncserver')
            else:
                subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'state.sls', 'common.tightvncserver'])

            if not vnc_passwd == 'letmein':
                set_vnc_password(vnc_passwd)
            sleep(5)
        # if heat:
        #     call_salt('openstack.heat')

    # if varg['fourth'] or varg['mini'] or varg['all'] or varg['upgrade']:
    #     call_salt('openstack.nova.install')
    #     building_salt_all()
    #     sleep(5)
    #    call_salt('openstack.neutron.changes')

    if varg['fourth'] or varg['all'] :
        if masterless:
            call_salt('openstack.neutron.changes,virl.std,virl.ank,virl.openvpn')
            # call_salt('virl.ank')
        else:
            subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'state.sls', 'openstack.neutron.changes,virl.std,virl.ank'])

        if guest_account:
            call_salt('virl.guest')
        # std_install()
        User_Creator(user_list, user_list_limited)
        print ('You need to restart now')
    if varg['test']:
        building_salt_all()
        qcall = ['neutron', '--os-tenant-name', 'admin', '--os-username', 'admin', '--os-password',
                 ospassword, '--os-user-domain-id=default', '--os-project-domain-id=default', '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
        subprocess.call(qcall + ['subnet-delete', 'flat'])
        subprocess.call(qcall + ['subnet-delete', 'flat1'])
        subprocess.call(qcall + ['subnet-delete', 'ext-net'])
        create_basic_networks()
        print ('You need to restart now')
    if varg['test1']:
      print 'nothing to see here'
    if desktop:
        if varg['desktop']:
            call_salt('virl.desktop')
            sleep(5)
    if varg['rehost'] or varg['upgrade']:
        call_salt('common.pip')
        call_salt('common.salt-minion')
        building_salt_all()
        subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'state.highstate'])
        call_salt('common.distuptodate')
        #call_salt('virl.network.int')
        call_salt('openstack')
        call_salt('openstack.setup')
        call_salt('openstack.stop')
        call_salt('virl.basics')
        call_salt('openstack.rabbitmq')
        call_salt('openstack.start')
        call_salt('openstack.rabbitmq')
        call_salt('openstack.restart')
        call_salt('virl.std')
        call_salt('virl.ank')
        call_salt('virl.docker')

        if masterless:
            subprocess.call(['sudo', 'salt-call', '--local', '-l', 'quiet', 'virl_core.project_absent', 'name=guest'])
        else:
            subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'virl_core.project_absent', 'name=guest'])

        nova_services_hosts = ["'ubuntu'"]
        nova_service_list = ["nova-compute","nova-cert","nova-consoleauth","nova-scheduler","nova-conductor"]
        print ('Deleting Nova services for old hostnames')
        pmypassword = '-p' + mypassword
        subprocess.call(['sudo', 'mysql', '-uroot', pmypassword , 'nova',
                        '--execute=delete from compute_nodes'])
        subprocess.call(['sudo', 'mysql', '-uroot', pmypassword , 'nova',
                         '--execute=delete from services'])

        if not (path.exists('/srv/salt/virl/host.sls')) and (path.exists('/srv/salt/host.sls')):
            subprocess.call(['sudo', 'cp', '/srv/salt/host.sls', '/srv/salt/virl/host.sls'])
        if not (path.exists('/srv/salt/virl/ntp.sls')) and (path.exists('/srv/salt/ntp.sls')):
            subprocess.call(['sudo', 'cp', '/srv/salt/ntp.sls', '/srv/salt/virl/ntp.sls'])
        subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'state.sls', 'openstack.restart'])
        sleep(50)
        qcall = ['neutron', '--os-tenant-name', 'admin', '--os-username', 'admin', '--os-password',
                 ospassword, '--os-user-domain-id=default', '--os-project-domain-id=default', '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
        nmcall = ['nova-manage', '--os-tenant-name', 'admin', '--os-username', 'admin', '--os-password',
                 ospassword, '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
        q_delete_list = (subprocess.check_output( ['neutron --os-username admin --os-password {ospassword} --os-tenant-name admin --os-user-domain-id=default --os-project-domain-id=default --os-auth-url=http://localhost:5000/{authver} agent-list | grep -v "+-" | sed 1d | grep -v "{hostname}" | grep -v "region" | cut -d "|" -f2'.format(ospassword=ospassword,hostname=hostname,authver=keystone_auth_version)], shell=True)).split()
        print q_delete_list
        for _qeach in q_delete_list:
            subprocess.call(qcall + ['agent-delete', '{0}'.format(_qeach)])
        # for _keach in k_delete_list:
        #     subprocess.call(kcall + ['endpoint-delete', '{0}'.format(_keach)])
        if guest_account:
            call_salt('virl.guest')
        novaclient = '/home/virl/.novaclient'
        if path.exists(novaclient):
            subprocess.call(['sudo', 'chown', '-R', 'virl:virl', '/home/virl/.novaclient'])
        # User_Creator(user_list, user_list_limited)
        if desktop:
            subprocess.call(['rm', '-f', '/home/virl/Desktop/Edit-settings.desktop'])
            subprocess.call(['rm', '-f', '/home/virl/Desktop/VIRL-renumber.desktop'])
            subprocess.call(['rm', '-f', '/home/virl/Desktop/README.desktop'])
        print ('You need to restart now')
    if varg['renumber']:
        print ('This command no longer required.')
        sleep(30)
    if varg['defrost']:
        building_salt_all()
        call_salt('openstack')
        call_salt('openstack.setup')
        call_salt('openstack.stop')
        call_salt('virl.basics')
        call_salt('openstack.rabbitmq')
        call_salt('openstack.start')
        call_salt('openstack.rabbitmq')
        call_salt('openstack.restart')
        call_salt('virl.std')
        call_salt('virl.ank')

        if masterless:
            subprocess.call(['sudo', 'salt-call', '--local', '-l', 'quiet', 'virl_core.project_absent', 'name=guest'])
        else:
            subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'virl_core.project_absent', 'name=guest'])

        nova_services_hosts = ["'ubuntu'"]
        nova_service_list = ["nova-compute","nova-cert","nova-consoleauth","nova-scheduler","nova-conductor"]
        print ('Deleting Nova services for old hostnames')
        pmypassword = '-p' + mypassword
        subprocess.call(['sudo', 'mysql', '-uroot', pmypassword , 'nova',
                        '--execute=delete from compute_nodes'])
        subprocess.call(['sudo', 'mysql', '-uroot', pmypassword , 'nova',
                         '--execute=delete from services'])

        if not (path.exists('/srv/salt/virl/host.sls')) and (path.exists('/srv/salt/host.sls')):
            subprocess.call(['sudo', 'cp', '/srv/salt/host.sls', '/srv/salt/virl/host.sls'])
        if not (path.exists('/srv/salt/virl/ntp.sls')) and (path.exists('/srv/salt/ntp.sls')):
            subprocess.call(['sudo', 'cp', '/srv/salt/ntp.sls', '/srv/salt/virl/ntp.sls'])
        subprocess.call(['sudo', 'salt-call', '-l', 'quiet', 'state.sls', 'openstack.restart'])
        sleep(50)
        qcall = ['neutron', '--os-tenant-name', 'admin', '--os-username', 'admin', '--os-password',
                 ospassword, '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
        nmcall = ['nova-manage', '--os-tenant-name', 'admin', '--os-username', 'admin', '--os-password',
                 ospassword, '--os-auth-url=http://localhost:5000/{0}'.format(keystone_auth_version)]
        subprocess.call(qcall + ['subnet-delete', 'flat'])
        subprocess.call(qcall + ['subnet-delete', 'flat1'])
        subprocess.call(qcall + ['subnet-delete', 'ext-net'])
        q_delete_list = (subprocess.check_output( ['neutron --os-username admin --os-password {ospassword} --os-tenant-name admin --os-auth-url=http://localhost:5000/{authver} agent-list | grep -v "{hostname}" |grep -v "region" | grep -v "+-" | cut -d "|" -f2'.format(ospassword=ospassword,hostname=hostname,authver=keystone_auth_version)], shell=True)).split()
        print q_delete_list
        for _qeach in q_delete_list:
            subprocess.call(qcall + ['agent-delete', '{0}'.format(_qeach)])
        create_basic_networks()
        if guest_account:
            call_salt('virl.guest')
        novaclient = '/home/virl/.novaclient'
        if path.exists(novaclient):
            subprocess.call(['sudo', 'chown', '-R', 'virl:virl', '/home/virl/.novaclient'])
    if varg['nova']:
        novaclient = '/home/virl/.novaclient'
        if path.exists(novaclient):
            subprocess.call(['sudo', 'chown', '-R', 'virl:virl', '/home/virl/.novaclient'])
    if varg['host']:
        call_salt('virl.host')
    if varg['routervms']:
        call_salt_quiet('virl.routervms')
    if varg['vmm']:
        call_salt_quiet('virl.vmm.download')
        if desktop:
          call_salt_quiet('virl.vmm.local')

    if varg['salt']:
        building_salt_all()
        if multi_salt_key:
          while multi_salt_key > 1:
            building_salt_extras(multi_salt_key)
            multi_salt_key = multi_salt_key -1
        if virl_cluster and controller:
            call_salt_quiet('common.salt-master.cluster-config')
    if varg['users']:
        User_Creator(user_list, user_list_limited)

    if varg['bridge']:
        call_salt('common.bridge')
    if varg['kvm']:
        call_salt('common.kvm,common.ksm')
    if path.exists('/tmp/install.out'):
        subprocess.call(['sudo', 'rm', '/tmp/install.out'])
