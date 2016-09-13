#!/usr/bin/python
__author__ = 'ejk'
''' The bootstrap-salt.sh script here is a direct copy of github.bom/saltstack/salt-bootstrap
    you can find the authors of that script here
    https://github.com/saltstack/salt-bootstrap/blob/develop/AUTHORS.rst
    all credit to them for that fine piece of work'''
import subprocess
from os import path, system
from time import sleep
import glob

salt_master = 'salt-master.cisco.com'
salt_name = 'virl'
salt_append_domain = 'virl.info'
while_exit = 0
cwd = path.realpath('./')
proxy = 'None'
hostname = 'virl'
domain = 'virl.info'

if system('grep 16.04 /etc/issue.net') == 0:
    xenial = True
else:
    xenial = False
if xenial:
    nano_path = '/bin/nano'
else:
    nano_path = '/usr/bin/nano'

while not while_exit:
    print (30 * '-')
    print ("   V I R L - I N S T A L L - M E N U")
    print (30 * '-')
    print ("1. Change salt master from {0} ".format(salt_master))
    print ("2. Change salt id from {0} or salt domain from {1}".format(salt_name, salt_append_domain))
    print ("3. Change hostname from {0} or domain name {1}".format(hostname, domain))
    print ("4. Write out extra.conf")
    print ("5. Change http proxy from {0}".format(proxy))
    print ("6. install salt without preseed keys")
    print ("7. install salt with preseed keys in {0}".format(cwd + '/preseed_keys'))
    print ("8. Test if you are connected to salt-master")
    print ("9. Install virl installer and settings")
    print ("10. Edit /etc/virl.ini")
    print ("11. Exit")
    print (30 * '-')

    choice = raw_input('Which step are you on [1-11] : ')

    choice = int(choice)

    if choice == 1:
        salt_master = raw_input('Salt master [%s] ' % salt_master) or 'salt-master.cisco.com'
    if choice == 2:
        salt_name = raw_input('Salt id [%s] ' % salt_name) or 'virl'
        salt_append_domain = raw_input('Salt domain name [%s] ' % salt_append_domain) or 'virl.info'
    if choice == 3:
        hostname = raw_input('System hostname [%s] ' % hostname) or 'virl'
        domain = raw_input('System Domain name [%s] ' % domain) or 'virl.info'
    if choice == 4:
        if not path.exists('/etc/salt/virl'):
            subprocess.check_output(['mkdir', '-p', '/etc/salt/virl'])
        if not path.exists('/etc/salt/minion.d'):
            subprocess.check_output(['mkdir', '-p', '/etc/salt/minion.d'])
        with open(("/etc/salt/minion.d/extra.conf"), "w") as extra:
            extra.write("""master: [{salt_master}]\n""".format(salt_master=salt_master))
            extra.write("""id: {salt_name}\n""".format(salt_name=salt_name))
            extra.write("""append_domain: {salt_append_domain}\n""".format(salt_append_domain=salt_append_domain))
            if salt_master == 'masterless':
                extra.write("""file_client: local

fileserver_backend:
  - git
  - roots

gitfs_provider: Dulwich

gitfs_remotes:
  - https://github.com/Snergster/virl-salt.git\n""")
            else:
                if len(salt_master.split(',')) >= 2:
                  extra.write("""master_type: failover \n""")
                extra.write("""verify_master_pubkey_sign: True \n""")
                extra.write("""master_shuffle: True \n""")
                extra.write("""master_alive_interval: 180 \n""")
            ##TODO waiting for salt to put this back in
            # extra.write("""grains_dirs:\n""")
            # extra.write("""  - /etc/salt/virl\n""")
        with open(("/etc/salt/minion.d/stateagg.conf"), "w") as stateagg:
            stateagg.write("""state_aggregate: False \n""")

    if choice == 5:
        proxy = raw_input('Http proxy [%s] ' % proxy) or 'None'
        if not proxy == 'None':
            if not path.exists('/etc/salt'):
                subprocess.check_output(['mkdir', '-p', '/etc/salt'])
            with open(("/etc/salt/grains"), "w") as grains:
                grains.write("""proxy: True\n""")
                grains.write("""http_proxy: {proxy}\n""".format(proxy=proxy))
        else:
            with open(("/etc/salt/grains"), "w") as grains:
                grains.write("""proxy: False\n""")

    if choice == 6:
        subprocess.call(['mkdir', '-p','/etc/salt/pki/minion'])
        subprocess.call(['cp', './master_sign.pub', '/etc/salt/pki/minion'])
        if salt_master == 'masterless':
            subprocess.call(['git', 'clone', '--depth', '1', 'https://github.com/Snergster/virl-salt.git', '/srv/salt'])
            if not proxy == 'None':
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh', '-P', '-H', '{proxy}'.format(proxy=proxy), '-X', '-P', 'stable'])
            else:
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh', '-X', '-P', 'stable'])
        else:
            if not proxy == 'None':
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh', '-P', '-H', '{proxy}'.format(proxy=proxy), '-X', '-P', 'stable'])
            else:
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh', '-P', 'stable'])
    if choice == 7:
        subprocess.call(['mkdir', '-p','/etc/salt/pki/minion'])
        subprocess.call(['cp', './master_sign.pub', '/etc/salt/pki/minion'])
        subprocess.call(['rm', '-f', './preseed_keys/minion.pem'])
        for file in glob.glob(r'{0}/preseed_keys/*.pem'.format(cwd)):
            subprocess.call(['cp', '{0}'.format(file), '{0}/preseed_keys/minion.pem'.format(cwd)])
        subprocess.call('openssl rsa -in {0}/preseed_keys/minion.pem  -pubout > {0}/preseed_keys/minion.pub'.format(cwd), shell=True)
        subprocess.call(['cp', '-f', '{0}/preseed_keys/minion.pem'.format(cwd), '/etc/salt/pki/minion/minion.pem'])
        subprocess.call(['cp', '-f', '{0}/preseed_keys/minion.pub'.format(cwd), '/etc/salt/pki/minion/minion.pub'])
        subprocess.call(['chmod', '400', '/etc/salt/pki/minion/minion.pem'])
        if salt_master == 'masterless':
            subprocess.call(['git', 'clone', 'https://github.com/Snergster/virl-salt.git', '/srv/salt'])
            if not proxy == 'None':
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh', '-P', '-H', '{proxy}'.format(proxy=proxy), '-X', '-P', 'stable'])
            else:
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh', '-X', '-P', 'stable'])
        else:
            if not proxy == 'None':
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh','-P', '-H', '{proxy}'.format(proxy=proxy), '-X', '-P', 'stable'])
            else:
              subprocess.call(['sh', '/home/virl/virl-bootstrap/bootstrap-salt.sh', '-P', 'stable'])

    if choice == 8:
        if salt_master == 'masterless':
            print "Running in masterless mode skipping ping."
        else:
            subprocess.call(['salt-call', 'test.ping'])
    if choice == 9:
        if xenial:
            subprocess.call(['salt-call', '--local', 'grains.setval', 'mitaka', 'true'])
            subprocess.call(['salt-call', '--local', 'grains.setval', 'kilo', 'false'])
        else:
            subprocess.call(['salt-call', '--local', 'grains.setval', 'kilo', 'true'])
        if salt_master == 'masterless':
            if xenial:
                subprocess.call(['salt-call', '--local', 'state.sls', 'common.xenial-pip'])
            subprocess.call(['salt-call', '--local', 'state.sls', 'zero'])
        else:
            if xenial:
                subprocess.call(['salt-call', '-l', 'debug', 'state.sls', 'common.xenial-pip'])
            subprocess.call(['salt-call', '-l', 'debug', 'state.sls', 'zero'])
    if choice == 10:
        if not path.exists('/etc/virl.ini'):
            subprocess.call(['cp', './vsettings.ini', '/etc/virl.ini'])
        subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'salt_master', salt_master])
        subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'salt_id', salt_name])
        subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'salt_domain', salt_append_domain])
        if salt_master == 'masterless':
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'salt_masterless', 'true'])
        if not proxy == 'None':
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'proxy', 'True'])
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'http_proxy', proxy])
        else:
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'proxy', 'False'])
        if not hostname == 'virl' or not domain == 'virl.info':
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'hostname', hostname ])
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'domain_name', domain])
        if xenial:
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'mitaka', 'True'])
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'kilo', 'False'])
        else:
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'mitaka', 'False'])
            subprocess.call(['crudini', '--set','/etc/virl.ini', 'DEFAULT',
                         'kilo', 'True'])
        subprocess.call([nano_path, '/etc/virl.ini'])

    if choice == 11:
        if path.isfile('/etc/salt/grains'):
            subprocess.call(['rm', '/etc/salt/grains'])
        subprocess.call(['/usr/local/bin/vinstall', 'salt'])
        sleep(5)
        subprocess.call(['salt-call', '-l', 'debug', 'state.sls', 'common.virl'])
        subprocess.call(['salt-call', '-l', 'debug', 'state.sls', 'virl.basics'])
        subprocess.call(['salt-call', '-l', 'debug', 'saltutil.sync_all'])
        subprocess.call(['salt-call', '-l', 'debug', 'state.sls', 'common.virl,virl.web'])
        subprocess.call(['/usr/local/bin/vinstall', 'salt'])
        subprocess.call(['salt-call', '-l', 'debug', 'state.sls', 'virl.openrc'])
        if xenial:
            subprocess.call(['salt-call', '-l', 'debug', 'state.sls', 'common.xenial-bootstrap'])
        print 'Please validate the contents of /etc/network/interfaces before rebooting!'
        while_exit = 1
