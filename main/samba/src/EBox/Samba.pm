# Copyright (C) 2008-2014 Zentyal S.L.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

use strict;
use warnings;

package EBox::Samba;

use base qw(EBox::Module::LDAP
            EBox::SysInfo::Observer
            EBox::FirewallObserver
            EBox::LogObserver);

use EBox::Config;
use EBox::Exceptions::External;
use EBox::Exceptions::Internal;
use EBox::Exceptions::InvalidType;
use EBox::Exceptions::LDAP;
use EBox::Exceptions::MissingArgument;
use EBox::Exceptions::UnwillingToPerform;
use EBox::FileSystem;
use EBox::Gettext;
use EBox::Global;
use EBox::Ldap;
use EBox::LdapUserImplementation;
use EBox::Menu::Folder;
use EBox::Menu::Item;
use EBox::SambaLogHelper;
use EBox::Service;
use EBox::Sudo;
use EBox::SyncFolders::Folder;
use EBox::Samba::Computer;
use EBox::Samba::Contact;
use EBox::Samba::Container;
use EBox::Samba::DMD;
use EBox::Samba::Group;
use EBox::Samba::LdapObject;
use EBox::Samba::NamingContext;
use EBox::Samba::OU;
use EBox::Samba::Provision;
use EBox::Samba::SecurityPrincipal;
use EBox::Samba::User;
use EBox::Util::Random qw( generate );
use EBox::Util::Random;
use EBox::Util::Version;

use Digest::SHA;
use Digest::MD5;
use Sys::Hostname;

use TryCatch;
use JSON::XS;
use Net::LDAP::Control::Sort;
use Net::LDAP::Util qw(ldap_explode_dn);
use File::Copy;
use File::Slurp;
use File::Basename;
use File::Temp qw/tempfile/;
use Perl6::Junction qw(any);
use String::ShellQuote;
use Fcntl qw(:flock);
use Net::Ping;
use String::ShellQuote 'shell_quote';
use Time::HiRes;
use IO::Socket::INET;
use IO::Socket::UNIX;


use constant SAMBA_DIR            => '/home/samba/';
use constant SAMBACONFFILE        => '/etc/samba/smb.conf';
use constant SHARESCONFFILE       => '/etc/samba/shares.conf';
use constant PRIVATE_DIR          => '/var/lib/samba/private/';
use constant SAMBA_DNS_DIR        => '/var/lib/samba/bind-dns/';
use constant SAMBA_DNS_ZONE       => SAMBA_DNS_DIR . 'named.conf';
use constant SAMBA_DNS_POLICY     => SAMBA_DNS_DIR . 'named.conf.update';
use constant SAMBA_DNS_KEYTAB     => PRIVATE_DIR . 'dns.keytab';
use constant SECRETS_KEYTAB       => PRIVATE_DIR . 'secrets.keytab';
use constant SAM_DB               => PRIVATE_DIR . 'sam.ldb';
use constant SAMBA_PRIVILEGED_SOCKET => PRIVATE_DIR . '/ldap_priv';
use constant FSTAB_FILE           => '/etc/fstab';
use constant SYSVOL_DIR           => '/var/lib/samba/sysvol';
use constant PROFILES_DIR         => SAMBA_DIR . 'profiles';
use constant SAMBA_DNS_UPDATE_LIST => PRIVATE_DIR . 'dns_update_list';

use constant COMPUTERSDN    => 'ou=Computers';
use constant AD_COMPUTERSDN => 'cn=Computers';

use constant STANDALONE_MODE      => 'master';
use constant EXTERNAL_AD_MODE     => 'external-ad';
use constant BACKUP_MODE_FILE     => 'LDAP_MODE.bak';
use constant BACKUP_USERS_FILE    => 'userlist.bak';

use constant JOURNAL_DIR    => EBox::Config::home() . 'syncjournal/';
use constant AUTHCONFIGTMPL => '/etc/auth-client-config/profile.d/acc-zentyal';

use constant SAMBACONFFILE        => '/etc/samba/smb.conf';
use constant SYSVOL_DIR           => '/var/lib/samba/sysvol';

use constant SHARES_DIR           => SAMBA_DIR . 'shares';
use constant PROFILE_PHOTO_CRON_FILE => '/etc/cron.d/zentyal-profile-photo';

# Kerberos constants
use constant KERBEROS_PORT => 88;
use constant KPASSWD_PORT => 464;
use constant KRB5_CONF_FILE => '/var/lib/samba/private/krb5.conf';
use constant SYSTEM_WIDE_KRB5_CONF_FILE => '/etc/krb5.conf';
use constant SYSTEM_WIDE_KRB5_KEYTAB => '/etc/krb5.keytab';

use constant OBJECT_EXISTS => 1;
use constant OBJECT_EXISTS_AND_HIDDEN_SID => 2;


sub _create
{
    my $class = shift;
    my $self = $class->SUPER::_create(name => 'samba',
                                      printableName => __('Domain Controller and File Sharing'),
                                      @_);
    bless($self, $class);

    $self->{ldapClass} = 'EBox::Ldap';
    $self->{ouClass} = 'EBox::Samba::OU';
    $self->{userClass} = 'EBox::Samba::User';
    $self->{contactClass} = 'EBox::Samba::Contact';
    $self->{groupClass} = 'EBox::Samba::Group';
    $self->{containerClass} = 'EBox::Samba::Container';

    return $self;
}

# Method: ldapClass
#
#   Return the LDAP class implementation to use.
#
sub ldapClass
{
    my ($self) = @_;

    (defined $self->{ldapClass}) or
        throw EBox::Exceptions::Internal("ldapClass not initialized.");

    return $self->{ldapClass};
}

# Method: ouClass
#
#   Return the OU class implementation to use.
#
sub ouClass
{
    my ($self) = @_;

    (defined $self->{ouClass}) or
        throw EBox::Exceptions::Internal("ouClass not initialized.");

    return $self->{ouClass};
}

# Method: userClass
#
#   Return the User class implementation to use.
#
sub userClass
{
    my ($self) = @_;

    (defined $self->{userClass}) or
        throw EBox::Exceptions::Internal("userClass not initialized.");

    return $self->{userClass};
}

# Method: contactClass
#
#   Return the Contact class implementation to use.
#
sub contactClass
{
    my ($self) = @_;

    (defined $self->{contactClass}) or
        throw EBox::Exceptions::Internal("contactClass not initialized.");

    return $self->{contactClass};
}

# Method: groupClass
#
#   Return the Group class implementation to use.
#
sub groupClass
{
    my ($self) = @_;

    (defined $self->{groupClass}) or
        throw EBox::Exceptions::Internal("groupClass not initialized.") ;

    return $self->{groupClass};
}

# Method: container
#
#   Return the Container class implementation to use.
#
#  Warning:
#    this can be undefined since standalone server does not use it
sub containerClass
{
    my ($self) = @_;
    return $self->{containerClass};
}

# Method: actions
#
#       Override EBox::ServiceModule::ServiceInterface::actions
#
sub actions
{
    my ($self) = @_;

    my @actions;

    push (@actions, {
        'action' => __('Your LDAP database will be populated with some basic organizational units'),
        'reason' => __('Zentyal needs this organizational units to add users and groups into them.'),
        'module' => 'samba'
    });
    push (@actions, {
        'action' => __('Create Samba home directory for shares and groups'),
        'reason' => __('Zentyal will create the directories for Samba ' .
                       'shares and groups under /home/samba.'),
        'module' => 'samba',
    });

    # FIXME: This probably won't work if PAM is enabled after enabling the module
    if ($self->model('PAM')->enable_pamValue()) {
        push @actions, {
                'action' => __('Configure PAM.'),
                'reason' => __('Zentyal will give LDAP samba system account.'),
                'module' => 'samba'
            };
    }

    return \@actions;
}

# Method: usedFiles
#
#       Override EBox::Module::Service::files
#
sub usedFiles
{
    my ($self) = @_;
    my @files = ();
    push @files, {
            'file'   => SYSTEM_WIDE_KRB5_CONF_FILE,
            'reason' => __('To set up kerberos authentication'),
            'module' => 'samba'
        };

    push @files, (
        {
            'file' => '/etc/nsswitch.conf',
            'reason' => __('To make NSS use LDAP resolution for user and '.
                           'group accounts. Needed for Samba PDC configuration.'),
            'module' => 'samba'
        },
        {
            'file' => '/etc/fstab',
            'reason' => __('To add quota support to /home partition.'),
            'module' => 'samba'
        },
        {
            'file'   => FSTAB_FILE,
            'reason' => __('To enable extended attributes and acls.'),
            'module' => 'samba',
        },
    );

    return \@files;
}

# Method: initialSetup
#
# Overrides:
#
#   EBox::Module::Base::initialSetup
#
sub initialSetup
{
    my ($self, $version) = @_;

    # Create default rules and services
    # only if installing the first time
    unless ($version) {
        my $services = EBox::Global->modInstance('network');

        my $serviceName = 'samba';
        unless($services->serviceExists(name => $serviceName)) {
            $services->addMultipleService(
                'name' => $serviceName,
                'printableName' => 'Samba',
                'description' => __('Domain and File sharing protocols'),
                'internal' => 1,
                'readOnly' => 1,
                'services' => $self->_services(),
            );
        }

        my $firewall = EBox::Global->modInstance('firewall');
        $firewall->setInternalService($serviceName, 'accept');
        $firewall->saveConfigRecursive();

        # unmask systemd service to avoid no such daemon error
        EBox::Sudo::silentRoot('systemctl unmask samba-ad-dc');
    }

    if (defined ($version) and (EBox::Util::Version::compare($version, '6.0.1') < 0)) {
        my $network = $self->global()->modInstance('network');
        my $svcs = $network->model('ServiceTable');
        $svcs->row($svcs->findId(name => 'samba'))->subModel('configuration')->addRow(
            protocol => 'tcp',
            source_range_type => 'any',
            destination_range_type => 'range',
            destination_from_port => 49152,
            destination_to_port => 65535,
            internal => 1,
            readOnly => 1,
        );
        $network->saveConfigRecursive();
    }

    # Execute initial-setup script
    $self->SUPER::initialSetup($version);
}

sub _checkEnableIPs
{
    my ($self) = @_;
    my $network = $self->global()->modInstance('network');
    my @dhcpIfaces = ();
    my $noAddresses = 1;
    foreach my $iface (@{ $network->allIfaces() }) {
        my @addresses = @{ $network->ifaceAddresses($iface) };
        if (@addresses) {
            $noAddresses = 0;
            last;
        }
        if ($network->ifaceMethod($iface) eq 'dhcp') {
            push @dhcpIfaces, $iface;
        }
    }
    if ($noAddresses) {
        my $errMsg;
        if (@dhcpIfaces) {
            $errMsg = __x('Cannot enable Users and Computers module because your system does not have availalbe IPs. Since you have dhcp interfaces ({ifaces}) it is possible that you have not received leases. Saving changes if network module has just been configured or waiting for a lease can solve this situation',
                          ifaces => "@dhcpIfaces"
                         );
        } else {
            $errMsg = __x('Cannot enable Users and Computers module because your system does not have available IPs. {oh}Configuring network interfaces{ch} and saving changes can solve this situation',
                          oh => '<a href="/Network/Ifaces">',
                          ch => '</a>'
                          );
        }

        EBox::Exceptions::External->throw($errMsg);
    }
}

sub setupDNS
{
    my ($self) = @_;

    EBox::info("Setting up DNS");

    # Get the host domain
    my $sysinfo = EBox::Global->modInstance('sysinfo');
    my $ownDomain = $sysinfo->hostDomain();
    my $hostName = $sysinfo->hostName();

    # Create the domain in the DNS module if it does not exists
    my $dnsMod = EBox::Global->modInstance('dns');
    my $domainModel = $dnsMod->model('DomainTable');
    my $row = $domainModel->find(domain => $ownDomain);
    if (defined $row) {
        # Set the domain as managed and readonly
        $row->setReadOnly(1);
        $row->elementByName('managed')->setValue(1);
        $row->store();
    } else {
        $domainModel->addRow(domain => $ownDomain, managed => 1, readOnly => 1);
    }

    EBox::debug("Adding DNS records for kerberos");

    # Add the TXT record with the realm name
    my $txtRR = { name => '_kerberos',
                  data => $ownDomain,
                  readOnly => 1 };
    $dnsMod->addText($ownDomain, $txtRR);

    # Add the SRV records to the domain
    my $service = { service => 'kerberos',
                    protocol => 'tcp',
                    port => KERBEROS_PORT,
                    priority => 100,
                    weight => 100,
                    target_type => 'domainHost',
                    target => $hostName,
                    readOnly => 1 };
    $dnsMod->addService($ownDomain, $service);
    $service->{protocol} = 'udp';
    $dnsMod->addService($ownDomain, $service);

    $service = { service => 'kerberos-master',
                 protocol => 'tcp',
                 port => KERBEROS_PORT,
                 priority => 100,
                 weight => 100,
                 target_type => 'domainHost',
                 target => $hostName,
                 readOnly => 1 };
    $dnsMod->addService($ownDomain, $service);
    $service->{protocol} = 'udp';
    $dnsMod->addService($ownDomain, $service);

    $service = { service => 'kpasswd',
                 protocol => 'tcp',
                 port => KPASSWD_PORT,
                 priority => 100,
                 weight => 100,
                 target_type => 'domainHost',
                 target => $hostName,
                 readOnly => 1 };
    $dnsMod->addService($ownDomain, $service);
    $service->{protocol} = 'udp';
    $dnsMod->addService($ownDomain, $service);
}

# Method: enableActions
#
#   Override EBox::Module::Service::enableActions
#
sub enableActions
{
    my ($self) = @_;

    $self->_setAppArmorProfiles();

    $self->_internalServerEnableActions();
}

sub _internalServerEnableActions
{
    my ($self) = @_;

    $self->_checkEnableIPs();

    # Setup DNS
    $self->setupDNS();

    # Execute enable-module script
    $self->SUPER::enableActions();

    # FIXME: temporary disabled until reload of webadmin properly
    #        implemented with SIGHUP or uwsgi master FIFO
    # mark webAdmin as changed to avoid problems with getpwent calls, it needs
    # to be restarted to be aware of the new nsswitch conf
    #EBox::Global->modInstance('webadmin')->setAsChanged();
}

sub enableService
{
    my ($self, $status) = @_;

    if ($status) {
        my $throwException = 1;
        if ($self->{restoringBackup}) {
            $throwException = 0;
        }

        $self->getProvision->checkEnvironment($throwException);
    }

    $self->SUPER::enableService($status);

    my $dns = EBox::Global->modInstance('dns');
    $dns->setAsChanged();
}

sub _startDaemon
{
    my ($self, $daemon, %params) = @_;

    $self->SUPER::_startDaemon($daemon, %params);

    my $services = $self->_services($daemon->{name});
    foreach my $service (@{$services}) {
        next if $service->{skipWaitService};

        my $port = $service->{destinationPort};
        next unless $port;

        my $proto = $service->{protocol};
        next unless $proto;

        my $desc = $service->{description};
        if ($proto eq 'tcp/udp') {
            $self->_waitService('tcp', $port, $desc);
            $self->_waitService('udp', $port, $desc);
        } elsif (($proto eq 'tcp') or ($proto eq 'udp')) {
            $self->_waitService($proto, $port, $desc);
        }
    }
}

# Method: _waitService
#
#   This function will block until service is listening or timed
#   out (300 * 0.1 = 30 seconds)
#
sub _waitService
{
    my ($self, $proto, $port, $desc) = @_;

    my $maxTries = 300;
    my $sleepSeconds = 0.1;
    my $listening = 0;

    if (length ($desc)) {
        EBox::debug("Wait users task '$desc'");
    } else {
        EBox::debug("Wait unknown users task");
    }
    while (not $listening and $maxTries > 0) {
        my $sock = new IO::Socket::INET(PeerAddr => '127.0.0.1',
                                        PeerPort => $port,
                                        Proto    => $proto);
        if ($sock) {
            $listening = 1;
            last;
        }
        $maxTries--;
        Time::HiRes::sleep($sleepSeconds);
    }

    unless ($listening) {
        EBox::warn("Timeout reached while waiting for users service '$desc' ($proto)");
    }
}

sub _services
{
    my ($self) = @_;

    return [
            { # kerberos
                'protocol' => 'tcp/udp',
                'sourcePort' => 'any',
                'destinationPort' => '88',
                'description' => 'Kerberos authentication',
            },
            { # DCE endpoint resolution
                'protocol' => 'tcp',
                'sourcePort' => 'any',
                'destinationPort' => '135',
                'description' => 'DCE endpoint resolution',
            },
            { # netbios-ns
                'protocol' => 'udp',
                'sourcePort' => 'any',
                'destinationPort' => '137',
                'description' => 'NETBIOS name service',
            },
            { # netbios-dgm
                'protocol' => 'udp',
                'sourcePort' => 'any',
                'destinationPort' => '138',
                'description' => 'NETBIOS datagram service',
            },
            { # netbios-ssn
                'protocol' => 'tcp',
                'sourcePort' => 'any',
                'destinationPort' => '139',
                'description' => 'NETBIOS session service',
            },
            { # samba LDAP
                'protocol' => 'tcp/udp',
                'sourcePort' => 'any',
                'destinationPort' => '389',
                'description' => 'Lightweight Directory Access Protocol',
            },
            { # microsoft-ds
                'protocol' => 'tcp',
                'sourcePort' => 'any',
                'destinationPort' => '445',
                'description' => 'Microsoft directory services',
            },
            { # kerberos change/set password
                'protocol' => 'tcp/udp',
                'sourcePort' => 'any',
                'destinationPort' => '464',
                'description' => 'Kerberos set/change password',
            },
            { # LDAP over TLS/SSL
                'protocol' => 'tcp',
                'sourcePort' => 'any',
                'destinationPort' => '636',
                'description' => 'LDAP over TLS/SSL',
            },
            { # msft-gc
                'protocol' => 'tcp',
                'sourcePort' => 'any',
                'destinationPort' => '3268',
                'description' => 'Microsoft global catalog',
            },
            { # msft-gc-ssl
                'protocol' => 'tcp',
                'sourcePort' => 'any',
                'destinationPort' => '3269',
                'description' => 'Microsoft global catalog over SSL',
            },
            { # rpc
                'protocol' => 'tcp',
                'sourcePort' => 'any',
                'destinationPort' => '49152:65535',
                'description' => 'RPC server dynamic port range',
                'skipWaitService' => 1,
            },
        ];
}

# Method: wizardPages
#
#   Override EBox::Module::Base::wizardPages
#
sub wizardPages
{
    my ($self) = @_;
    return [{ page => '/Samba/Wizard/Users', order => 300 }];
}

# Method: _regenConfig
#
#   Overrides <EBox::Module::Service::_regenConfig>
#
sub _regenConfig
{
    my $self = shift;

    return unless $self->configured();

    # Do provision first before adding schemas, overrides
    # default EBox::Module::LDAP behavior of adding schemas
    # first and then regenConfig
    $self->EBox::Module::Service::_regenConfig(@_);
    if ($self->isProvisioned() and $self->isEnabled()) {
        $self->_performSetup();
    }
}

# Method: _setConf
#
#       Override EBox::Module::Service::_setConf
#
sub _setConf
{
    my ($self) = @_;

    return unless $self->configured() and $self->isEnabled();

    $self->writeSambaConfig();

    my $prov = $self->getProvision();
    if ((not $prov->isProvisioned()) or $self->get('need_reprovision')) {
        if ($self->get('need_reprovision')) {
            $self->_cleanModulesForReprovision();
            # Current provision is not useful, change back status to not provisioned.
            $prov->setProvisioned(0);
            # The LDB connection needs to be reset so we stop using cached values.
            $self->ldap()->clearConn()
        }
        $prov->provision();
        $self->unset('need_reprovision');
    }

    $self->writeSambaConfig();

    $self->_setupNSSPAM();

    # Apply ACLs to shares
    $self->setACLs();
    # Remove shares
    $self->model('SambaDeletedShares')->removeDirs();

    unless ($self->global()->communityEdition()) {
        $self->_installPhotoCronFile();
    }
}

sub _createDirectories
{
    my ($self) = @_;

    return unless $self->isProvisioned();

    my $group = $self->ldap->domainUsersGroup();
    my $gidNumber = $group->gidNumber();
    my $guest = $self->ldap->domainGuestUser();
    my $nobodyUidNumber = $guest->uidNumber();

    my @cmds;
    push (@cmds, 'mkdir -p ' . SAMBA_DIR);
    push (@cmds, "chown root " . SAMBA_DIR);
    push (@cmds, "chgrp '+$gidNumber' " . SAMBA_DIR);
    push (@cmds, "chmod 770 " . SAMBA_DIR);
    push (@cmds, "setfacl -b " . SAMBA_DIR);
    push (@cmds, "setfacl -m u:$nobodyUidNumber:rx " . SAMBA_DIR);

    push (@cmds, 'mkdir -p ' . PROFILES_DIR);
    push (@cmds, "chown root " . PROFILES_DIR);
    push (@cmds, "chgrp '+$gidNumber' " . PROFILES_DIR);
    push (@cmds, "chmod 770 " . PROFILES_DIR);
    push (@cmds, "setfacl -b " . PROFILES_DIR);

    push (@cmds, 'mkdir -p ' . SHARES_DIR);
    push (@cmds, "chown root " . SHARES_DIR);
    push (@cmds, "chgrp '+$gidNumber' " . SHARES_DIR);
    push (@cmds, "chmod 770 " . SHARES_DIR);
    push (@cmds, "setfacl -b " . SHARES_DIR);
    push (@cmds, "setfacl -m u:$nobodyUidNumber:rx " . SHARES_DIR);

    EBox::Sudo::root(@cmds);
}

sub _adcMode
{
    my ($self) = @_;

    my $settings = $self->global()->modInstance('samba')->model('DomainSettings');
    return ($settings->modeValue() eq $settings->MODE_ADC());
}

sub _postServiceHook
{
    my ($self, $enabled) = @_;

    return unless $enabled;

    return unless $self->isProvisioned();

    $self->_createDirectories();

    my $ldap = $self->ldap();
    # Execute the hook actions *only* if Samba module is enabled and we were invoked from the web application, this will
    # prevent that we execute this code with every service restart or on server boot delaying such processes.
    if ($enabled and ($0 =~ /\/global-action$/)) {
        my $host = $ldap->rootDse()->get_value('dnsHostName');
        unless (defined $host and length $host) {
            throw EBox::Exceptions::Internal('Could not get DNS hostname');
        }

        # Write DNS update list
        EBox::info("Writing DNS update list...");
        $self->_writeDnsUpdateList();
    } else {
        EBox::debug("Ignoring Samba's _postServiceHook code because it was not invoked from the web application.");
    }

    return $self->SUPER::_postServiceHook($enabled);
}

sub _installPhotoCronFile
{
    my ($self) = @_;

    my $share = EBox::Config::configkey('photo_share_name');

    return unless ($share and EBox::Sudo::fileTest('-d', "/home/samba/shares/$share"));

    my $minutes = EBox::Config::configkey('photo_cron_interval');

    # We cannot call writeConfFile since we are not
    # EBox::Module::Service, we are not updating the digests
    # but ebox-software script is not from other package
    EBox::Module::Base::writeConfFileNoCheck(
        PROFILE_PHOTO_CRON_FILE,
        'samba/photo.cron',
        [
            share => $share,
            minutes => $minutes
        ]
    );
}

sub kerberosRealm
{
    my ($self) = @_;

    my $sysinfo = EBox::Global->modInstance('sysinfo');
    my $realm = uc ($sysinfo->hostDomain());
    return $realm;
}

# Set up NSS PAM for LDB users
sub _setupNSSPAM
{
    my ($self) = @_;

    my @array = ();
    my $umask = EBox::Config::configkey('dir_umask');
    push (@array, 'umask' => $umask);

    $self->writeConfFile(AUTHCONFIGTMPL, 'samba/acc-zentyal.mas',
                         \@array);

    my $PAMModule = $self->model('PAM');
    my $enablePAM = $PAMModule->enable_pamValue();

    my $cmd;
    if ($enablePAM) {
        $cmd = 'auth-client-config -a -p zentyal-krb';
    } else {
        $cmd = 'auth-client-config -a -p zentyal-nokrb';
    }
    EBox::Sudo::root($cmd);
}

# Method: editableMode
#
#       Check if users and groups can be edited.
#
#       They could not be edited ither mode is external-ad or the syncprovider
#       does not allows it
#
sub editableMode
{
    my ($self) = @_;

    return 1;
}

# Method: _daemons
#
#       Override EBox::Module::Service::_daemons
#
sub _daemons
{
    my ($self) = @_;

    return [
        {
            name => 'samba-ad-dc',
        },
        {
            name => 'zentyal.samba-sync',
            precondition => \&_syncEnabled,
        },
    ];
}

sub _syncEnabled
{
    my ($self) = @_;

    return 0 if (EBox::Config::boolean('disable_uid_sync') and
                 EBox::Config::boolean('unmanaged_acls'));

    return ($self->isEnabled() and $self->isProvisioned());
}

# Method: _daemonsToDisable
#
# Overrides:
#
#   <EBox::Module::Service::_daemonsToDisable>
#
sub _daemonsToDisable
{
    return [
        { 'name' => 'smbd', 'type' => 'systemd' },
        { 'name' => 'nmbd', 'type' => 'systemd' },
        { 'name' => 'winbind', 'type' => 'systemd' },
    ];
}

# Function: usesPort
#
#   Implements EBox::FirewallObserver interface
#
sub usesPort
{
    my ($self, $protocol, $port, $iface) = @_;

    return undef unless($self->isEnabled());

    foreach my $smbport (@{$self->_services()}) {
        return 1 if ($port eq $smbport->{destinationPort});
    }

    return undef;
}


# Method: _startService
#
#   Overrided to ensure proper permissions of the ldap_priv folder, where the
#   privileged socket that zentyal uses to connect is. This is a special socket
#   that samba create that allow r/w restricted attributes.
#   Samba expects the ldap_priv folder to be owned by root and mode 0750, or the
#   LDAP service won't run.
#
#   Here we set the expected permissions before start the daemon.
#
sub _startService
{
    my ($self) = @_;

    my $group = EBox::Config::group();
    EBox::Sudo::root("mkdir -p " . SAMBA_PRIVILEGED_SOCKET);
    EBox::Sudo::root("chgrp $group " . SAMBA_PRIVILEGED_SOCKET);
    EBox::Sudo::root("chmod 0750 " . SAMBA_PRIVILEGED_SOCKET);
    EBox::Sudo::root("setfacl -b " . SAMBA_PRIVILEGED_SOCKET);

    $self->SUPER::_startService();

    # Wait for samba to open the ldapi socket
    # TODO: wait also for winbind pipe?
    my $tries = 300;
    my $sleep = 0.1;
    my $socket = undef;
    while (not defined $socket and $tries > 0) {
        $socket = new IO::Socket::UNIX(
            Type => SOCK_STREAM,
            Peer => '/var/lib/samba/private/ldap_priv/ldapi');
        last if $socket;
        $tries--;
        Time::HiRes::sleep($sleep);
    }
}

# Method: groupDn
#
#    Returns the dn for a given group. The group doesn't have to exist
#
#   Parameters:
#       group
#
#  Returns:
#     dn for the group
#
# FIXME: This should not be used anymore...
sub groupDn
{
    my ($self, $group) = @_;
    $group or throw EBox::Exceptions::MissingArgument('group');

    my $dn = "cn=$group," . EBox::Samba::Group->defaultContainer()->dn();
    return $dn;
}

# Init a new user (home and permissions)
sub initUser
{
    my ($self, $user) = @_;

    my $mk_home = EBox::Config::configkey('mk_home');
    $mk_home = 'yes' unless $mk_home;
    if ($mk_home eq 'yes') {
        my $home = $user->home();
        if ($home and ($home ne '/dev/null') and (not -e $home)) {
            my $qhome = shell_quote($home);
            my $gidNumber = $user->gidNumber();
            my $uidNumber = $user->uidNumber();

            my @cmds;
            push (@cmds, "mkdir -p `dirname $qhome`");
            push (@cmds, "cp -dR --preserve=mode /etc/skel $qhome");
            push (@cmds, "chown -R +$uidNumber:+$gidNumber $qhome");

            my $dir_umask = oct(EBox::Config::configkey('dir_umask'));
            my $perms = sprintf("%#o", 00777 &~ $dir_umask);
            push (@cmds, "chmod $perms $qhome");
            EBox::Sudo::root(@cmds);
        }
    }

    my $roamingEnabled = $self->global(1)->modInstance('samba')->roamingProfiles();
    if ($roamingEnabled) {
        $user->setRoamingProfile(1, $self->_roamingProfilesPath());
    }
}

# Reload nscd daemon if it's installed
sub reloadNSCD
{
    if (-f '/etc/init.d/nscd') {
        try {
            EBox::Sudo::root('service nscd force-reload');
        } catch {
        }
   }
}

# Method: containers
#
#   Returns an array containing all the containers. The array is ordered in a
#   hierarquical way. Parents before childs.
#
# Returns:
#
#   array ref - holding the containers. Each member is represented by a
#   EBox::Samba::Container object
#
sub containers
{
    my ($self, $baseDN) = @_;

    my $list = [];

    return $list if (not $self->isEnabled());

    unless (defined $baseDN) {
        $baseDN = $self->ldap->dn();
    }

    my $searchArgs = {
        base => $baseDN,
        filter => "(objectclass=container)",
        scope => 'one',
        attrs => ['*'],
    };

    my @entries = @{$self->ldap->pagedSearch($searchArgs)};
    foreach my $entry (@entries) {
        my $container = new EBox::Samba::Container(entry => $entry);
        push (@{$list}, $container);
        my $nested = $self->containers($container->dn());
        push (@{$list}, @{$nested});
    }

    return $list;
}

# Method: ous
#
#   Returns an array containing all the OUs. The array ir ordered in a
#   hierarquical way. Parents before childs.
#
# Returns:
#
#   array ref - holding the OUs. Each user is represented by a
#   EBox::Samba::OU object
#
sub ous
{
    my ($self, $baseDN) = @_;

    my $list = [];

    return $list if (not $self->isEnabled());

    unless (defined $baseDN) {
        $baseDN = $self->ldap->dn();
    }

    my $args = {
        base => $baseDN,
        filter => "(objectclass=organizationalUnit)",
        scope => 'one',
    };

    my @entries = @{$self->ldap->pagedSearch($args)};
    foreach my $entry (@entries) {
        my $ou = new EBox::Samba::OU(entry => $entry);
        push (@{$list}, $ou);
        my $nested = $self->ous($ou->dn());
        push (@{$list}, @{$nested});
    }

    return $list;
}

# Method: users
#
#   Returns an array containing all the users (not system users)
#
# Parameters:
#
#   system - show system users also (default: false)
#
# Returns:
#
#   array ref - holding the users. Each user is represented by a
#               EBox::Samba::User object
#
sub users
{
    my ($self, $system) = @_;

    my @list;

    return [] if (not $self->isEnabled());

    # Query the containers stored in the root DN and skip the ignored ones
    # Note that 'OrganizationalUnit' and 'msExchSystemObjectsContainer' are
    # subclasses of 'Container'.
    my @containers;
    my $params = {
        base => $self->ldap->dn(),
        scope => 'one',
        filter => '(|(objectClass=container)(objectClass=organizationalUnit)(objectClass=msExchSystemObjectsContainer))',
        attrs => ['*'],    };
    my @entries = @{$self->ldap->pagedSearch($params)};
    @entries = sort {
            my $aValue = $a->get_value('name');
            my $bValue = $b->get_value('name');
            (lc $aValue cmp lc $bValue) or ($aValue cmp $bValue)
    } @entries;
    foreach my $entry (@entries) {
        my $container = new EBox::Samba::Container(entry => $entry);
        next if $container->get('cn') eq any EBox::Ldap::QUERY_IGNORE_CONTAINERS();
        push (@containers, $container);
    }

    # Query the users stored in the non ignored containers
    my $filter = "(&(&(objectclass=user)(!(objectclass=computer)))(!(isDeleted=*)))";
    foreach my $container (@containers) {
        $params = {
            base   => $container->dn(),
            scope  => 'sub',
            filter => $filter,
            attrs  => ['*', 'unicodePwd', 'supplementalCredentials'],
        };
        @entries = @{$self->ldap->pagedSearch($params)};

        foreach my $entry (@entries) {
            my $user = new EBox::Samba::User(entry => $entry);
            next if (not $system and $user->isSystem());
            push @list, $user;
        }
    }

    @list = sort {
        my $aValue = $a->get('samAccountName');
        my $bValue = $b->get('samAccountName');
        (lc $aValue cmp lc $bValue) or ($aValue cmp $bValue)
    } @list;

    return \@list;
}

# Method: usersToTable
#
#   Returns an array containing all the users (not system users)
#
# Parameters:
#
#   filter - filter to apply to users (default: ')
#
# Returns:
#
#   array ref - holds the users. Each user is represented by an
#               EBox::Samba::User object
#
sub usersToTable
{
    my ($self, $filterParam, $dn) = @_;
    my @list;

    return [] if (not $self->isEnabled());

    # Quering the containers stored in the root DN and skipping the ignored ones
    # Note that 'OrganizationalUnit' and 'msExchSystemObjectsContainer' are
    # subclasses of 'Container'.
    my @containers;
    my $base = $self->ldap->dn();
    if (defined $dn){
        $base = $dn;
    }

    # Quering the users stored in the non ignored containers
    my $filterCN='';
    if($filterParam and !($filterParam eq '')){
        $filterCN = sprintf ("(|(samAccountName=*%s*)(givenName=*%s*)(sn=*%s*)(mail=*%s*))",$filterParam,$filterParam,$filterParam,$filterParam);
    }
    my $filter = sprintf ("(&(&(objectclass=user)%s(!(objectclass=computer)))(!(isDeleted=*)))",$filterCN);
    my $params = {
            # base   => $container->dn(),
            base   => $base,
            scope  => 'sub',
            filter => $filter,
            attrs  => ['*', 'unicodePwd', 'supplementalCredentials'],
        };
    my @entries = @{$self->ldap->pagedSearch($params)};
    foreach my $entry (@entries) {
        my $user = new EBox::Samba::User(entry => $entry);
        next if ($user->isSystem());
        push (@list, $user);
    }

    @list = sort {
        my $aValue = $a->get('samAccountName');
        my $bValue = $b->get('samAccountName');
        (lc $aValue cmp lc $bValue) or ($aValue cmp $bValue)
    } @list;

    return @list;
}

# Method: realUsers
#
#       Returns an array containing all the non-internal users
#
# Returns:
#
#       array ref - holding the users. Each user is represented by a
#       EBox::Samba::User object
#
sub realUsers
{
    my ($self, $includeAdmin) = @_;

    my @users;
    if ($includeAdmin) {
        @users = grep { not ($_->isInternal() or $_->isGuest()) } @{$self->users()};
    } else {
        @users = grep { not ($_->isInternal() or $_->isGuest() or $_->isAdministrator()) } @{$self->users()};
    }

    return \@users;
}

# Method: realGroups
#
#       Returns an array containing all the non-internal groups
#
# Returns:
#
#       array ref - holding the groups. Each user is represented by a
#       EBox::Samba::Group object
#
sub realGroups
{
    my ($self) = @_;

    my @groups = grep { not $_->isInternal() } @{$self->securityGroups()};

    return \@groups;
}

# Method: contactsByName
#
# Return a reference to a list of instances of EBox::Samba::Contact objects which represents a given name.
#
#  Parameters:
#      name
#
sub contactsByName
{
    my ($self, $name) = @_;

    my $list = [];

    return $list if (not $self->isEnabled());

    my $params = {
        base => $self->ldap->dn(),
        scope => 'sub',
        filter => "(&(objectclass=contact)(!(isDeleted=*))(cn=$name))",
        attrs => ['*'],
    };
    my @entries = @{$self->ldap->pagedSearch($params)};
    @entries = sort {
            my $aValue = $a->get_value('cn');
            my $bValue = $b->get_value('cn');
            (lc $aValue cmp lc $bValue) or ($aValue cmp $bValue)
    } @entries;
    foreach my $entry (@entries) {
        my $contact = new EBox::Samba::Contact(entry => $entry);
        push (@{$list}, $contact);
    }
    return $list;
}

# Method: contactExists
#
#  Returns:
#
#      bool - whether the contact exists or not
#
sub contactExists
{
    my ($self, $name) = @_;
    return undef unless ($self->contactsByName($name));
    return 1;
}

# Method: contacts
#
#       Returns an array containing all the contacts
#
# Returns:
#
#       array ref - holding the contacts. Each contact is represented by a
#       EBox::Samba::Contact object
#
sub contacts
{
    my ($self) = @_;

    return [] if (not $self->isEnabled());

    my %args = (
        base => $self->ldap->dn(),
        filter => '(&(objectclass=inetOrgPerson)(!(objectclass=posixAccount)))',
        scope => 'sub',
    );

    my $result = $self->ldap->search(\%args);

    my @contacts = ();
    foreach my $entry ($result->entries) {
        my $contact = new EBox::Samba::Contact(entry => $entry);

        push (@contacts, $contact);
    }

    # sort by name
    @contacts = sort {
        my $aValue = $a->fullname();
        my $bValue = $b->fullname();
        (lc $aValue cmp lc $bValue) or ($aValue cmp $bValue)
    } @contacts;

    return \@contacts;
}

# Method: groupByName
#
# Return the instance of EBox::Samba::Group object which represents a give group name or undef if it's not found.
#
#  Parameters:
#      name
#
sub groupByName
{
    my ($self, $name) = @_;

    return undef unless ($self->isEnabled());

    my $args = {
        base => $self->ldap->dn(),
        filter => "(&(objectclass=group)(!(isDeleted=*))(cn=$name))",
        scope => 'sub',
        attrs => ['*'],
    };

    my $result = $self->ldap->search($args);
    my $count = $result->count();
    if ($count > 1) {
        throw EBox::Exceptions::Internal(
            __x('Found {count} results for \'{name}\' group, expected only one.',
                count => $count,
                name  => $name
            )
        );
    } elsif ($count == 0) {
        return undef;
    } else {
        return new EBox::Samba::Group(entry => $result->entry(0));
    }
}

# Method: groups
#
#       Returns an array containing all the groups
#
#   Parameters:
#       system - show system groups (default: false)
#
# Returns:
#
#       array - holding the groups as EBox::Samba::Group objects
#
sub groups
{
    my ($self, $system) = @_;

    return [] if (not $self->isEnabled());

    my @list;
    my $params = {
        base => $self->ldap->dn(),
        scope => 'sub',
        filter => '(&(objectclass=group)(!(isDeleted=*)))',
        attrs => ['*'],
    };
    my @entries = @{$self->ldap->pagedSearch($params)};
    foreach my $entry (@entries) {
        my $group = new EBox::Samba::Group(entry => $entry);
        next if (not $system and $group->isSystem());
        push @list, $group;
    }
    @list = sort {
            my $aValue = $a->get('samAccountName');
            my $bValue = $b->get('samAccountName');
            (lc $aValue cmp lc $bValue) or ($aValue cmp $bValue)
        } @list;

    return \@list;
}

# Method: securityGroups
#
#   Returns an array containing all the security groups
#
# Parameters:
#
#   system - show system groups (default: false)
#
# Returns:
#
#   array - holding the groups as EBox::Samba::Group objects
#
sub securityGroups
{
    my ($self, $system) = @_;

    my $list = [];

    return $list if (not $self->isEnabled());

    my $groups = $self->groups($system);
    foreach my $group (@{$groups}) {
        next unless $group->isSecurityGroup();
        next if (not $system and $group->isSystem());
        push (@{$list}, $group);
    }

    return $list;
}

# Method: _modsLdapUserbase
#
# Returns modules implementing LDAP user base interface
#
# Parameters:
#   ignored_modules (Optional) - array ref to a list of module names to ignore
#
sub _modsLdapUserBase
{
    my ($self, $ignored_modules) = @_;

    my $global = EBox::Global->modInstance('global');
    my @names = @{$global->modNames};

    $ignored_modules or $ignored_modules = [];

    my @modules;
    foreach my $name (@names) {
        next if ($name eq any @{$ignored_modules});

        my $mod = EBox::Global->modInstance($name);

        if ($mod->isa('EBox::Module::LDAP')) {
            if ($name ne $self->name()) {
                $mod->configured() or
                    next;
            }
            push (@modules, $mod->_ldapModImplementation);
        }
    }

    return \@modules;
}

# Method: notifyModsPreLdapUserBase
#
#   Notify all modules implementing LDAP user base interface about
#   a change in users or groups before it happen.
#
# Parameters:
#
#   signal - Signal name to notify the modules (addUser, delUser, modifyGroup, ...)
#   args - single value or array ref containing signal parameters
#   ignored_modules - array ref of modnames to ignore (won't be notified)
#
sub notifyModsPreLdapUserBase
{
    my ($self, $signal, $args, $ignored_modules) = @_;

    # convert signal to method name
    my $method = '_' . $signal;

    # convert args to array if it is a single value
    unless (ref ($args) eq 'ARRAY') {
        $args = [ $args ];
    }

    foreach my $mod (@{$self->_modsLdapUserBase($ignored_modules)}) {
        $mod->$method(@{$args});
    }
}

# Method: notifyModsLdapUserBase
#
#   Notify all modules implementing LDAP user base interface about
#   a change in users or groups
#
# Parameters:
#
#   signal - Signal name to notify the modules (addUser, delUser, modifyGroup, ...)
#   args - single value or array ref containing signal parameters
#   ignored_modules - array ref of modnames to ignore (won't be notified)
#
sub notifyModsLdapUserBase
{
    my ($self, $signal, $args, $ignored_modules) = @_;

    # convert signal to method name
    my $method = '_' . $signal;

    # convert args to array if it is a single value
    unless (ref($args) eq 'ARRAY') {
        $args = [ $args ];
    }

    my $object = $args->[0];
    foreach my $mod (@{$self->_modsLdapUserBase($ignored_modules)}) {
        my $defaultOU = $mod->objectInDefaultContainer($object);

        # Skip modules not supporting multiple OU if not default OU
        next unless ($mod->multipleOUSupport or $defaultOU);

        # TODO catch errors here? Not a good idea. The way to go is
        # to implement full transaction support and rollback if a notified
        # module throws an exception
        $mod->$method(@{$args});
    }
}

# Method: defaultUserModels
#
#   Returns all the defaultUserModels from modules implementing
#   <EBox::LdapUserBase>
sub defaultUserModels
{
    my ($self) = @_;
    my @models;
    for my $module  (@{$self->_modsLdapUserBase()}) {
        my $model = $module->defaultUserModel();
        push (@models, $model) if (defined($model));
    }
    return \@models;
}

# Method: allUserAddOns
#
#       Returns all the mason components from those modules implementing
#       the function _userAddOns from EBox::LdapUserBase
#
# Parameters:
#
#       user - user object
#
# Returns:
#
#       array ref - holding all the components and parameters
#
sub allUserAddOns
{
    my ($self, $user) = @_;

    my $defaultOU = ($user->baseDn() eq $user->defaultContainer()->dn());

    my @modsFunc = @{$self->_modsLdapUserBase()};
    my @components;
    foreach my $mod (@modsFunc) {
        my $comp;
        if ($defaultOU or $mod->multipleOUSupport) {
            $comp = $mod->_userAddOns($user);
        } else {
            $comp  = $mod->noMultipleOUSupportComponent($user);
        }

        if ($comp) {
            $comp->{id} = ref $mod;
            $comp->{id} =~ s/:/_/g;
            push (@components, $comp);
        }
    }

    return \@components;
}

# Method: allGroupAddOns
#
#       Returns all the mason components from those modules implementing
#       the function _groupAddOns from EBox::LdapUserBase
#
# Parameters:
#
#       group  - group name
#
# Returns:
#
#       array ref - holding all the components and parameters
#
sub allGroupAddOns
{
    my ($self, $group) = @_;

    my $global = EBox::Global->modInstance('global');
    my @names = @{$global->modNames};

    my @modsFunc = @{$self->_modsLdapUserBase()};
    my @components;
    foreach my $mod (@modsFunc) {
        my $comp = $mod->_groupAddOns($group);
        if ($comp) {
            $comp->{id} = ref $mod;
            $comp->{id} =~ s/:/_/g;
            push (@components, $comp) if ($comp);
        }
    }

    return \@components;
}

# Method: allWarnings
#
#       Returns all the the warnings provided by the modules when a certain
#       user, group is going to be deleted. Function _delUserWarning or
#       _delGroupWarning is called in all module implementing them.
#
# Parameters:
#
#       object - Sort of object: 'user' or 'group'
#       name - name of the user or group
#
# Returns:
#
#       array ref - holding all the warnings
#
sub allWarnings
{
    my ($self, $object, $name) = @_;

    # TODO: Extend it for ous and contacts.
    return [] unless (($object eq 'user') or ($object eq 'group'));

    my @modsFunc = @{$self->_modsLdapUserBase()};
    my @allWarns;
    foreach my $mod (@modsFunc) {
        my $warn = undef;
        if ($object eq 'user') {
            $warn = $mod->_delUserWarning($name);
        } else {
            $warn = $mod->_delGroupWarning($name);
        }
        push (@allWarns, $warn) if ($warn);
    }

    return \@allWarns;
}

# Method: _supportActions
#
#       Overrides EBox::ServiceModule::ServiceInterface method.
#
sub _supportActions
{
    return undef;
}

# Method: menu
#
#       Overrides EBox::Module method.
#
sub menu
{
    my ($self, $root) = @_;

    $root->add(new EBox::Menu::Item(
        name => 'Domain',
        url => 'Samba/Composite/Domain',
        text => __('Domain'),
        icon => 'domain',
        tag => 'main',
        order => 2)
    );

    my $folder = new EBox::Menu::Folder(
        name    => 'Users',
        icon    => 'samba',
        text    => __('Users and Computers'),
        tag     => 'main',
        order   => 1
    );

    $folder->add(new EBox::Menu::Item(
        'url'   => 'Samba/Tree/Manage',
        'text'  => __('Manage'), 
        order   => 10
    ));

    $folder->add(new EBox::Menu::Item(
        'url'   => 'Samba/Composite/UserTemplate',
        'text'  => __('User Template'), 
        order   => 30
    ));

    $folder->add(new EBox::Menu::Item(
        'url'   => 'Samba/Composite/Settings',
        'text'  => __('LDAP Settings'), 
        order   => 50
    ));

    $folder->add(new EBox::Menu::Item(
        'url'   => 'Samba/Composite/ImportExport',
        'text'  => __('Import/Export'),
        'order' => 40
    ));

    $root->add($folder);

    $root->add(new EBox::Menu::Item(
        text      => __('File Sharing'),
        url       => 'Samba/Composite/FileSharing',
        icon      => 'sharing',
        tag       => 'main',
        order     => 3
    ));
}

# LdapModule implementation
sub _ldapModImplementation
{
    return new EBox::LdapUserImplementation();
}

sub dumpConfig
{
    my ($self, $dir, %options) = @_;

    return unless $self->isProvisioned();

    my @cmds;

    my $hostname  =  `hostname --fqdn`;
    chomp $hostname;
    File::Slurp::write_file("$dir/oldhostname", $hostname);

    my $mirror = EBox::Config::tmp() . "/samba.backup";
    my $privateDir = PRIVATE_DIR;
    if (EBox::Sudo::fileTest('-d', $privateDir)) {
        # Export the list of users to a file. On restore this list will be
        # loaded to check no users exists in /etc/passwd with same name as
        # any user backed up
        my $users = $self->users();
        my @users = map { $_->get('samAccountName') } @{$users};
        File::Slurp::write_file($dir . '/' . BACKUP_USERS_FILE, join("\n", @users));

        # Remove previous backup files
        my $ldbBakFiles = EBox::Sudo::root("find $privateDir -name '*.ldb.bak'");
        my $tdbBakFiles = EBox::Sudo::root("find $privateDir -name '*.tdb.bak'");
        foreach my $bakFile ((@{$ldbBakFiles}, @{$tdbBakFiles})) {
            chomp ($bakFile);
            push (@cmds, "rm '$bakFile'");
        }

        # Backup private. TDB and LDB files must be backed up using tdbbackup
        my $ldbFiles = EBox::Sudo::root("find $privateDir -name '*.ldb'");
        my $tdbFiles = EBox::Sudo::root("find $privateDir -name '*.tdb' | grep -v netlogon_creds_cli");
        foreach my $dbFile ((@{$ldbFiles}, @{$tdbFiles})) {
            chomp ($dbFile);
            push (@cmds, "tdbbackup '$dbFile'");
            # Preserve file permissions
            my $st = EBox::Sudo::stat($dbFile);
            my $uid = $st->uid();
            my $gid = $st->gid();
            my $mode = sprintf ("%04o", $st->mode() & 07777);
            push (@cmds, "chown $uid:$gid $dbFile.bak");
            push (@cmds, "chmod $mode $dbFile.bak");
        }

        push (@cmds, "rm -rf $mirror");
        push (@cmds, "mkdir -p $mirror/private");
        push (@cmds, "rsync -HAXavz $privateDir/ " .
                     "--exclude=*.tdb --exclude=*.ldb " .
                     "--exclude=ldap_priv --exclude=smbd.tmp " .
                     "--exclude=ldapi $mirror/private");
        push (@cmds, "tar pcjf $dir/private.tar.bz2 --hard-dereference -C $mirror private");
    }

    my $bindDir = SAMBA_DNS_DIR;
    if (EBox::Sudo::fileTest('-d', $bindDir)) {
        # Storing all BIND DNS directory tree where DLZ and dns keytab are stored
        push (@cmds, "rm -rf $mirror");
        push (@cmds, "mkdir -p $mirror/bind-dns");
        push (@cmds, "rsync -HAXavz $bindDir/ $mirror/bind-dns");
        push (@cmds, "tar pcjf $dir/bind-dns.tar.bz2 --hard-dereference -C $mirror bind-dns");
    }    

    # Backup sysvol
    my $sysvolDir = SYSVOL_DIR;
    if (EBox::Sudo::fileTest('-d', $sysvolDir)) {
        push (@cmds, "rm -rf $mirror");
        push (@cmds, "mkdir -p $mirror/sysvol");
        push (@cmds, "rsync -HAXavz $sysvolDir/ $mirror/sysvol");
        push (@cmds, "tar pcjf $dir/sysvol.tar.bz2 --hard-dereference -C $mirror sysvol");
    }

    try {
        EBox::Sudo::root(@cmds);
    } catch ($e) {
        $e->throw();
    }

    # Backup admin password
    unless ($options{bug}) {
        my $pwdFile = EBox::Config::conf() . 'samba.passwd';
        # Additional domain controllers does not have stashed pwd
        if (EBox::Sudo::fileTest('-f', $pwdFile)) {
            EBox::Sudo::root("cp '$pwdFile' $dir");
        }
    }
}

sub _usersInEtcPasswd
{
    my ($self) = @_;
    my @users;

    my @lines = File::Slurp::read_file('/etc/passwd');
    foreach my $line (@lines) {
        my ($user) = split ':', $line, 2;
        push @users, $user;
    }

    return \@users;
}

sub restoreDependencies
{
    my ($self) = @_;

    return ['dns'];
}

# Method: restoreBackupPreCheck
#
# Check that the backup to be restored mode is compatible.
# Also, in case we are using standalone mode, checks if we have clonflicts between
# users in the LDAP data to be loaded and the users in /etc/passwd
sub restoreBackupPreCheck
{
    my ($self, $dir) = @_;

    my $oldHostname;
    my $hostnameFile = "$dir/oldhostname";
    if (-r $hostnameFile) {
        $oldHostname = File::Slurp::read_file($hostnameFile);
    }
    if ($oldHostname) {
        my $hostname  =  `hostname --fqdn`;
        chomp $hostname;
        if ($hostname ne $oldHostname) {
            throw EBox::Exceptions::External(
                __x('To be able to restore this backup the hostname should be first set to {hn}. Otherwise samba data could not be restored.',
                    hn => $oldHostname)
               );
        }
    } else {
        EBox::warn("No hostname stored in backup. Samba restore will fail if you dont have the same hostname that the original server");
    }

    my $userListFile = $dir . '/' . BACKUP_USERS_FILE;
    if (EBox::Sudo::fileTest('-f', $userListFile)) {
        my %etcPasswdUsers = map { $_ => 1 } @{ $self->_usersInEtcPasswd() };
        my @usersToRestore = File::Slurp::read_file($userListFile);
        foreach my $user (@usersToRestore) {
            chomp $user;
            if (exists $etcPasswdUsers{$user}) {
                throw EBox::Exceptions::External(
                    __x('Cannot restore because LDAP user {user} already ' .
                        'exists as /etc/passwd user. Delete or rename this ' .
                        'user and try again', user => $user));
            }
        }
    }
}

sub restoreConfig
{
    my ($self, $dir) = @_;
    my $provisioned = $self->isProvisioned();
    if (not $provisioned) {
        try {
            $self->getProvision()->checkEnvironment(1);
        } catch ($ex) {
            my $exError = "$ex";
            my $error = __x("We cannot recreate the samba provision with the data from the backup because we get this error:\n{ex}",
                           ex => $exError);
            throw EBox::Exceptions::External($error);
        }
    }

    my $modeDC = $self->dcMode();
    unless ($modeDC eq EBox::Samba::Model::DomainSettings::MODE_DC()) {
        # Restoring an ADC will corrupt entire domain as sync data
        # get out of sync.
        EBox::info(__("Restore is only possible if the server is the unique " .
                      "domain controller of the forest"));
        $self->getProvision->setProvisioned(0);
        return;
    }

    if ($provisioned) {
        $self->stopService();
    }

    # Remove bind-dns, private and sysvol
    my $privateDir = PRIVATE_DIR;
    my $bindDir = SAMBA_DNS_DIR;
    my $sysvolDir = SYSVOL_DIR;
    EBox::Sudo::root("rm -rf $privateDir $sysvolDir $bindDir");

    # Unpack bind-dns, sysvol and private
    my %dest = ('bind-dns' => $bindDir, 'sysvol' => $sysvolDir, 'private' => $privateDir );
    foreach my $archive (keys %dest) {
        if (EBox::Sudo::fileTest('-f', "$dir/$archive.tar.bz2")) {
            my $destdir = dirname($dest{$archive});
            EBox::Sudo::root("tar jxfp $dir/$archive.tar.bz2 -C $destdir");
        }
    }

    # Rename ldb files
    my $ldbBakFiles = EBox::Sudo::root("find $privateDir -name '*.ldb.bak'");
    my $tdbBakFiles = EBox::Sudo::root("find $privateDir -name '*.tdb.bak'");
    foreach my $bakFile ((@{$ldbBakFiles}, @{$tdbBakFiles})) {
        chomp $bakFile;
        my $destFile = $bakFile;
        $destFile =~ s/\.bak$//;
        EBox::Sudo::root("mv '$bakFile' '$destFile'");
    }
    
    # Hard-link DomainDnsZones and ForestDnsZones partitions
    EBox::Sudo::root("rm -f $bindDir/dns/sam.ldb.d/DC*FORESTDNSZONES*");
    EBox::Sudo::root("rm -f $bindDir/dns/sam.ldb.d/DC*DOMAINDNSZONES*");
    EBox::Sudo::root("rm -f $bindDir/dns/sam.ldb.d/metadata.tdb");
    EBox::Sudo::root("ln $privateDir/sam.ldb.d/DC*FORESTDNSZONES* $bindDir/dns/sam.ldb.d/");
    EBox::Sudo::root("ln $privateDir/sam.ldb.d/DC*DOMAINDNSZONES* $bindDir/dns/sam.ldb.d/");
    EBox::Sudo::root("ln $privateDir/sam.ldb.d/metadata.tdb $bindDir/dns/sam.ldb.d/");
    EBox::Sudo::root("chown root:bind $bindDir/dns/*.ldb");
    EBox::Sudo::root("chmod 770 $bindDir/dns/*.ldb");

    # Restore stashed password
    if (EBox::Sudo::fileTest('-f', "$dir/samba.passwd")) {
        EBox::Sudo::root("cp $dir/samba.passwd " . EBox::Config::conf());
        EBox::Sudo::root("chmod 0600 $dir/samba.passwd");
    }

    # Set provisioned flag
    $self->getProvision->setProvisioned(1);

    if ($provisioned) {
        $self->_startService();
        $self->getProvision()->resetSysvolACL();
    }
}

sub _provisionFromBackup
{
    my ($self, $dir) = @_;
    EBox::info("Provision samba before restoring backup");
    my $provision = $self->getProvision();
    $provision->checkEnvironment(1);
    $provision->setProvisioned(1);
}

sub _removePasswds
{
  my ($self, $file) = @_;

  my $anyPasswdAttr = any(qw(
              userPassword
              sambaLMPassword
              sambaNTPassword
              )
          );
  my $passwordSubstitution = "password";

  my $FH_IN;
  open $FH_IN, "<$file" or
      throw EBox::Exceptions::Internal ("Cannot open $file: $!");

  my ($FH_OUT, $tmpFile) = tempfile(DIR => EBox::Config::tmp());

  foreach my $line (<$FH_IN>) {
      my ($attr, $value) = split ':', $line;
      if ($attr eq $anyPasswdAttr) {
          $line = $attr . ': ' . $passwordSubstitution . "\n";
      }

      print $FH_OUT $line;
  }

  close $FH_IN  or
      throw EBox::Exceptions::Internal ("Cannot close $file: $!");
  close $FH_OUT or
      throw EBox::Exceptions::Internal ("Cannot close $tmpFile: $!");

  File::Copy::move($tmpFile, $file);
  unlink $tmpFile;
}

sub listSchemas
{
    my ($self, $ldap) = @_;

    my %args = (
        'base' => 'cn=schema,cn=config',
        'scope' => 'one',
        'filter' => "(objectClass=olcSchemaConfig)"
    );
    my $result = $ldap->search(%args);

    my @schemas = map { $_->get_value('cn') } $result->entries();
    return \@schemas;
}

# Method: dcMode
#
#   Returns the configured server mode
#
sub dcMode
{
    my ($self) = @_;

    my $model = $self->model('DomainSettings');
    return $model->modeValue();
}


# Method: newLDAP
#
#  Return a new LDAP object instance of the class requiered by the active mode
#
sub newLDAP
{
    my ($self) = @_;

    return  EBox::Ldap->instance();
}

# common check for user names and group names
sub checkNameLimitations
{
    my ($name) = @_;

    # combination of unix limitations + windows limitation characters are
    # limited to unix portable file character + space for windows compability
    # slash not valid as first character (unix limitation)
    # see http://technet.microsoft.com/en-us/library/cc776019%28WS.10%29.aspx
    if ($name =~ /^[a-zA-Z0-9\._-][a-zA-Z0-9\._[:space:]-]*$/) {
         return 1;
     } else {
         return undef;
     }
}

# Method: checkCnLimitations
#
#   Return whether the given string is valid for its usage as a cn field.
#
# Parameters:
#
#   string - The string to check.
#
sub checkCnLimitations
{
    my ($self, $string) = @_;

    if ($string =~ /^([a-zA-Z\d\s_-]+\.)*[a-zA-Z\d\s_-]+$/) {
        return 1;
    } else {
        return undef;
    }
}

#  Nethod: newUserUidNumber
#
#  return the uid for a new user
#
#   Parameters:
#     system - true if we want the uid for a system user, defualt false
#
sub newUserUidNumber
{
    my ($self, $system) = @_;

    return EBox::Samba::User->_newUserUidNumber($system);
}

######################################
##  SysInfo observer implementation ##
######################################

# Method: hostNameChanged
#
#   Disallow domainname changes if module is configured
#
sub hostNameChanged
{
    my ($self, $oldHostName, $newHostName) = @_;

    $self->_hostOrDomainChanged();
}

# Method: hostNameChangedDone
#
#   This method updates the computer netbios name if the module has not
#   been configured yet
#
sub hostNameChangedDone
{
    my ($self, $oldHostName, $newHostName) = @_;

    my $settings = $self->global()->modInstance('samba')->model('DomainSettings');
    $settings->setValue('netbiosName', $newHostName);
}

# Method: hostDomainChanged
#
#   This method disallow the change of the host domain if the module is
#   configured (implies that the kerberos realm has been initialized)
#
sub hostDomainChanged
{
    my ($self, $oldDomainName, $newDomainName) = @_;

    $self->_hostOrDomainChanged();

    if ($self->configured()) {
        $self->set('need_reprovision', 1);
        $self->setAsChanged(1); # for compability with machines with phantom
                                # need_reprovision in read-only tree
        EBox::Global->modInstance('webadmin')->setAsChanged();
    }
}

# Method: hostDomainChangedDone
#
#   This method updates the base DN for LDAP if the module has not
#   been configured yet
#
sub hostDomainChangedDone
{
    my ($self, $oldDomainName, $newDomainName) = @_;

    my $settings = $self->global()->modInstance('samba')->model('DomainSettings');
    $settings->setValue('realm', uc ($newDomainName));

    my @parts = split (/\./, $newDomainName);
    my $value = substr($parts[0], 0, 15);
    $value = 'ZENTYAL-DOMAIN' unless defined $value;
    $value = uc ($value);
    $settings->setValue('workgroup', $value);
}

sub _hostOrDomainChanged
{
    my ($self) = @_;

    if ($self->configured()) {
        if ($self->_adcMode()) {
            throw EBox::Exceptions::UnwillingToPerform(
                reason => __('The hostname or domain cannot be changed if Zentyal is configured as additional domain controller.')
            );
        }

        $self->set('need_reprovision', 1);
    }
}

# Method: reprovision
#
#   Destroys all LDAP/Kerberos configuration and creates a new
#   empty one. Useful after a host/domain change.
#
sub reprovision
{
    my ($self) = @_;

    return unless $self->configured();
    EBox::info("Reprovisioning LDAP");

    my @removeHomeCmds;
    foreach my $home (map { $_->home() } @{$self->users()}) {
        push (@removeHomeCmds, "rm -rf $home");
    }
    EBox::Sudo::root(@removeHomeCmds);

    $self->_manageService('stop');
    EBox::Sudo::root('rm -rf /var/lib/ldap/*');
    $self->_manageService('start');

    $self->enableActions();

    # LDAP module has lost its schemas and LDAP config after the reprovision
    my $global = $self->global();
    my @mods = @{ $global->sortModulesByDependencies($global->modInstances(), 'depends' ) };
    foreach my $mod (@mods) {
        if (not $mod->isa('EBox::Module::LDAP')) {
            next;
        } elsif ($mod->name() eq $self->name()) {
            # dont reconfigure itself
            next;
        } elsif (not $mod->configured()) {
            next;
        }
        $mod->reprovisionLDAP();
    }
}

sub reprovisionLDAP
{
    throw EBox::Exceptions::Internal("This method should not be called in user module");
}

# Implement EBox::SyncFolders::Provider interface
sub syncFolders
{
    my ($self) = @_;

    # sync all shares
    my $sshares = $self->model('SyncShares');
    my $shares = $self->model('SambaShares');

    my $syncAll = $sshares->row()->valueByName('sync');
    my @folders;
    for my $id (@{$shares->enabledRows()}) {
        my $row = $shares->row($id);
        my $sync = $row->valueByName('sync');

        my $path = $row->elementByName('path');
        if ($path->selectedType() eq 'zentyal') {
            $path = SHARES_DIR . '/' . $path->value();
        } else {
            $path = $path->value();
        }

        if ($sync or $syncAll) {
            push (@folders, new EBox::SyncFolders::Folder($path, 'share', name => basename($path)));
        }
    }

    if ($self->recoveryEnabled()) {
        push (@folders, new EBox::SyncFolders::Folder('/home', 'recovery'));
        foreach my $share ($self->filesystemShares()) {
            push (@folders, new EBox::SyncFolders::Folder($share, 'recovery'));
        }
    }

    return \@folders;
}

sub recoveryDomainName
{
    return __('Users data and Filesystem shares');
}

# Method: entryModeledObject
#
#   Return the Perl Object that handles the given LDAP entry.
#
#   Throw EBox::Exceptions::Internal on error.
#
# Parameters:
#
#   entry - A Net::LDAP::Entry object.
#
sub entryModeledObject
{
    my ($self, $entry) = @_;

    my $anyObjectClasses = any(@{[$entry->get_value('objectClass')]});
    # IMPORTANT: The order matters, a contactClass would match users too, so we must check first if it's a user.
    foreach my $type ( qw(ouClass userClass contactClass groupClass containerClass)) {
        my $class = $self->$type();
        # containerClass may not exist.
        next unless ($class);
        my $mainLDAPClass = $class->mainObjectClass();
        if ((defined $mainLDAPClass) and ($mainLDAPClass eq $anyObjectClasses)) {
            return $class->new(entry => $entry);
        }
    }

    my $ldap = $self->ldap();
    if ($entry->dn() eq $ldap->dn()) {
        return $self->defaultNamingContext();
    }

    EBox::debug("Ignored unknown perl object for DN: " . $entry->dn());
    return undef;
}

# Method: relativeDN
#
#   Return the given dn without the naming Context part.
#
sub relativeDN
{
    my ($self, $dn) = @_;

    throw EBox::Exceptions::MissingArgument("dn") unless ($dn);

    my $baseDN = $self->ldap()->dn();

    return '' if ($dn eq $baseDN);

    if (not $dn =~ s/,$baseDN$//) {
        throw EBox::Exceptions::Internal("$dn is not contained in $baseDN");
    }

    return $dn;
}

# Method: objectFromDN
#
#   Return the perl object modeling the given dn or undef if not found.
#
# Parameters:
#
#   dn - An LDAP DN string identifying the object to retrieve.
#
sub objectFromDN
{
    my ($self, $dn) = @_;
    my $ldap = $self->ldap();
    if ($dn eq $ldap->dn()) {
        return $self->defaultNamingContext();
    }

    my $baseObject = new EBox::Samba::LdapObject(dn => $dn);

    if ($baseObject->exists()) {
        return $self->entryModeledObject($baseObject->_entry());
    } else {
        return undef;
    }
}

# Method: defaultNamingContext
#
#   Return the Perl Object that holds the default Naming Context for this LDAP server.
#
sub defaultNamingContext
{
    my ($self) = @_;

    my $ldap = $self->ldap;
    return new EBox::Samba::NamingContext(dn => $ldap->dn());
}

sub ousToHide
{
    my ($self) = @_;

    my @ous;

    foreach my $mod (@{EBox::Global->modInstancesOfType('EBox::Module::LDAP')}) {
        push (@ous, @{$mod->_ldapModImplementation()->hiddenOUs()});
    }

    return \@ous;
}

# Method: checkMailNotInUse
#
#   check if a mail address is not used by the system and throw exception if it
#   is already used
#
#   If mail module is installed its checkMailNotInUse method should be called
#   instead this one
sub checkMailNotInUse
{
    my ($self, $addr, %params) = @_;

    my %searchParams = (
        base => $self->ldap()->dn(),
        filter => "&(|(objectclass=person)(objectclass=couriermailalias)(objectclass=group))(|(otherMailbox=$addr)(mail=$addr))",
        scope => 'sub'
    );

    my $result = $self->{'ldap'}->search(\%searchParams);
    foreach my $entry ($result->entries()) {
        my $modeledObject = $self->entryModeledObject($entry);
        my $type = $modeledObject ? $modeledObject->printableType() : $entry->get_value('objectClass');
        my $name;
        if ($type eq 'CourierMailAlias') {
            $type = __('alias');
            $name = $entry->get_value('mail');
        } else {
            $name = $modeledObject ? $modeledObject->name() : $entry->dn();
        }

        my $ownAddress = 0;
        if ($params{owner}) {
            $ownAddress = $entry->dn() eq $params{owner}->dn();
        }
        if (not $ownAddress) {
            EBox::Exceptions::External->throw(__x('Address {addr} is already in use by the {type} {name}',
                                              addr => $addr,
                                              type => $type,
                                              name => $name,
                                        ),
                                    );
        }
    }
}

sub getProvision
{
    my ($self) = @_;

    unless (defined $self->{provision}) {
        $self->{provision} = new EBox::Samba::Provision();
    }
    return $self->{provision};
}

sub isProvisioned
{
    my ($self) = @_;

    return $self->getProvision->isProvisioned();
}

# Method: domainControllers
#
#   Query the domain controllers by searching in 'Domain Controllers' OU
#
# Returns:
#
#   Array reference containing instances of EBox::Samba::Computer class
#
sub domainControllers
{
    my ($self) = @_;

    return [] unless $self->isProvisioned();

    my $sort = new Net::LDAP::Control::Sort(order => 'name');
    my $ldap = $self->ldap();
    my $baseDN = $ldap->dn();
    my $args = {
        base => "OU=Domain Controllers,$baseDN",
        filter => 'objectClass=computer',
        scope => 'sub',
        control => [ $sort ],
    };

    my $result = $ldap->search($args);

    my @computers;
    foreach my $entry ($result->entries()) {
        my $computer = new EBox::Samba::Computer(entry => $entry);
        next unless $computer->exists();
        push (@computers, $computer);
    }

    return \@computers;
}

# Method: computers
#
#   Query the computers joined to the domain by searching in the computers
#   container
#
# Returns:
#
#   Array reference containing instances of EBox::Samba::Computer class
#
sub computers
{
    my ($self) = @_;

    return [] unless $self->isProvisioned();

    my $sort = new Net::LDAP::Control::Sort(order => 'name');
    my $ldap = $self->ldap();
    my $baseDN = $ldap->dn();
    my $args = {
        base => "CN=Computers,$baseDN",,
        filter => 'objectClass=computer',
        scope => 'sub',
        control => [ $sort ],
    };

    my $result = $self->ldap->search($args);

    my @computers;
    foreach my $entry ($result->entries()) {
        my $computer = new EBox::Samba::Computer(entry => $entry);
        next unless $computer->exists();
        push (@computers, $computer);
    }

    return \@computers;
}

# Method: defaultNetbios
#
#   Generates the default netbios server name
#
sub defaultNetbios
{
    my ($self) = @_;

    my $sysinfo = EBox::Global->modInstance('sysinfo');
    my $hostName = $sysinfo->hostName();
    $hostName = substr($hostName, 0, 15);

    return $hostName;
}

# Method: defaultWorkgroup
#
#   Generates the default workgroup
#
sub defaultWorkgroup
{
    my $users = EBox::Global->modInstance('samba');
    my $realm = $users->kerberosRealm();
    my @parts = split (/\./, $realm);
    my $value = substr($parts[0], 0, 15);
    $value = 'ZENTYAL-DOMAIN' unless defined $value;

    return uc($value);
}

# Method: defaultDescription
#
#   Generates the default server string
#
sub defaultDescription
{
    my $prefix = EBox::Config::configkey('custom_prefix');
    $prefix = 'zentyal' unless $prefix;

    return ucfirst($prefix) . ' Server';
}

# Method: sambaInterfaces
#
# Return interfaces upon samba should listen
#
sub sambaInterfaces
{
    my ($self) = @_;
    my @ifaces = ();
    # Always listen on loopback interface
    push (@ifaces, 'lo');
    my $net = EBox::Global->modInstance('network');
    my $listen_external = EBox::Config::configkey('listen_external');
    my $netIfaces;
    if ($listen_external eq 'yes') {
        $netIfaces = $net->allIfaces();
    } else {
        $netIfaces = $net->InternalIfaces();
    }
    my %seenBridges;
    foreach my $iface (@{$netIfaces}) {
        my $method = $net->ifaceMethod($iface);
        next if ($method eq 'notset');
        push @ifaces, $iface;
        if ($method eq 'bridged') {
            my $br = $net->ifaceBridge($iface);
            if (not $seenBridges{$br}) {
                push (@ifaces, "br$br");
                $seenBridges{$br} = 1;
            }
            next;
        }
        my $vifacesNames = $net->vifaceNames($iface);
        if (defined $vifacesNames) {
            push @ifaces, @{$vifacesNames};
        }
    }
    return \@ifaces;
}

sub writeSambaConfig
{
    my ($self) = @_;

    my $netbiosName = $self->netbiosName();
    my $realmName   = $self->kerberosRealm();

    my $sysinfo = EBox::Global->modInstance('sysinfo');
    my $hostDomain = $sysinfo->hostDomain();

    my @array = ();
    push (@array, 'workgroup'   => $self->workgroup());
    push (@array, 'netbiosName' => $netbiosName);
    push (@array, 'description' => $self->description());
    push (@array, 'mode'        => 'dc');
    push (@array, 'realm'       => $realmName);
    push (@array, 'domain'      => $hostDomain);
    push (@array, 'roamingProfiles' => $self->roamingProfiles());
    push (@array, 'profilesPath' => PROFILES_DIR);
    push (@array, 'sysvolPath'  => SYSVOL_DIR);
    push (@array, 'shares' => 1);
    push (@array, 'shell' => $self->model('PAM')->value('login_shell'));

    if (not EBox::Config::boolean('listen_all')) {
        my $interfaces = join (',', @{$self->sambaInterfaces()});
        push (@array, 'ifaces' => $interfaces);
    }

    if ($self->global()->modExists('radius')) {
        my $radiusMod = $self->global()->modInstance('radius');
        if ($radiusMod->isEnabled()) {
            push (@array, 'radius' => 1);
        }
    }

    if ($self->global()->modExists('printers')) {
        my $printersMod = $self->global()->modInstance('printers');
        if ($printersMod->isEnabled()) {
            push (@array, 'print' => 1);
            $printersMod->writeSambaConfig();
        }
    }

    $self->writeConfFile(SAMBACONFFILE, 'samba/smb.conf.mas', \@array,
                         { 'uid' => 'root', 'gid' => 'root', mode => '644' });

    my $prefix = EBox::Config::configkey('custom_prefix');
    $prefix = 'zentyal' unless $prefix;

    push (@array, 'prefix' => $prefix);

    if ($self->global()->communityEdition()) {
        push (@array, 'disableFullAudit' => EBox::Config::boolean('disable_fullaudit'));
    } else {
        if ($self->sambaSettingByName('enable_full_audit')) {
            # If this option is enabled we need to disable the disabler (LOL)
            push (@array, 'disableFullAudit' => 0);
        } else {
            push (@array, 'disableFullAudit' => 1);
        }

    }

    push (@array, 'unmanagedAcls' => EBox::Config::boolean('unmanaged_acls'));
    push (@array, 'shares' => $self->shares());
    push (@array, 'disable_home_share' => EBox::Config::boolean('disable_home_share'));

    push (@array, 'recycle' => $self->defaultRecycleSettings());
    push (@array, 'recycle_exceptions' => $self->recycleExceptions());
    push (@array, 'recycle_config' => $self->recycleConfig());

    $self->writeConfFile(SHARESCONFFILE, 'samba/shares.conf.mas', \@array,
                         { 'uid' => 'root', 'gid' => 'root', mode => '644' });
}

# Method: netbiosName
#
#   Returns the configured netbios name
#
sub netbiosName
{
    my ($self) = @_;

    my $model = $self->model('DomainSettings');
    return $model->netbiosNameValue();
}

# Method: workgroup
#
#   Returns the configured workgroup name
#
sub workgroup
{
    my ($self) = @_;

    my $model = $self->model('DomainSettings');
    return $model->workgroupValue();
}

# Method: description
#
#   Returns the configured description string
#
sub description
{
    my ($self) = @_;

    my $model = $self->model('DomainSettings');
    return $model->descriptionValue();
}

# Method: roamingProfiles
#
#   Returns if roaming profiles are enabled
#
sub roamingProfiles
{
    my ($self) = @_;

    my $model = $self->model('DomainSettings');
    return $model->roamingValue();
}

sub _roamingProfilesPath
{
    my ($self) = @_;
    my $netbiosName = $self->netbiosName();
    my $realmName = $self->kerberosRealm();
    return "\\\\$netbiosName.$realmName\\profiles";
}

# Method: drive
#
#   Returns the configured drive letter
#
sub drive
{
    my ($self) = @_;

    my $model = $self->model('DomainSettings');
    return $model->driveValue();
}

# Method: dMD
#
#   Return the Perl Object that holds the Directory Management Domain for this LDB server.
#
sub dMD
{
    my ($self) = @_;

    my $dn = "CN=Schema,CN=Configuration," . $self->ldap()->dn();
    return new EBox::Samba::DMD(dn => $dn);
}

# Method: shares
#
#   It returns the custom shares
#
# Returns:
#
#   Array ref containing hash ref with:
#
#   share   - share's name
#   path    - share's path
#   comment - share's comment
#   readOnly  - string containing users and groups with read-only permissions
#   readWrite - string containing users and groups with read and write
#               permissions
#   administrators  - string containing users and groups with admin priviliges
#                     on the share
#   validUsers - readOnly + readWrite + administrators
#
sub shares
{
    my ($self) = @_;

    my $shares = $self->model('SambaShares');
    my @shares = ();

    for my $id (@{$shares->enabledRows()}) {
        my $row = $shares->row($id);
        my @readOnly;
        my @readWrite;
        my @administrators;
        my $shareConf = {};

        my $path = $row->elementByName('path');
        if ($path->selectedType() eq 'zentyal') {
            $shareConf->{'path'} = SHARES_DIR . '/' . $path->value();
        } else {
            $shareConf->{'path'} = $path->value();
        }
        $shareConf->{'type'} = $path->selectedType();
        $shareConf->{'share'} = $row->valueByName('share');
        $shareConf->{'comment'} = $row->valueByName('comment');
        $shareConf->{'guest'} = $row->valueByName('guest');
        $shareConf->{'groupShare'} = $row->valueByName('groupShare');

        for my $subId (@{$row->subModel('access')->ids()}) {
            my $subRow = $row->subModel('access')->row($subId);
            my $userType = $subRow->elementByName('user_group');
            my $preCar = '';
            if ($userType->selectedType() eq 'group') {
                $preCar = '@';
            }
            my $user = $preCar . '"' . $userType->value() . '"';

            my $permissions = $subRow->elementByName('permissions');

            if ($permissions->value() eq 'readOnly') {
                push (@readOnly, $user);
            } elsif ($permissions->value() eq 'readWrite') {
                push (@readWrite, $user);
            } elsif ($permissions->value() eq 'administrator') {
                push (@administrators, $user);
                push (@readWrite, $user);
            }
        }

        $shareConf->{'readOnly'} = join (', ', @readOnly);
        $shareConf->{'readWrite'} = join (', ', @readWrite);
        $shareConf->{'administrators'} = join (', ', @administrators);
        $shareConf->{'validUsers'} = join (', ', @readOnly,
                                                 @readWrite,
                                                 @administrators);

        push (@shares, $shareConf);
    }

    return \@shares;
}

sub defaultRecycleSettings
{
    my ($self) = @_;

    my $recycle = $self->model('RecycleDefault');
    return $recycle->row()->valueByName('enabled');
}

sub recycleExceptions
{
    my ($self) = @_;

    my $model = $self->model('RecycleExceptions');
    my $exceptions = {
        'share' => {},
        'group' => {},
    };

    for my $id (@{$model->ids()}) {
        my $row = $model->row($id);
        my $element = $row->elementByName('user_group_share');
        my $type = $element->selectedType();
        if ($type eq 'users') {
            $exceptions->{'users'} = 1;
        } else {
            my $value = $element->printableValue();
            $exceptions->{$type}->{$value} = 1;
        }
    }
    return $exceptions;
}

sub recycleConfig
{
    my ($self) = @_;

    my $conf = {};
    my @keys = ('repository', 'directory_mode', 'keeptree', 'versions', 'touch', 'minsize',
                'maxsize', 'exclude', 'excludedir', 'noversions', 'inherit_nt_acl');

    foreach my $key (@keys) {
        my $value = EBox::Config::configkey($key);
        if ($value) {
            $conf->{$key} = $value;
        }
    }

    return $conf;
}

sub _writeDnsUpdateList
{
    my ($self) = @_;

    my $array = [];
    my $partitions = ['DomainDnsZones', 'ForestDnsZones'];
    push (@{$array}, partitions => $partitions);
    $self->writeConfFile(SAMBA_DNS_UPDATE_LIST,
                         'samba/dns_update_list.mas', $array,
                         { 'uid' => '0', 'gid' => '0', mode => '644' });
}

# Implement LogHelper interface
sub tableInfo
{
    my ($self) = @_;

    my $access_titles = {
        'timestamp' => __('Date'),
        'client' => __('Client address'),
        'username' => __('User'),
        'event' => __('Action'),
        'resource' => __('Resource'),
    };
    my @access_order = qw(timestamp client username event resource);
    my $access_events = {
        'connect' => __('Connect'),
        'disconnect' => __('Disconnect'),
        'create_file' => __('Create file'),
        'pread_send' => __('Read file'),
        'pwrite_send' => __('Write file'),
        'renameat' => __('Rename'),
        'unlinkat' => __('Remove'),
        'mkdirat' => __('Create directory')
    };

    return [{
        'name' => __('Samba access'),
        'tablename' => 'samba_access',
        'titles' => $access_titles,
        'order' => \@access_order,
        'timecol' => 'timestamp',
        'filter' => ['client', 'username', 'resource'],
        'types' => { 'client' => 'IPAddr' },
        'events' => $access_events,
        'eventcol' => 'event'
    }];
}

sub logHelper
{
    my ($self) = @_;

    return (new EBox::SambaLogHelper);
}

# Method: filesystemShares
#
#   This function is used for Disaster Recovery, to get
#   the paths of the filesystem shares.
#
sub filesystemShares
{
    my ($self) = @_;

    my $shares = $self->shares();
    my $paths = [];

    foreach my $share (@{$shares}) {
        if ($share->{type} eq 'system') {
            push (@{$paths}, $share->{path});
        }
    }

    return $paths;
}

# Method: userShares
#
#   This function is used to generate disk usage reports. It
#   returns all the users with their shares
#
#   Returns:
#       Array ref with hash refs containing:
#           - 'user' - String the username
#           - 'shares' - Array ref with all the shares for this user
#
sub userShares
{
    my ($self) = @_;

    my $userProfilesPath = PROFILES_DIR;

    my $users = $self->users();

    my $shares = [];
    foreach my $user (@{$users}) {
        my $userProfilePath = $userProfilesPath . "/" . $user->get('samAccountName');

        my $userShareInfo = {
            'user' => $user->name(),
            'shares' => [$user->get('homeDirectory'), $userProfilePath],
        };
        push (@{$shares}, $userShareInfo);
    }

    return $shares;
}

# Method: groupPaths
#
#   This function is used to generate disk usage reports. It
#   returns the group share path if it is configured.
#
sub groupPaths
{
    my ($self, $group) = @_;

    my $groupName = $group->get('cn');
    my $shares = $self->shares();
    my $paths = [];

    foreach my $share (@{$shares}) {
        if (defined $groupName and defined $share->{groupShare} and
            $groupName eq $share->{groupShare}) {
            push (@{$paths}, $share->{path});
            last;
        }
    }

    return $paths;
}

my @sharesSortedByPathLen;

sub _updatePathsByLen
{
    my ($self) = @_;

    @sharesSortedByPathLen = ();

    # Group and custom shares
    foreach my $sh_r (@{ $self->shares() }) {
        push @sharesSortedByPathLen, {path => $sh_r->{path},
                                      share =>  $sh_r->{share},
                                      type => ($sh_r->{'groupShare'} ? 'Group' : 'Custom')};
    }

    # User shares
    foreach my $user (@{ $self->userShares() }) {
        foreach my $share (@{$user->{'shares'}}) {
            my $entry = {};
            $entry->{'share'} = $user->{'user'};
            $entry->{'type'} = 'User';
            $entry->{'path'} = $share;
            push (@sharesSortedByPathLen, $entry);
        }
    }

    # add regexes
    foreach my $share (@sharesSortedByPathLen) {
        my $path = $share->{path};
        # Remove duplicate '/'
        $path =~ s/\/+/\//g;
        $share->{pathRegex} = qr{^$path/};
    }

    @sharesSortedByPathLen = sort {
        length($b->{path}) <=>  length($a->{path})
    } @sharesSortedByPathLen;
}

#   Returns a hash with:
#       share - The name of the share
#       path  - The path of the share
#       type  - The type of the share (User, Group, Custom)
sub shareByFilename
{
    my ($self, $filename) = @_;

    if (not @sharesSortedByPathLen) {
        $self->_updatePathsByLen();
    }

    foreach my $shareAndPath (@sharesSortedByPathLen) {
        if ($filename =~ m/$shareAndPath->{pathRegex}/) {
            return $shareAndPath;
        }
    }

    return undef;
}

# Method: sambaSettingByName
#
#     Get samba parameters by its key name
#
sub sambaSettingByName
{
    my ($self, $name) = @_;
    my $val = $self->model('SambaSettings')->value($name);

    return $val; 
}

sub _cleanModulesForReprovision
{
    my ($self) = @_;

    foreach my $mod (@{$self->global()->modInstancesOfType('EBox::Module::LDAP')}) {
        my $state = $mod->get_state();
        delete $state->{'_schemasAdded'};
        delete $state->{'_ldapSetup'};
        $mod->set_state($state);
        $mod->setAsChanged(1);
    }
}

# Method: setACLs
#
#   Set ACLs for shares with pending changes
#
sub setACLs
{
    my ($self) = @_;

    my $samba = $self;
    my $sambaShares = $samba->model('SambaShares');

    for my $id (@{$sambaShares->ids()}) {
        my $row = $sambaShares->row($id);
        my $enabled     = $row->valueByName('enabled');
        my $shareName   = $row->valueByName('share');
        my $pathType    = $row->elementByName('path');
        my $guestAccess = $row->valueByName('guest');

        unless ($enabled) {
            next;
        }

        my $path = undef;
        if ($pathType->selectedType() eq 'zentyal') {
            $path = $samba->SHARES_DIR() . '/' . $pathType->value();
        } elsif ($pathType->selectedType() eq 'system') {
            $path = $pathType->value();
        } else {
            EBox::error("Unknown share type on share '$shareName'");
        }
        unless (defined $path) {
            next;
        }

        my $syncShareFile = EBox::Config::conf() . "samba/sync_shares/$shareName";
        my $syncShareFileExists = (-f $syncShareFile);

        if (EBox::Sudo::fileTest('-d', $path)) {
            next if EBox::Config::boolean('unmanaged_acls');
            next unless $syncShareFileExists; # share permissions didn't change, nothing needs to be done for this share.
        }

        EBox::info("Starting to apply recursive ACLs to share '$shareName'...");

        my @cmds = ();
        push (@cmds, "mkdir -p '$path'");
        push (@cmds, "setfacl -Rb '$path'"); # Clear POSIX ACLs
        if ($guestAccess) {
            push (@cmds, "chmod 0777 '$path'");
            push (@cmds, "chown nobody:'domain users' '$path'");
        } else {
            push (@cmds, "chmod 0770 '$path'");
            push (@cmds, "chown administrator:adm '$path'");
        }
        EBox::Sudo::root(@cmds);

        # Posix ACL
        my @posixACL;
        push (@posixACL, 'u:administrator:rwx');
        push (@posixACL, 'g:adm:rwx');
        push (@posixACL, 'g:"domain admins":rwx');

        for my $subId (@{$row->subModel('access')->ids()}) {
            my $subRow = $row->subModel('access')->row($subId);
            my $permissions = $subRow->elementByName('permissions');

            my $userType = $subRow->elementByName('user_group');
            my $perm;
            if ($userType->selectedType() eq 'group') {
                $perm = 'g:';
            } elsif ($userType->selectedType() eq 'user') {
                $perm = 'u:';
            }
            my $account = $userType->value();
            my $qobject = shell_quote($account);
            $perm .= $qobject . ':';

            if ($permissions->value() eq 'readOnly') {
                $perm .= 'rx';
            } elsif ($permissions->value() eq 'readWrite') {
                $perm .= 'rwx';
            } elsif ($permissions->value() eq 'administrator') {
                $perm .= 'rwx';
            } else {
                my $type = $permissions->value();
                EBox::error("Unknown share permission type '$type'");
                next;
            }
            push (@posixACL, $perm);
        }

        if (@posixACL) {
            try {
                EBox::Sudo::root('setfacl -R -m d:' . join(',d:', @posixACL) ." '$path'");
                EBox::Sudo::root('setfacl -R -m ' . join(',', @posixACL) . " '$path'");
            } catch {
                my $error = shift;
                EBox::error("Couldn't enable POSIX ACLs for $path: $error")
            }
        }

        unlink ($syncShareFile) if $syncShareFileExists;
        EBox::info("Recursive set of ACLs to share '$shareName' finished.");
    }
}

1;
