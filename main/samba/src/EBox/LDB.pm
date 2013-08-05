# Copyright (C) 2012-2013 Zentyal S.L.
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

package EBox::LDB;
use base 'EBox::LDAPBase';

use EBox::Samba::OU;
use EBox::Samba::User;
use EBox::Samba::Contact;
use EBox::Samba::Group;
use EBox::Samba::DNS::Zone;
use EBox::Users::User;

use EBox::LDB::IdMapDb;
use EBox::Exceptions::DataNotFound;
use EBox::Exceptions::DataExists;
use EBox::Exceptions::External;
use EBox::Exceptions::Internal;
use EBox::Gettext;

use Net::LDAP;
use Net::LDAP::Util qw(ldap_error_name);

use Error qw( :try );
use File::Slurp qw(read_file);
use Perl6::Junction qw(any);
use Time::HiRes;

use constant LDAPI => "ldapi://%2fopt%2fsamba4%2fprivate%2fldap_priv%2fldapi" ;

use constant BUILT_IN_CONTAINERS => qw(Users Computers Builtin);

# NOTE: The list of attributes available in the different Windows Server versions
#       is documented in http://msdn.microsoft.com/en-us/library/cc223254.aspx
use constant ROOT_DSE_ATTRS => [
    'configurationNamingContext',
    'currentTime',
    'defaultNamingContext',
    'dnsHostName',
    'domainControllerFunctionality',
    'domainFunctionality',
    'dsServiceName',
    'forestFunctionality',
    'highestCommittedUSN',
    'isGlobalCatalogReady',
    'isSynchronized',
    'ldapServiceName',
    'namingContexts',
    'rootDomainNamingContext',
    'schemaNamingContext',
    'serverName',
    'subschemaSubentry',
    'supportedCapabilities',
    'supportedControl',
    'supportedLDAPPolicies',
    'supportedLDAPVersion',
    'supportedSASLMechanisms',
];

# Singleton variable
my $_instance = undef;

sub _new_instance
{
    my $class = shift;

    my $ignoredGroupsFile = EBox::Config::etc() . 's4sync-groups.ignore';
    my @lines = read_file($ignoredGroupsFile);
    chomp (@lines);
    my %ignoredGroups = map { $_ => 1 } @lines;

    my $self = $class->SUPER::_new_instance();
    $self->{idamp} = undef;
    $self->{ignoredGroups} = \%ignoredGroups;
    bless ($self, $class);
    return $self;
}

# Method: instance
#
#   Return a singleton instance of this class
#
# Returns:
#
#   object of class <EBox::LDB>
sub instance
{
    my ($class) = @_;

    unless(defined($_instance)) {
        $_instance = $class->_new_instance();
    }

    return $_instance;
}

# Method: idmap
#
#   Returns an instance of IdMapDb.
#
sub idmap
{
    my ($self) = @_;

    unless (defined $self->{idmap}) {
        $self->{idmap} = EBox::LDB::IdMapDb->new();
    }
    return $self->{idmap};
}

# Method: connection
#
#   Return the Net::LDAP connection used by the module
#
# Exceptions:
#
#   Internal - If connection can't be created
#
# Override:
#   EBox::LDAPBase::connection
#
sub connection
{
    my ($self) = @_;

    # Workaround to detect if connection is broken and force reconnection
    my $reconnect = 0;
    if (defined $self->{ldap}) {
        my $mesg = $self->{ldap}->search(
                base => '',
                scope => 'base',
                filter => "(cn=*)",
                );
        if (ldap_error_name($mesg) ne 'LDAP_SUCCESS') {
            $self->clearConn();
            $reconnect = 1;
        }
    }

    if (not defined $self->{ldap} or $reconnect) {
        $self->{ldap} = $self->safeConnect();
    }

    return $self->{ldap};
}

# Method: url
#
#  Return the URL or parameter to create a connection with this LDAP
#
# Override: EBox::LDAPBase::url
#
sub url
{
    return LDAPI;
}

sub safeConnect
{
    my ($self) = @_;

    local $SIG{PIPE};
    $SIG{PIPE} = sub {
       EBox::warn('SIGPIPE received connecting to samba LDAP');
    };

    my $samba = EBox::Global->modInstance('samba');
    $samba->_startService() unless $samba->isRunning();

    my $error = undef;
    my $lastError = undef;
    my $maxTries = 300;
    for (my $try=1; $try<=$maxTries; $try++) {
        my $ldb = Net::LDAP->new(LDAPI);
        if (defined $ldb) {
            my $dse = $ldb->root_dse(attrs => ROOT_DSE_ATTRS);
            if (defined $dse) {
                return $ldb;
            }
        }
        $error = $@;
        EBox::warn("Could not connect to samba LDAP server: $error, retrying. ($try attempts)")   if (($try == 1) or (($try % 100) == 0));
        Time::HiRes::sleep(0.1);
    }

    throw EBox::Exceptions::External(
        __x(q|FATAL: Could not connect to samba LDAP server: {error}|,
            error => $error));
}

# Method: dn
#
#   Returns the base DN (Distinguished Name)
#
# Returns:
#
#   string - DN
#
sub dn
{
    my ($self) = @_;

    unless (defined $self->{dn}) {
        my $dse = $self->rootDse();

        $self->{dn} = $dse->get_value('defaultNamingContext');
    }

    return defined $self->{dn} ? $self->{dn} : '';
}

#############################################################################
## LDB related functions                                                   ##
#############################################################################

# Method domainSID
#
#   Get the domain SID
#
# Returns:
#
#   string - The SID string of the domain
#
sub domainSID
{
    my ($self) = @_;

    my $base = $self->dn();
    my $params = {
        base => $base,
        scope => 'base',
        filter => "(distinguishedName=$base)",
        attrs => ['objectSid'],
    };
    my $msg = $self->search($params);
    if ($msg->count() == 1) {
        my $entry = $msg->entry(0);
        # The object is not a SecurityPrincipal but a SamDomainBase. As we only query
        # for the sid, it works.
        my $object = new EBox::Samba::SecurityPrincipal(entry => $entry);
        return $object->sid();
    } else {
        throw EBox::Exceptions::DataNotFound(data => 'domain', value => $base);
    }
}

sub domainNetBiosName
{
    my ($self) = @_;

    my $realm = EBox::Global->modInstance('users')->kerberosRealm();
    my $params = {
        base => 'CN=Partitions,CN=Configuration,' . $self->dn(),
        scope => 'sub',
        filter => "(&(nETBIOSName=*)(dnsRoot=$realm))",
        attrs => ['nETBIOSName'],
    };
    my $result = $self->search($params);
    if ($result->count() == 1) {
        my $entry = $result->entry(0);
        my $name = $entry->get_value('nETBIOSName');
        return $name;
    }
    return undef;
}

sub ldapOUToLDB
{
    my ($self, $ldapOU) = @_;

    unless ($ldapOU and $ldapOU->isa('EBox::Users::OU')) {
        throw EBox::Exceptions::MissingArgument('ldapOU');
    }

    my $global = EBox::Global->getInstance();
    my $sambaMod = $global->modInstance('samba');

    my $parent = $sambaMod->ldbObjectFromLDAPObject($ldapOU->parent);
    if (not $parent) {
        my $dn = $ldapOU->dn();
        throw EBox::Exceptions::External("Unable to to find the container for '$dn' in Samba");
    }
    my $name = $ldapOU->name();
    my $parentDN = $parent->dn();

    EBox::debug("Loading OU $name into $parentDN");
    # Samba already has an specific container for this OU, ignore it.
    if (($parentDN eq $self->dn()) and (grep { $_ eq $name } BUILT_IN_CONTAINERS)) {
        EBox::debug("Ignoring OU $name given that it has a built in container");
        next;
    }

    my $sambaOU = undef;
    try {
        $sambaOU = EBox::Samba::OU->create(name => $name, parent => $parent);
        $sambaOU->_linkWithUsersObject($ldapOU);
    } catch EBox::Exceptions::DataExists with {
        EBox::debug("OU $name already in $parentDN on Samba database");
        $sambaOU = $sambaMod->ldbObjectFromLDAPObject($ldapOU);
    } otherwise {
        my $error = shift;
        EBox::error("Error loading OU '$name' in '$parentDN': $error");
    };

    return $sambaOU;
}

sub ldapOUsToLDB
{
    my ($self) = @_;

    EBox::info('Loading Zentyal OUS into samba database');

    my $global = EBox::Global->getInstance();
    my $usersMod = $global->modInstance('users');
    my @ous = @{ $usersMod->ous() };
    foreach my $ou (@ous) {
        $self->ldapOUToLDB($ou);
    }
}

sub ldapUsersToLdb
{
    my ($self) = @_;

    EBox::info('Loading Zentyal users into samba database');
    my $global = EBox::Global->getInstance();
    my $usersMod = $global->modInstance('users');
    my $sambaMod = $global->modInstance('samba');

    my $users = $usersMod->users();
    foreach my $user (@{$users}) {
        my $parent = $sambaMod->ldbObjectFromLDAPObject($user->parent);
        if (not $parent) {
            my $dn = $user->dn();
            throw EBox::Exceptions::External("Unable to to find the container for '$dn' in Samba");
        }
        my $samAccountName = $user->get('uid');
        EBox::debug("Loading user $samAccountName");
        try {
            my %args = (
                name           => scalar ($user->get('cn')),
                samAccountName => scalar ($samAccountName),
                parent         => $parent,
                uidNumber      => scalar ($user->get('uidNumber')),
                sn             => scalar ($user->get('sn')),
                givenName      => scalar ($user->get('givenName')),
                description    => scalar ($user->get('description')),
                kerberosKeys   => $user->kerberosKeys(),
            );
            my $sambaUser = EBox::Samba::User->create(%args);
            $sambaUser->_linkWithUsersObject($user);
        } catch EBox::Exceptions::DataExists with {
            EBox::debug("User $samAccountName already in Samba database");
            my $sambaUser = new EBox::Samba::User(samAccountName => $samAccountName);
            $sambaUser->setCredentials($user->kerberosKeys());
            EBox::debug("Password updated for user $samAccountName");
        } otherwise {
            my $error = shift;
            EBox::error("Error loading user '$samAccountName': $error");
        };
    }
}

sub ldapContactsToLdb
{
    my ($self) = @_;

    EBox::info('Loading Zentyal contacts into samba database');
    my $global = EBox::Global->getInstance();
    my $usersMod = $global->modInstance('users');
    my $sambaMod = $global->modInstance('samba');

    my $contacts = $usersMod->contacts();
    foreach my $contact (@{$contacts}) {
        my $parent = $sambaMod->ldbObjectFromLDAPObject($contact->parent);
        if (not $parent) {
            my $dn = $contact->dn();
            throw EBox::Exceptions::External("Unable to to find the container for '$dn' in Samba");
        }

        my $parentDN = $parent->dn();
        my $name = $contact->get('cn');
        EBox::debug("Loading contact $name on $parentDN");
        try {
            my %args = (
                name        => scalar ($name),
                parent      => $parent,
                givenName   => scalar ($contact->get('givenName')),
                initials    => scalar ($contact->get('initials')),
                sn          => scalar ($contact->get('sn')),
                displayName => scalar ($contact->get('displayName')),
                description => scalar ($contact->get('description')),
                mail        => $contact->get('mail')
            );
            my $sambaContact = EBox::Samba::Contact->create(%args);
            $sambaContact->_linkWithUsersObject($contact);
        } catch EBox::Exceptions::DataExists with {
            EBox::debug("Contact $name already in $parentDN on Samba database");
        } otherwise {
            my $error = shift;
            EBox::error("Error loading contact '$name' in '$parentDN': $error");
        };
    }
}

sub ldapGroupsToLdb
{
    my ($self) = @_;

    EBox::info('Loading Zentyal groups into samba database');
    my $global = EBox::Global->getInstance();
    my $usersMod = $global->modInstance('users');
    my $sambaMod = $global->modInstance('samba');

    my $groups = $usersMod->groups();
    foreach my $group (@{$groups}) {
        my $parent = $sambaMod->ldbObjectFromLDAPObject($group->parent);
        if (not $parent) {
            my $dn = $group->dn();
            throw EBox::Exceptions::External("Unable to to find the container for '$dn' in Samba");
        }
        my $parentDN = $parent->dn();
        my $name = $group->get('cn');
        EBox::debug("Loading group $name");
        my $sambaGroup = undef;
        try {
            my %args = (
                name => $name,
                parent => $parent,
                description => scalar ($group->get('description')),
                isSecurityGroup => $group->isSecurityGroup(),
            );
            if ($group->isSecurityGroup()) {
                $args{gidNumber} = scalar ($group->get('gidNumber'));
            };
            $sambaGroup = EBox::Samba::Group->create(%args);
            $sambaGroup->_linkWithUsersObject($group);
        } catch EBox::Exceptions::DataExists with {
            EBox::debug("Group $name already in Samba database");
        } otherwise {
            my $error = shift;
            EBox::error("Error loading group '$name': $error");
        };
        next unless defined $sambaGroup;

        foreach my $user (@{$group->users()}) {
            try {
                my $smbUser = new EBox::Samba::User(samAccountName => $user->get('uid'));
                next unless defined $smbUser;
                $sambaGroup->addMember($smbUser, 1);
            } otherwise {
                my $error = shift;
                EBox::error("Error adding member: $error");
            };
        }
        $sambaGroup->save();
    }
}

sub ldapServicePrincipalsToLdb
{
    my ($self) = @_;

    EBox::info('Loading Zentyal service principals into samba database');
    my $sysinfo = EBox::Global->modInstance('sysinfo');
    my $hostname = $sysinfo->hostName();
    my $fqdn = $sysinfo->fqdn();

    my $modules = EBox::Global->modInstancesOfType('EBox::KerberosModule');
    my $usersMod = EBox::Global->modInstance('users');
    my $sambaMod = EBox::Global->modInstance('samba');

    my $ldb = $sambaMod->ldb();
    my $baseDn = $usersMod->ldap()->dn();
    my $realm = $usersMod->kerberosRealm();
    my $ldapKerberosDN = "ou=Kerberos,$baseDn";
    my $ldapKerberosOU = new EBox::Users::OU(dn => $ldapKerberosDN);

    # If OpenLDAP doesn't have the Kerberos OU, we don't need to do anything.
    return unless ($ldapKerberosOU and $ldapKerberosOU->exists());

    my $ldbKerberosOU = $sambaMod->ldbObjectFromLDAPObject($ldapKerberosOU);
    unless ($ldbKerberosOU) {
        # Check whether the OU exist in Samba but it's not linked with OpenLDAP.
        my $ldbRootDN = $ldb->dn();
        my $ldbKerberosDN = "OU=Kerberos,$ldbRootDN";
        $ldbKerberosOU = $sambaMod->objectFromDN($ldbKerberosDN);

        if ($ldbKerberosOU and $ldbKerberosOU->exists()) {
            $ldbKerberosOU->_linkWithUsersObject($ldapKerberosOU);
        } else {
            $ldbKerberosOU = $ldb->ldapOUToLDB($ldapKerberosOU);
        }
    }

    return unless ($ldbKerberosOU and $ldbKerberosOU->exists());

    foreach my $module (@{$modules}) {
        my $principals = $module->kerberosServicePrincipals();
        my $samAccountName = "$principals->{service}-$hostname";
        try {
            my $smbUser = new EBox::Samba::User(samAccountName => $samAccountName);
            unless ($smbUser->exists()) {
                # Get the heimdal user to extract the kerberos keys. All service
                # principals for each module should have the same keys, so take
                # the first one.
                my $p = @{$principals->{principals}}[0];
                my $dn = "krb5PrincipalName=$p/$fqdn\@$realm,$ldapKerberosDN";
                my $user = new EBox::Users::User(dn => $dn, internal => 1);
                # If the user does not exists the module has not been enabled yet
                next unless ($user->exists());

                EBox::info("Importing service principal $dn");
                my %args = (
                    name           => scalar ($user->get('uid')),
                    parent         => $ldbKerberosOU,
                    samAccountName => scalar ($samAccountName),
                    description    => scalar ($user->get('description')),
                    kerberosKeys   => $user->kerberosKeys(),
                );
                $smbUser = EBox::Samba::User->create(%args);
                # TODO: Should we link this with any OpenLDAP user?
                $smbUser->setCritical(1);
                $smbUser->setViewInAdvancedOnly(1);
            }
            foreach my $p (@{$principals->{principals}}) {
                try {
                    my $spn = "$p/$fqdn";
                    EBox::info("Adding SPN '$spn' to user " . $smbUser->dn());
                    $smbUser->addSpn($spn);
                } otherwise {
                    my $error = shift;
                    EBox::error("Error adding SPN '$p' to account '$samAccountName': $error");
                };
            }
        } otherwise {
            my $error = shift;
            EBox::error("Error adding account '$samAccountName': $error");
        };
    }
}

sub users
{
    my ($self) = @_;

    my $params = {
        base => $self->dn(),
        scope => 'sub',
        filter => '(&(&(objectclass=user)(!(objectclass=computer)))' .
                  '(!(showInAdvancedViewOnly=*))(!(isDeleted=*)))',
        attrs => ['*', 'unicodePwd', 'supplementalCredentials'],
    };
    my $result = $self->search($params);
    my $list = [];
    foreach my $entry ($result->sorted('samAccountName')) {
        my $user = new EBox::Samba::User(entry => $entry);
        push (@{$list}, $user);
    }
    return $list;
}

sub contacts
{
    my ($self) = @_;

    my $params = {
        base => $self->dn(),
        scope => 'sub',
        filter => '(&(&(objectclass=contact)(!(objectclass=computer)))' .
                  '(!(showInAdvancedViewOnly=*))(!(isDeleted=*)))',
        attrs => ['*'],
    };
    my $result = $self->search($params);
    my $list = [];
    foreach my $entry ($result->sorted('name')) {
        my $contact = new EBox::Samba::Contact(entry => $entry);

        push (@{$list}, $contact);
    }
    return $list;
}

sub groups
{
    my ($self) = @_;

    my $params = {
        base => $self->dn(),
        scope => 'sub',
        filter => '(&(objectclass=group)(!(showInAdvancedViewOnly=*))(!(isDeleted=*)))',
        attrs => ['*', 'unicodePwd', 'supplementalCredentials'],
    };
    my $result = $self->search($params);
    my $list = [];
    foreach my $entry ($result->sorted('samAccountName')) {

        next if (exists $self->{ignoredGroups}->{$entry->get_value('samAccountName')});

        my $group = new EBox::Samba::Group(entry => $entry);

        push (@{$list}, $group);
    }

    return $list;
}

sub ous
{
    my ($self) = @_;
    my $objectClass = EBox::Samba::OU->mainObjectClass();
    my %args = (
        base => $self->dn(),
        filter => "(objectclass=$objectClass)",
        scope => 'sub',
    );

    my $result = $self->search(\%args);

    my @ous = ();
    foreach my $entry ($result->entries)
    {
        my $ou = EBox::Samba::OU->new(entry => $entry);
        push (@ous, $ou);
    }

    my @sortedOUs = sort { $a->canonicalName(1) cmp $b->canonicalName(1) } @ous;

    return \@sortedOUs;
}

# Method: dnsZones
#
#   Returns the DNS zones stored in the samba LDB
#
sub dnsZones
{
    my ($self) = @_;

    my $defaultNC = $self->dn();
    my @zonePrefixes = (
        "CN=MicrosoftDNS,DC=DomainDnsZones,$defaultNC",
        "CN=MicrosoftDNS,DC=ForestDnsZones,$defaultNC",
        "CN=MicrosoftDNS,CN=System,$defaultNC");
    my @ignoreZones = ('RootDNSServers', '..TrustAnchors');
    my $zones = [];

    foreach my $prefix (@zonePrefixes) {
        my $params = {
            base => $prefix,
            scope => 'one',
            filter => '(objectClass=dnsZone)',
            attrs => ['*']
        };
        my $result = $self->search($params);
        foreach my $entry ($result->entries()) {
            my $name = $entry->get_value('name');
            next unless defined $name;
            next if $name eq any @ignoreZones;
            my $zone = new EBox::Samba::DNS::Zone(entry => $entry);
            push (@{$zones}, $zone);
        }
    }
    return $zones;
}

# Method: rootDse
#
#   Returns the root DSE
#
sub rootDse
{
    my ($self) = @_;

    return $self->connection()->root_dse(attrs => ROOT_DSE_ATTRS);
}

1;
