# Copyright (C) 2012-2014 Zentyal S.L.
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

# Class: EBox::Samba::User
#
#   Samba user, stored in samba LDAP
#
package EBox::Samba::User;

use base qw(EBox::Samba::SecurityPrincipal);

use EBox::Config;
use EBox::Global;
use EBox::Sudo;
use EBox::Gettext;
use EBox::Samba;
use EBox::Samba::Group;

use EBox::Exceptions::External;
use EBox::Exceptions::InvalidData;
use EBox::Exceptions::MissingArgument;
use EBox::Exceptions::UnwillingToPerform;
use EBox::Exceptions::Internal;

use EBox::Samba::Credentials;

use Perl6::Junction qw(any);
use Encode qw(encode);
use Net::LDAP::Control;
use Net::LDAP::Entry;
use Net::LDAP::Constant qw(LDAP_ALREADY_EXISTS LDAP_LOCAL_ERROR);
use Date::Calc;
use File::Slurp;
use TryCatch;

use constant MAXUSERLENGTH  => 128;
use constant MAXPWDLENGTH   => 512;
use constant SYSMINUID      => 1900;
use constant MINUID         => 2000;
use constant MAXUID         => 2**31;
use constant HOMEPATH       => '/home';
use constant QUOTA_PROGRAM  => EBox::Config::scripts('samba') . 'user-quota';
use constant QUOTA_LIMIT    => 2097151;

# UserAccountControl flags extracted from http://support.microsoft.com/kb/305144
use constant SCRIPT                         => 0x00000001;
use constant ACCOUNTDISABLE                 => 0x00000002;
use constant HOMEDIR_REQUIRED               => 0x00000008;
use constant LOCKOUT                        => 0x00000010;
use constant PASSWD_NOTREQD                 => 0x00000020;
use constant PASSWD_CANT_CHANGE             => 0x00000040;
use constant ENCRYPTED_TEXT_PWD_ALLOWED     => 0x00000080;
use constant TEMP_DUPLICATE_ACCOUNT         => 0x00000100;
use constant NORMAL_ACCOUNT                 => 0x00000200;
use constant INTERDOMAIN_TRUST_ACCOUNT      => 0x00000800;
use constant WORKSTATION_TRUST_ACCOUNT      => 0x00001000;
use constant SERVER_TRUST_ACCOUNT           => 0x00002000;
use constant DONT_EXPIRE_PASSWORD           => 0x00010000;
use constant MNS_LOGON_ACCOUNT              => 0x00020000;
use constant SMARTCARD_REQUIRED             => 0x00040000;
use constant TRUSTED_FOR_DELEGATION         => 0x00080000;
use constant NOT_DELEGATED                  => 0x00100000;
use constant USE_DES_KEY_ONLY               => 0x00200000;
use constant DONT_REQ_PREAUTH               => 0x00400000;
use constant PASSWORD_EXPIRED               => 0x00800000;
use constant TRUSTED_TO_AUTH_FOR_DELEGATION => 0x01000000;
use constant PARTIAL_SECRETS_ACCOUNT        => 0x04000000;

# These attributes' changes are notified to LDAP slaves
use constant CORE_ATTRS => ('samAccountName', 'givenName', 'sn', 'description', 'mail',
                            'uidNumber', 'gidNumber', 'unicodePwd', 'supplementalCredentials');

sub new
{
    my $class = shift;
    my %opts = @_;

    my $self = $class->SUPER::new(%opts);

    if (defined $opts{uid}) {
        $self->{uid} = $opts{uid};
    }

    bless ($self, $class);
    return $self;
}

# Method: mainObjectClass
#
sub mainObjectClass
{
    return 'user';
}

sub printableType
{
    return __('user');
}

# Clss method: defaultContainer
#
#   Parameters:
#     ro - wether to use the read-only version of the users module
#
#   Return the default container that will hold Group objects.
#
sub defaultContainer
{
    my ($package, $ro) = @_;
    my $usersMod = EBox::Global->getInstance($ro)->modInstance('samba');
    return $usersMod->objectFromDN('CN=Users,' . $usersMod->ldap->dn());
}

# Method: uidTag
#
#   Return the tag to store the uid
#
sub uidTag
{
    return 'samAccountName';
}


# Method: changePassword
#
#   Configure a new password for the user
#
sub changePassword
{
    my ($self, $passwd, $lazy) = @_;

    $self->_checkPwdLength($passwd);

    $passwd = encode('UTF16-LE', "\"$passwd\"");

    # The password will be changed on save, save it also to
    # notify LDAP user base mods
    $self->{core_changed_password} = $passwd;
    $self->set('unicodePwd', $passwd, 1);
    try {
        $self->save() unless $lazy;
    } catch ($e) {
        throw EBox::Exceptions::External("$e");
    }
}

# Method: setCredentials
#
#   Configure user credentials directly from kerberos hashes
#   IMPORTANT: We cannot use lazy flag here due to the relaxing permissions we need.
#
# Parameters:
#
#   keys - array ref of krb5keys
#
sub setCredentials
{
    my ($self, $keys) = @_;

    my $pwdSet = 0;
    my $credentials = new EBox::Samba::Credentials(krb5Keys => $keys);
    if ($credentials->supplementalCredentials()) {
        $self->set('supplementalCredentials', $credentials->supplementalCredentials(), 1);
        $pwdSet = 1;
    }
    if ($credentials->unicodePwd()) {
        $self->set('unicodePwd', $credentials->unicodePwd(), 1);
        $pwdSet = 1;
    }

    if ($pwdSet) {
        # This value is stored as a large integer that represents
        # the number of 100 nanosecond intervals since January 1, 1601 (UTC)
        my ($sec, $min, $hour, $day, $mon, $year) = gmtime(time);
        $year = $year + 1900;
        $mon += 1;
        my $days = Date::Calc::Delta_Days(1601, 1, 1, $year, $mon, $day);
        my $secs = $sec + $min * 60 + $hour * 3600 + $days * 86400;
        my $val = $secs * 10000000;
        $self->set('pwdLastSet', $val, 1);
    }

    my $bypassControl = Net::LDAP::Control->new(
        type => '1.3.6.1.4.1.7165.4.3.12',
        critical => 1 );
    $self->save($bypassControl);
}

# Method: delete
#
#      Delete an attribute from the object
#
# Parameters:
#
#      attr - String the attribute's name
#
#      lazy - Boolean to perform the result directly or wait for
#             <save> method
#
sub delete
{
    my ($self, $attr, $lazy) = @_;

    # remember changes in core attributes (notify LDAP user base modules)
    if ($attr eq any(CORE_ATTRS)) {
        $self->{core_changed} = 1;
    }

    shift @_;
    $self->SUPER::delete(@_);
}


# Method: deleteObject
#
#   Delete the user
#
sub deleteObject
{
    my ($self, @params) = @_;

    if (not $self->checkObjectErasability()) {
        throw EBox::Exceptions::UnwillingToPerform(
            reason => __x('The object {x} is a system critical object.',
                          x => $self->dn()));
    }

    # Notify users deletion to modules
    my $usersMod = $self->_usersMod();
    $usersMod->notifyModsLdapUserBase('delUser', $self, $self->{ignoreMods});

    # Remove the roaming profile directory
    my $samAccountName = $self->get('samAccountName');
    my $path = EBox::Samba::PROFILES_DIR() . "/$samAccountName";
    EBox::Sudo::silentRoot("rm -rf '$path'");

    # TODO Remove this user from shares ACLs

    # Call super implementation
    $self->SUPER::deleteObject(@params);
}

sub setupUidMapping
{
    my ($self, $uidNumber) = @_;

    my $type = $self->_ldap->idmap->TYPE_UID();
    $self->_ldap->idmap->setupNameMapping($self->sid(), $type, $uidNumber);
}

# Method: setAccountEnabled
#
#   Enables or disables the user account.
#
sub setAccountEnabled
{
    my ($self, $enable, $lazy) = @_;

    unless (defined $enable) {
        throw EBox::Exceptions::MissingArgument('enable');
    }
    my $flags = $self->get('userAccountControl');
    if ($enable) {
        $flags = $flags & ~ACCOUNTDISABLE;
    } else {
        $flags = $flags | ACCOUNTDISABLE;
    }
    $self->set('userAccountControl', $flags, 1);

    $self->save() unless $lazy;
}

# Method: isAccountEnabled
#
#   Check if the account is enabled, reading the userAccountControl
#   attribute. For a description of this attribute check:
#   http://support.microsoft.com/kb/305144
#
# Returns:
#
#   boolean - 1 if enabled, 0 if disabled
#
sub isAccountEnabled
{
    my ($self) = @_;

    return not ($self->get('userAccountControl') & ACCOUNTDISABLE);
}

sub createRoamingProfileDirectory
{
    my ($self) = @_;

    my $domainSid       = $self->_ldap->domainSID();
    my $samAccountName  = $self->get('samAccountName');

    # Create the directory if it does not exist
    my $path  = EBox::Samba::PROFILES_DIR() . "/$samAccountName";
    my $gidNumber = $self->gidNumber();
    my $uidNumber = $self->uidNumber();

    my @cmds = ();
    # Create the directory if it does not exist
    push (@cmds, "mkdir -p \'$path\'") unless -d $path;

    # Set unix permissions on directory
    push (@cmds, "chown -R $uidNumber:$gidNumber \'$path\'");
    push (@cmds, "chmod 0700 \'$path\'");

    # Set native NT permissions on directory
    my @perms;
    push (@perms, 'u:root:rwx');
    push (@perms, 'g::---');
    push (@perms, "g:$gidNumber:---");
    push (@perms, "u:'$samAccountName':rwx");
    push (@cmds, "setfacl -b \'$path\'");
    push (@cmds, 'setfacl -R -m ' . join(',', @perms) . " \'$path\'");
    push (@cmds, 'setfacl -R -m d:' . join(',d:', @perms) ." \'$path\'");
    EBox::Sudo::root(@cmds);
}

sub setRoamingProfile
{
    my ($self, $enable, $path, $lazy) = @_;

    if ($enable) {
        my $userName = $self->get('samAccountName');
        $self->createRoamingProfileDirectory();
        $path .= "\\$userName";
        $self->set('profilePath', $path, $lazy);
    } else {
        $self->delete('profilePath', $lazy);
    }
    $self->save() unless $lazy;
}

sub setHomeDrive
{
    my ($self, $drive, $path, $lazy) = @_;

    my $userName = $self->get('samAccountName');
    $path .= "\\$userName";
    $self->set('homeDrive', $drive);
    $self->set('homeDirectory', $path);
    $self->save() unless $lazy;
}

# Method: setFullName
#
#    Change the full name and name attributes.
#
#    This requires to modify the Distinguished Name (DN) for the
#    object, therefore the operation cannot be lazy.
#
# Parameters:
#
#    newFullName - String the new full name
#
# Exceptions:
#
#    <EBox::Exceptions::DataExists> - if the CN already exists in the
#    same container.
#
#    <EBox::Exceptions::LDAP> if the operation cannot be done
#
sub setFullName
{
    my ($self, $newFullName) = @_;

    my $entry = $self->_entry();
    my $baseDN = $self->baseDn();
    my $newRDN = "CN=$newFullName";
    my $result = $self->_ldap()->connection()->moddn($entry, newrdn => $newRDN, deleteoldrdn => 1);
    if ($result->is_error()) {
        if ($result->code() eq LDAP_ALREADY_EXISTS) {
            throw EBox::Exceptions::DataExists(
                text => __x('User name with {x} full name already exists in the same container',
                            x => $newFullName));
        }
        throw EBox::Exceptions::LDAP(
            message => __('There was an error modifying the RDN:'),
            result  => $result,
            opArgs  => "New RDN: $newRDN"
           );
    }
    # Make it work in the next calls for user
    $self->{dn} = "$newRDN,$baseDN";
    $self->clearCache();
}

# Method: create
#
# FIXME: We should find a way to share code with the Contact::create method using the common class. I had to revert it
# because an OrganizationalPerson reconversion to a User failed.
#
#   Adds a new user
#
# Named parameters:
#
#       samAccountName
#       parent
#       givenName
#       initials
#       sn
#       displayName
#       description
#       mail
#       samAccountName - string with the user name
#       password - Clear text password
#       kerberosKeys - Set of kerberos keys
#       isSystemUser - boolean: if true it adds the user as system user, otherwise as normal user
#       uidNumber - user UID number
#
# Returns:
#
#   Returns the new create user object
#
sub create
{
    my ($class, %args) = @_;

    # Check for required arguments.
    throw EBox::Exceptions::MissingArgument('samAccountName') unless ($args{samAccountName});
    throw EBox::Exceptions::MissingArgument('parent') unless ($args{parent});
    throw EBox::Exceptions::InvalidData(
        data => 'parent', value => $args{parent}->dn()) unless ($args{parent}->isContainer());

    my $samAccountName = $args{samAccountName};
    $class->_checkAccountName($samAccountName, MAXUSERLENGTH);
    $class->_checkAccountNotExists($samAccountName);

    # Check the password length if specified
    my $password = $args{'password'};
    if (defined $password) {
        $class->_checkPwdLength($password);
    }
    my $isSystemUser = 0;
    if ($args{isSystemUser}) {
        $isSystemUser = 1;
    }

    my @userPwAttrs = getpwnam ($samAccountName);
    if (@userPwAttrs) {
        throw EBox::Exceptions::External(__('Username already exists on the system'));
    }

    my $homedir = _homeDirectory($samAccountName);
    if (-e $homedir) {
        EBox::warn("Home directory $homedir already exists when creating user $samAccountName");
    }
    my $quota = $class->defaultQuota();

    my $name = $args{name};
    unless ($name) {
        $name = $class->generatedFullName(%args);
        if (not $name) {
            throw EBox::Exceptions::MissingArgument('name or at least one name component parameter (givenName, sn, initials))');
        }
    }
    my $displayName = $args{displayName};
    unless ($displayName) {
        $displayName = $name;
    }

    my $mail = $args{'mail'};

    my $dn = "CN=$name," .  $args{parent}->dn();

    # Check DN is unique (duplicated givenName and surname)
    $class->_checkDnIsUnique($dn, $name);

    my $usersMod = EBox::Global->modInstance('samba');
    my $realm = $usersMod->kerberosRealm();

    my $uidNumber = defined $args{uidNumber} ?
                            $args{uidNumber} :
                            $class->_newUserUidNumber($isSystemUser);
    $class->_checkUid($uidNumber, $isSystemUser);

    my @attr = ();
    push (@attr, objectClass => ['top', 'person', 'organizationalPerson', 'user', 'posixAccount', 'systemQuotas']);
    push (@attr, cn          => $name);
    push (@attr, name        => $name);
    push (@attr, givenName   => $args{givenName}) if ($args{givenName});
    push (@attr, initials    => $args{initials}) if ($args{initials});
    push (@attr, sn          => $args{sn}) if ($args{sn});
    push (@attr, displayName => $displayName);
    push (@attr, description => $args{description}) if ($args{description});
    push (@attr, mail => $mail);
    push (@attr, sAMAccountName => $samAccountName);
    push (@attr, userPrincipalName => "$samAccountName\@$realm");
    # All accounts are, by default Normal and disabled accounts.
    push (@attr, userAccountControl => NORMAL_ACCOUNT | ACCOUNTDISABLE);
    push (@attr, uidNumber => $uidNumber);
    push (@attr, gidNumber => $class->_domainUsersGidNumber());
    push (@attr, homeDirectory => $homedir);
    push (@attr, quota => $quota);

    my $res = undef;
    my $entry = undef;
    try {
        $entry = new Net::LDAP::Entry($dn, @attr);
        my $result = $entry->update($class->_ldap->connection());
        if ($result->is_error()) {
            unless ($result->code() == LDAP_LOCAL_ERROR and $result->error() eq 'No attributes to update') {
                throw EBox::Exceptions::LDAP(
                    message => __('Error on person LDAP entry creation:'),
                    result => $result,
                    opArgs => { dn => $dn, @attr },
                );
            };
        }

        $res = new EBox::Samba::User(dn => $dn);

        if (defined $args{password}) {
            $res->changePassword($args{password});
            $res->setAccountEnabled(1);
        } elsif (defined $args{kerberosKeys}) {
            $res->setCredentials($args{kerberosKeys});
            $res->setAccountEnabled(1);
        }

        $res->setupUidMapping($uidNumber);

        # Init user
        if ($isSystemUser) {
            if ($uidNumber == 0) {
                # Special case to handle Samba's Administrator. It's like a regular user but without quotas.
                $usersMod->initUser($res);

                # Call modules initialization
                $usersMod->notifyModsLdapUserBase('addUser', [ $res ], $res->{ignoreMods});
            }
        } else {
            $usersMod->initUser($res);
            $res->_setFilesystemQuota($quota);

            # Call modules initialization
            $usersMod->notifyModsLdapUserBase(
                'addUser', [ $res ], $res->{ignoreMods});
        }
    } catch ($error) {
        EBox::error($error);

        if (defined $res and $res->exists()) {
            $res->SUPER::deleteObject(@_);
        }
        $res = undef;
        $entry = undef;
        throw $error;
    }

    return $res;
}

sub _checkAccountName
{
    my ($self, $name, $maxLength) = @_;
    $self->SUPER::_checkAccountName($name, $maxLength);
    if ($name =~ m/^[[:space:]\.]+$/) {
        throw EBox::Exceptions::InvalidData(
                'data' => __('account name'),
                'value' => $name,
                'advice' =>   __('Windows user names cannot be only spaces and dots.')
           );
    } elsif ($name =~ m/@/) {
        throw EBox::Exceptions::InvalidData(
                'data' => __('account name'),
                'value' => $name,
                'advice' =>   __('Windows user names cannot contain the "@" character.')
           );
    }
}

sub _checkPwdLength
{
    my ($self, $pwd) = @_;

    if (length($pwd) > MAXPWDLENGTH) {
        throw EBox::Exceptions::External(
                __x("Password must not be longer than {maxPwdLength} characters",
                    maxPwdLength => MAXPWDLENGTH));
    }
}

sub _checkDnIsUnique
{
    my ($self, $dn, $name) = @_;

    my $entry = new EBox::Samba::LdapObject(dn => $dn);
    if ($entry->exists()) {
        throw EBox::Exceptions::DataExists(
            text => __x('User name {x} already exists in the same container.',
                        x => $name));
    }
}

# Method: _entry
#
#   Return Net::LDAP::Entry entry for the user
#
sub _entry
{
    my ($self) = @_;

    unless ($self->{entry}) {
        if (defined $self->{uid}) {
            my $result = undef;
            my $attrs = {
                base => $self->_ldap->dn(),
                filter => "(samAccountName=$self->{uid})",
                scope => 'sub',
            };
            $result = $self->_ldap->search($attrs);
            if ($result->count() > 1) {
                throw EBox::Exceptions::Internal(
                    __x('Found {count} results for, expected only one.',
                        count => $result->count()));
            }
            $self->{entry} = $result->entry(0);
        } else {
            $self->SUPER::_entry();
        }
    }
    return $self->{entry};
}

# Method: name
#
#   Return user name
#
sub name
{
    my ($self) = @_;
    return $self->get('samAccountName');
}

sub home
{
    my ($self) = @_;
    return $self->get('homeDirectory');
}

sub quota
{
    my ($self) = @_;

    my $quota = $self->get('quota');
    return (defined ($quota) ? $quota : 0);
}

# Method: uidNumber
#
#   This method returns the user's uidNumber, ensuring it is properly set or
#   throwing an exception otherwise
#
sub uidNumber
{
    my ($self) = @_;

    my $uidNumber = $self->get('uidNumber');
    unless ($uidNumber =~ /^[0-9]+$/) {
        EBox::trace();
        throw EBox::Exceptions::External(
            __x('The user {x} has not uidNumber set. Get method ' .
                "returned '{y}'.",
                x => $self->get('samAccountName'),
                y => defined ($uidNumber) ? $uidNumber : 'undef'));
    }

    return $uidNumber;
}

# Method: gidNumber
#
#   This method returns the user's gidNumber, ensuring it is properly set or
#   throwing an exception otherwise
#
sub gidNumber
{
    my ($self) = @_;

    my $gidNumber = $self->get('gidNumber');
    unless ($gidNumber =~ /^[0-9]+$/) {
        throw EBox::Exceptions::External(
            __x('The user {x} has not gidNumber set. Get method ' .
                "returned '{y}'.",
                x => $self->get('samAccountName'),
                y => defined ($gidNumber) ? $gidNumber : 'undef'));
    }

    return $gidNumber;
}

sub isInternal
{
    my ($self) = @_;

    # FIXME: whitelist Guest account, Administrator account
    # do this better removing isCriticalSystemObject check
    if ($self->isAdministrator() or $self->isGuest()) {
        return 0;
    }

    return ($self->isInAdvancedViewOnly() or $self->get('isCriticalSystemObject'));
}

# Method: isAdministrator
#
#  Return if the user is Administrator system user
#
sub isAdministrator
{
    my ($self) = @_;

    return ($self->sid() =~ /^S-1-5-21-.*-500$/);
}

# Method: isGuest
#
#  Return if the user is Guest system user
#
sub isGuest
{
    my ($self) = @_;

    return ($self->sid() =~ /^S-1-5-21-.*-501$/);
}

sub setInternal
{
    my ($self, $internal, $lazy) = @_;

    $self->setInAdvancedViewOnly($internal, $lazy);
}

# Catch some of the set ops which need special actions
sub set
{
    my ($self, $attr, $value) = @_;

    if ($attr eq 'quota') {
        if ($self->_checkQuota($value)) {
            throw EBox::Exceptions::InvalidData('data' => __('user quota'),
                    'value' => $value,
                    'advice' => __('User quota must be an integer. To set an unlimited quota, enter zero.'),
                    );
        }

        # set quota on save
        $self->{set_quota} = 1;
    }

    # remember changes in core attributes (notify LDAP user base modules)
    if ($attr eq any(CORE_ATTRS)) {
        $self->{core_changed} = 1;
    }

    shift @_;
    $self->SUPER::set(@_);
}

sub save
{
    my ($self) = @_;

    my $changetype = $self->_entry->changetype();
    my $hasCoreChanges = $self->{core_changed};
    my $passwd = delete $self->{core_changed_password};

    if ($changetype ne 'delete') {
        if ($hasCoreChanges or defined $passwd) {
            my $usersMod = $self->_usersMod();
            $usersMod->notifyModsLdapUserBase('preModifyUser', [ $self, $passwd ], $self->{ignoreMods});
        }
    }

    if ($self->{set_quota}) {
        my $quota = $self->get('quota');
        $self->_checkQuota($quota);
        $self->_setFilesystemQuota($quota);
        delete $self->{set_quota};
    }

    shift @_;
    $self->SUPER::save(@_);

    if ($changetype ne 'delete') {
        if ($hasCoreChanges or defined $passwd) {
            delete $self->{core_changed};

            my $usersMod = $self->_usersMod();
            $usersMod->notifyModsLdapUserBase('modifyUser', [ $self, $passwd ], $self->{ignoreMods});
        }
    }
}

# Method: isSystem
#
#   Return 1 if this is a system user, 0 if not.
#
sub isSystem
{
    my ($self) = @_;

    my $uidNumber = $self->get('uidNumber');
    if (defined $uidNumber) {
        return ($uidNumber < MINUID);
    }

    return 1;
}

# Method: isDisabled
#
#   Return true if the user is disabled, false otherwise
#
sub isDisabled
{
    my ($self) = @_;

    return not $self->isAccountEnabled();
}

# Method: setDisabled
#
#   Enables / disables this user.
#
sub setDisabled
{
    my ($self, $status, $lazy) = @_;

    my $enabled = (not $status);
    $self->setAccountEnabled($enabled, $lazy);
}

sub _checkQuota
{
    my ($self, $quota) = @_;

    my $integer = $quota =~ m/^\d+$/;
    if (not $integer) {
        throw EBox::Exceptions::InvalidData('data' => __('user quota'),
                                            'value' => $quota,
                                            'advice' => __(
'User quota must be a positive integer. To set an unlimited quota, enter zero.'
                                                          ),
                                           );
    }

    if ($quota > QUOTA_LIMIT) {
        throw EBox::Exceptions::InvalidData(
            data => __('user quota'),
            value => $quota,
            advice => __x('The maximum value is {max} MB',
                          max => QUOTA_LIMIT),
        );
    }
}

sub _setFilesystemQuota
{
    my ($self, $userQuota) = @_;

    my $uid = $self->get('uidNumber');
    my $quota = $userQuota * 1024;
    EBox::Sudo::root(QUOTA_PROGRAM . " -s $uid $quota");

    # check if quota has been really set
    my $output = EBox::Sudo::root(QUOTA_PROGRAM . " -q $uid");
    my ($afterQuota) = $output->[0] =~ m/(\d+)/;
    if ((not defined $afterQuota) or ($quota != $afterQuota)) {
        EBox::error(
            __x('Cannot set quota for uid {uid} to {userQuota}. Maybe your file system does not support quota?',
                uid      => $uid,
                userQuota => $userQuota)
           );
    }
}

# Method: setPasswordFromHashes
#
#   Configure user password directly from its kerberos hashes.
#
#   It transforms the kerberos keys to Samba credentials (unicodePwd
#   and suplementalCredentials attributes)
#
# Parameters:
#
#   passwords - array ref of krb5keys
#
#   lazy - boolean this is ignored. See <setCredentials> for details.
#
sub setPasswordFromHashes
{
    my ($self, $passwords, $lazy) = @_;

    if (@{$passwords}) {
        my $krb5keys = $self->decodeKrb5Keys($passwords);
        $self->setCredentials($krb5keys);
    }
}

# Method: passwordHashes
#
#   Return an array ref to all krb hashed passwords as:
#
#   [ hash, hash, ... ]
#
# Returns:
#
#   array ref
#
# Exceptions:
#
#   <EBox::Exceptions::Internal> - thrown if we cannot get the
#   password hashes
#
sub passwordHashes
{
    my ($self) = @_;

    # To get password and credentials we need to use a special measure
    # by getting the attributes explicitly. This is possible because
    # we are reading from a special socket provided to do this.
    my $result = $self->_ldap()->search(
        { base   => $self->_ldap()->dn(),
          scope  => 'sub',
          filter => '(samAccountName=' . $self->name() . ')',
          attrs  => ['supplementalCredentials', 'unicodePwd']});
    if ($result->count() != 1) {
        throw EBox::Exceptions::Internal('Cannot get the passwords for ' . $self->name());
    }
    my $entry = $result->pop_entry();
    my ($unicodePwd, $suppCred) = ($entry->get_value('unicodePwd'),
                                   $entry->get_value('supplementalCredentials'));

    my $sambaCredentials = new EBox::Samba::Credentials(
        unicodePwd => $unicodePwd,
        supplementalCredentials => $suppCred
       );

    my $krb5Keys = $sambaCredentials->kerberosKeys();
    # Transform to set it as proper value for krb5Keys in OpenLDAP
    $krb5Keys = $self->_krb5Keys($krb5Keys);

    return $krb5Keys;
}

sub setThumbnailPhoto
{
    my ($self, $file) = @_;

    my $MAXSIZE = '96x96';

    my $tmpfile = "/var/lib/zentyal/tmp/profile-photo-$$.jpg";

    system("convert $file -resize '$MAXSIZE^' -gravity center -crop $MAXSIZE+0+0 +repage $tmpfile");

    my $jpg = read_file($tmpfile, binmode => ':raw');
    $self->set('thumbnailPhoto', $jpg);

    my $share = EBox::Config::configkey('photo_share_name');
    my $path = "/home/samba/shares/$share";
    if ($share and EBox::Sudo::fileTest('-d', $path)) {
        my $username = $self->name();
        EBox::Sudo::root("cp $tmpfile $path/$username.jpg");
    }
}

sub _checkUserName
{
    my ($name) = @_;
    if (not EBox::Samba::checkNameLimitations($name)) {
        return undef;
    }

    # windows user names cannot end with a  period
    if ($name =~ m/\.$/) {
        return undef;
    }

    return 1;
}

sub _homeDirectory
{
    my ($uid) = @_;

    my $home = HOMEPATH . '/' . $uid;
    return $home;
}

# Method: lastUid
#
#       Returns the last uid used.
#
# Parameters:
#
#       system - boolean: if true, it returns the last uid for system users,
#                         otherwise the last uid for normal users
#
# Returns:
#
#       string - last uid
#
sub lastUid
{
    my ($class, $system) = @_;

    my $lastUid = -1;
    my $sambaModule = EBox::Global->modInstance('samba');
    foreach my $user (@{$sambaModule->users($system)}) {
        my $uid = $user->get('uidNumber');
        if ($system) {
            last if ($uid >= MINUID);
        } else {
            next if ($uid < MINUID);
        }
        if ($uid > $lastUid) {
            $lastUid = $uid;
        }
    }

    my $ret;
    if ($system) {
        $ret = ($lastUid < SYSMINUID ? SYSMINUID : $lastUid);
    } else {
        $ret = ($lastUid < MINUID ? MINUID : $lastUid);
    }
    return $ret;
}

sub _newUserUidNumber
{
    my ($class, $systemUser) = @_;

    my $uid = $class->lastUid($systemUser);
    do {
        # try next uid in order
        $uid++;

        if ($systemUser) {
            if ($uid >= MINUID) {
                throw EBox::Exceptions::Internal(
                    __('Maximum number of system users reached'));
            }
        } else {
            if ($uid >= MAXUID) {
                throw EBox::Exceptions::Internal(
                        __('Maximum number of users reached'));
            }
        }

        # check if uid is already used
    } while (defined getpwuid($uid));

    return $uid;
}

sub _checkUid
{
    my ($self, $uid, $system) = @_;

    if ($uid < MINUID) {
        if (not $system) {
            throw EBox::Exceptions::External(
                __x('Incorrect UID {uid} for a user . UID must be equal or greater than {min}',
                    uid => $uid,
                    min => MINUID,
                   )
                );
        }
    }
    else {
        if ($system) {
            throw EBox::Exceptions::External(
                __x('Incorrect UID {uid} for a system user . UID must be lesser than {max}',
                    uid => $uid,
                    max => MINUID,
                   )
                );
        }
    }
}

# Get the gidNumber from Domain Users
sub _domainUsersGidNumber
{
    my ($class) = @_;

    my $ldap = $class->_ldap();
    my $group = $ldap->domainUsersGroup();
    return $group->gidNumber();
}

sub quotaAvailable
{
    return 1;
}

sub defaultQuota
{
    my $usersMod = EBox::Global->modInstance('samba');
    my $model = $usersMod->model('AccountSettings');

    my $value = $model->defaultQuotaValue();
    if ($value eq 'defaultQuota_disabled') {
        $value = 0;
    }

    return $value;
}

# Method: decodeKrb5Keys
#
#     Return the Kerberos key hashes for this user decoded using
#     krb5Key.asn file.
#
# Parameters:
#
#     krb5Keys - Array ref containing the encoded Kerberos 5 keys.
#
# Returns:
#
#     Array ref - containing three hash refs with the following keys
#
#         type  - Int the hash type (18 => DES-CBC-CRC, 16 => DES-CBC-MD5,
#                                    23 => arcfour-HMAC-MD5 (AKA NTLMv2)
#         value - Octects containing the hash
#
#         salt  - String the salt (only valid for 18 and 16 types)
#
sub decodeKrb5Keys
{
    my ($self, $krb5Keys) = @_;

    my $keys = [];

    my $syntaxFile = EBox::Config::scripts('samba') . 'krb5Key.asn';
    my $asn = Convert::ASN1->new();
    $asn->prepare_file($syntaxFile) or
        throw EBox::Exceptions::Internal($asn->error());
    my $asn_key = $asn->find('Key') or
        throw EBox::Exceptions::Internal($asn->error());

    foreach my $blob (@{$krb5Keys}) {
        my $key = $asn_key->decode($blob) or
            throw EBox::Exceptions::Internal($asn_key->error());
        push @{$keys}, {
                         type  => $key->{key}->{value}->{keytype}->{value},
                         value => $key->{key}->{value}->{keyvalue}->{value},
                         salt  => $key->{salt}->{value}->{salt}->{value}
                       };
    }

    return $keys;
}

# Transform samba credentials to krb5Keys expected by OpenLDAP
sub _krb5Keys
{
    my ($self, $keys) = @_;

    unless (defined $keys) {
        throw EBox::Exceptions::MissingArgument('keys');
    }

    my $syntaxFile = EBox::Config::scripts('samba') . 'krb5Key.asn';
    my $asn = Convert::ASN1->new();
    $asn->prepare_file($syntaxFile) or
        throw EBox::Exceptions::Internal($asn->error());
    my $asn_key = $asn->find('Key') or
        throw EBox::Exceptions::Internal($asn->error());

    my $blobs = [];
    foreach my $key (@{$keys}) {
        my $salt = undef;
        if (defined $key->{salt}) {
            $salt = {
                value => {
                    type => {
                        value => 3
                    },
                    salt => {
                        value => $key->{salt}
                    },
                    opaque => {
                        value => '',
                    },
                },
            };
        }

        my $blob = $asn_key->encode(
            mkvno => {
                value => 0
            },
            salt => $salt,
            key => {
                value => {
                    keytype => {
                        value =>  $key->{type}
                    },
                    keyvalue => {
                        value => $key->{value}
                    }
                }
            }) or
        throw EBox::Exceptions::Internal($asn_key->error());
        push (@{$blobs}, $blob);
    }
    return $blobs;
}

# Method: showPaginationForm
#
#   Show pagination form in the view.
#
sub showPaginationForm
{
    return 1;
}

# Method: defaultPageSize
#
#   Return the default amount of elements to show
#
sub defaultPageSize
{
    return 10;
}

# Method: table
#
#   Configure table to show in the pagination of the tree.
#
sub table
{
    my $dataTable = {
        'tableName'          => "Users",
        'printableTableName' => __('Users'),
        'confdir'            => "User"
    };

    return $dataTable;
}

# Method: changeViewJS
#
#     Return the javascript function to change view to
#     add a row
#
# Parameters:
#
#    (NAMED)
#    changeType - changeAdd or changeList
#    editId - edit id
#    page - page number
#    isFilter - boolean indicating if comes from filtering
#
#
# Returns:
#
#     string - holding a javascript funcion
sub changeViewJS
{
    my ($self, %args) = @_;

    my ($type, $editId, $page, $isFilter) = ($args{changeType},$args{editId}, $args{page},$args{isFilter},);

    my $function = "Zentyal.TableHelper.changeView('%s','%s','%s','%s','%s', %s, %s)";

    my $table = $self->table();
    return sprintf ($function,
                    '/Samba/ListContainer',
                    $table->{'tableName'},
                    $table->{'confdir'},
                    $type,
                    $editId,
                    $page,
                    $isFilter);
}

# Method: pageNumbersText
#
#  returns the localized string used in the pager.
sub pageNumbersText
{
    my ($self, $page, $nPages) = @_;
   if ($nPages == 1) {
        return __('Page 1');
   } else {
        return __x('Page {i} of {n}', i => $page + 1, n => $nPages);
   }
}

1;
