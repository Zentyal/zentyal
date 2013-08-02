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

# Class: EBox::Samba::User
#
#   Samba user, stored in samba LDAP
#
package EBox::Samba::User;

use base 'EBox::Samba::SecurityPrincipal';

use EBox::Global;
use EBox::Gettext;

use EBox::Exceptions::External;
use EBox::Exceptions::InvalidData;
use EBox::Exceptions::MissingArgument;
use EBox::Exceptions::UnwillingToPerform;

use EBox::Samba::Credentials;

use EBox::Users::User;
use EBox::Samba::Group;

use Perl6::Junction qw(any);
use Encode;
use Net::LDAP::Control;
use Net::LDAP::Entry;
use Net::LDAP::Constant qw(LDAP_LOCAL_ERROR);
use Date::Calc;
use Error qw(:try);

use constant MAXUSERLENGTH  => 128;
use constant MAXPWDLENGTH   => 512;

# Method: mainObjectClass
#
sub mainObjectClass
{
    return 'user';
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

    # The password will be changed on save
    $self->set('unicodePwd', $passwd, 1);
    $self->save() unless $lazy;
}

# Method: setCredentials
#
#   Configure user credentials directly from kerberos hashes
#
# Parameters:
#
#   keys - array ref of krb5keys
#
sub setCredentials
{
    my ($self, $keys, $lazy) = @_;

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
    $self->save($bypassControl) unless $lazy;
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
#   Enables or disables the user account, setting the userAccountControl
#   attribute. For a description of this attribute check:
#   http://support.microsoft.com/kb/305144
#
sub setAccountEnabled
{
    my ($self, $enable, $lazy) = @_;

    my $flags = $self->get('userAccountControl');
    if ($enable) {
        $flags = $flags & ~0x0002;
    } else {
        $flags = $flags | 0x0002;
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

    return not ($self->get('userAccountControl') & 0x0002);
}

# Method: addSpn
#
#   Add a service principal name to this account
#
sub addSpn
{
    my ($self, $spn, $lazy) = @_;

    my @spns = $self->get('servicePrincipalName');

    # return if spn already present
    foreach my $s (@spns) {
        return if (lc ($s) eq lc ($spn));
    }
    push (@spns, $spn);

    $self->set('servicePrincipalName', \@spns, $lazy);
}

sub createRoamingProfileDirectory
{
    my ($self) = @_;

    my $samAccountName  = $self->get('samAccountName');
    my $userSID         = $self->sid();
    my $domainAdminsSID = $self->_ldap->domainSID() . '-512';
    my $domainUsersSID  = $self->_ldap->domainSID() . '-513';

    # Create the directory if it does not exist
    my $samba = EBox::Global->modInstance('samba');
    my $path  = EBox::Samba::PROFILES_DIR() . "/$samAccountName";
    my $group = EBox::Users::DEFAULTGROUP();

    my @cmds = ();
    # Create the directory if it does not exist
    push (@cmds, "mkdir -p \'$path\'") unless -d $path;

    # Set unix permissions on directory
    push (@cmds, "chown $samAccountName:$group \'$path\'");
    push (@cmds, "chmod 0700 \'$path\'");

    # Set native NT permissions on directory
    my @perms;
    push (@perms, 'u:root:rwx');
    push (@perms, 'g::---');
    push (@perms, "g:$group:---");
    push (@perms, "u:$samAccountName:rwx");
    push (@cmds, "setfacl -b \'$path\'");
    push (@cmds, 'setfacl -R -m ' . join(',', @perms) . " \'$path\'");
    push (@cmds, 'setfacl -R -m d:' . join(',d:', @perms) ." \'$path\'");
    EBox::Sudo::root(@cmds);
}

sub setRoamingProfile
{
    my ($self, $enable, $path, $lazy) = @_;

    my $userName = $self->get('samAccountName');
    if ($enable) {
        $self->createRoamingProfileDirectory();
        $path .= "\\$userName";
        $self->set('profilePath', $path);
    } else {
        $self->delete('profilePath');
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

# Method: create
#
# FIXME: We should find a way to share code with the Contact::create method using the common class. I had to revert it
# because an OrganizationalPerson reconversion to a User failed.
#
#   Adds a new user
#
# Parameters:
#
#   args - Named parameters:
#       name
#       givenName
#       initials
#       sn
#       displayName
#       description
#       mail
#       samAccountName - string with the user name
#       clearPassword - Clear text password
#       kerberosKeys - Set of kerberos keys
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
    throw EBox::Exceptions::MissingArgument('name') unless ($args{name});
    throw EBox::Exceptions::MissingArgument('parent') unless ($args{parent});
    throw EBox::Exceptions::InvalidData(
        data => 'parent', value => $args{parent}->dn()) unless ($args{parent}->isContainer());



    my $samAccountName = $args{samAccountName};
    $class->_checkAccountName($samAccountName, MAXUSERLENGTH);

    # Check the password length if specified
    my $clearPassword = $args{'clearPassword'};
    if (defined $clearPassword) {
        $class->_checkPwdLength($clearPassword);
    }

    my $name = $args{name};
    my $dn = "CN=$name," .  $args{parent}->dn();

    $class->_checkAccountNotExists($name);
    my $usersMod = EBox::Global->modInstance('users');
    my $realm = $usersMod->kerberosRealm();

    my @attr = ();
    push (@attr, objectClass => ['top', 'person', 'organizationalPerson', 'user', 'posixAccount']);
    push (@attr, cn          => $name);
    push (@attr, name        => $name);
    push (@attr, givenName   => $args{givenName}) if ($args{givenName});
    push (@attr, initials    => $args{initials}) if ($args{initials});
    push (@attr, sn          => $args{sn}) if ($args{sn});
    push (@attr, displayName => $args{displayName}) if ($args{displayName});
    push (@attr, description => $args{description}) if ($args{description});
    push (@attr, sAMAccountName => $samAccountName);
    push (@attr, userPrincipalName => "$samAccountName\@$realm");
    push (@attr, userAccountControl => '514');

    my $res = undef;
    my $entry = undef;
    try {
        $entry = new Net::LDAP::Entry($dn, @attr);

        my $result = $entry->update($class->_ldap->connection());
        if ($result->is_error()) {
            unless ($result->code == LDAP_LOCAL_ERROR and $result->error eq 'No attributes to update') {
                throw EBox::Exceptions::LDAP(
                    message => __('Error on person LDAP entry creation:'),
                    result => $result,
                    opArgs => $class->entryOpChangesInUpdate($entry),
                );
            };
        }

        $res = new EBox::Samba::User(dn => $dn);

        # Set the password
        if (defined $args{clearPassword}) {
            $res->changePassword($args{clearPassword});
            $res->setAccountEnabled();
        } elsif (defined $args{kerberosKeys}) {
            $res->setCredentials($args{kerberosKeys});
            $res->setAccountEnabled();
        }

        if (defined $args{uidNumber}) {
            $res->setupUidMapping($args{uidNumber});
        }
    } otherwise {
        my ($error) = @_;

        EBox::error($error);

        if (defined $res and $res->exists()) {
            $res->SUPER::deleteObject(@_);
        }
        $res = undef;
        $entry = undef;
        throw $error;
    };

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

sub addToZentyal
{
    my ($self) = @_;

    my $sambaMod = EBox::Global->modInstance('samba');
    my $parent = $sambaMod->ldapObjectFromLDBObject($self->parent);

    if (not $parent) {
        my $dn = $self->dn();
        throw EBox::Exceptions::External("Unable to to find the container for '$dn' in OpenLDAP");
    }
    my $uid = $self->get('samAccountName');
    my $givenName = $self->givenName();
    my $surname = $self->surname();
    $givenName = '-' unless $givenName;
    $surname = '-' unless $surname;

    my $zentyalUser = undef;
    EBox::info("Adding samba user '$uid' to Zentyal");
    try {
        my %args = (
            uid          => scalar ($uid),
            parent       => $parent,
            fullname     => scalar($self->name()),
            givenname    => scalar($givenName),
            initials     => scalar($self->initials()),
            surname      => scalar($surname),
            displayname  => scalar($self->displayName()),
            description  => scalar($self->description()),
            ignoreMods   => ['samba'],
        );

        my $uidNumber = $self->xidNumber();
        unless (defined $uidNumber) {
            throw EBox::Exceptions::Internal("Could not get uidNumber for user $uid");
        }
        $args{uidNumber} = $uidNumber;
        $args{isSystemUser} = ($uidNumber < EBox::Users::User->MINUID());

        $zentyalUser = EBox::Users::User->create(%args);
    } catch EBox::Exceptions::DataExists with {
        EBox::debug("User $uid already in OpenLDAP database");
        $zentyalUser = new EBox::Users::User(uid => $uid);
    } otherwise {
        my $error = shift;
        EBox::error("Error loading user '$uid': $error");
    };

    if ($zentyalUser) {
        $zentyalUser->setIgnoredModules(['samba']);

        my $sc = $self->get('supplementalCredentials');
        my $up = $self->get('unicodePwd');
        my $creds = new EBox::Samba::Credentials(
            supplementalCredentials => $sc,
            unicodePwd => $up
        );
        $zentyalUser->setKerberosKeys($creds->kerberosKeys());

        $self->_linkWithUsersObject($zentyalUser);
    }
}

sub updateZentyal
{
    my ($self) = @_;

    my $uid = $self->get('samAccountName');
    EBox::info("Updating zentyal user '$uid'");

    my $zentyalUser = undef;
    my $givenName = $self->givenName();
    my $surname = $self->surname();
    my $fullName = $self->name();
    my $initials = $self->initials();
    my $displayName = $self->displayName();
    my $description = $self->description();
    $givenName = '-' unless $givenName;
    $surname = '-' unless $surname;

    $zentyalUser = new EBox::Users::User(uid => $uid);
    throw EBox::Exceptions::Internal("Zentyal user '$uid' does not exist") unless ($zentyalUser and $zentyalUser->exists());

    $zentyalUser->setIgnoredModules(['samba']);
    $zentyalUser->set('cn', $fullName, 1);
    $zentyalUser->set('givenName', $givenName, 1);
    $zentyalUser->set('initials', $initials, 1);
    $zentyalUser->set('sn', $surname, 1);
    $zentyalUser->set('displayName', $displayName, 1);
    $zentyalUser->set('description', $description, 1);
    $zentyalUser->save();

    my $sc = $self->get('supplementalCredentials');
    my $up = $self->get('unicodePwd');
    my $creds = new EBox::Samba::Credentials(
        supplementalCredentials => $sc,
        unicodePwd => $up
    );
    $zentyalUser->setKerberosKeys($creds->kerberosKeys());
}

1;
