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

package EBox::SambaLdapUser;
use base qw(EBox::LdapUserBase);

use MIME::Base64;
use Encode;
use Error qw(:try);

use EBox::Exceptions::External;
use EBox::Exceptions::Internal;
use EBox::Exceptions::NotImplemented;
use EBox::Sudo;
use EBox::Samba;
use EBox::Samba::OU;
use EBox::Samba::User;
use EBox::Samba::Group;
use EBox::Samba::Contact;
use EBox::Gettext;

sub new
{
    my $class = shift;
    my $self  = {};
    my $global = EBox::Global->getInstance(0);
    $self->{samba} = $global->modInstance('samba');
    $self->{ldb} = $self->{samba}->ldb();
    bless($self, $class);

    return $self;
}

# Method: _ldbDNFromLDAPDN
#
#   Return the LDB DN mapped from a given LDAP DN. It only works for OU and Contacts!
#
# TODO: Remove this deprecated method ASAP!
#
sub _ldbDNFromLDAPDN
{
    my ($self, $ldapDN) = @_;

    my $usersMod = EBox::Global->modInstance('users');

    my $relativeDN = $usersMod->relativeDN($ldapDN);
    # Computers, Builtin and Users are not OUs for Samba.
    $relativeDN =~ s/ou=Users$/CN=Users/gi;
    $relativeDN =~ s/ou=Computers$/CN=Computers/gi;
    $relativeDN =~ s/ou=Builtin$/CN=Builtin/gi;
    if (grep (/^uid=/i, $relativeDN)) {
        throw EBox::Exceptions::NotImplemented();
    }
    my $dn = '';
    if ($relativeDN) {
        $dn = $relativeDN .  ',';
    }
    $dn .= $self->{ldb}->dn();
    return $dn;
}

sub _sambaReady
{
    my ($self) = @_;
    return ($self->{samba}->configured() and
            $self->{samba}->isEnabled() and
            $self->{samba}->isProvisioned());
}

sub _preAddOU
{
    my ($self, $entry, $parent) = @_;

    return unless ($self->_sambaReady());

    my $sambaParent = $self->{samba}->ldbObjectFromLDAPObject($parent);
    my $name = $entry->get_value('ou');

    EBox::debug("Creating OU in LDB '$name'");
    my $ou = EBox::Samba::OU->create(name => $name, parent => $sambaParent);
    $ou->_linkWithUsersEntry($entry);
}

sub _preAddOuFailed
{
    my ($self, $entry, $parent) = @_;
    $self->_sambaReady() or
        return;

    try {
        my $sambaOU = undef;
        my $objectGUID = $entry->get_value('msdsObjectGUID');
        if ($objectGUID) {
            $sambaOU = new EBox::Samba::OU(objectGUID => $objectGUID);
        } else {
            # TODO: Stop using ldbDNFromLDAPDN!!
            my $dn = $self->_ldbDNFromLDAPDN($entry->dn());
            $sambaOU = new EBox::Samba::OU(dn => $dn);
        }
        return unless ($sambaOU and $sambaOU->exists());

        EBox::info("Aborted OU creation, removing from samba");
        $sambaOU->deleteObject();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error deleting OU " . $entry->dn() . ": $error");
    };
}

sub _delOU
{
    my ($self, $zentyalOU) = @_;
    $self->_sambaReady() or
        return;

    EBox::debug("Deleting OU '" . $zentyalOU->dn() . "' from samba");
    my $sambaOU = $self->{samba}->ldbObjectFromLDAPObject($zentyalOU);
    return unless $sambaOU;
    try {
        $sambaOU->deleteObject();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error deleting OU '" . $sambaOU->dn() . "': $error");
    };
}

# Method: _preAddUser
#
#   This method add the user to samba LDAP. The account will be
#   created, but without password and disabled.
#
sub _preAddUser
{
    my ($self, $entry, $parent) = @_;
    $self->_sambaReady() or
        return;

    my $name        = $entry->get_value('cn');
    my $givenName   = $entry->get_value('givenName');
    my $initials    = $entry->get_value('initials');
    my $surname     = $entry->get_value('sn');
    my $displayName = $entry->get_value('displayName');
    my $description = $entry->get_value('description');
    my $mail        = $entry->get_value('mail');
    my $uid         = $entry->get_value('uid');

    my $sambaParent = $self->{samba}->ldbObjectFromLDAPObject($parent);

    my @args = ();
    push (@args, name           => $name);
    push (@args, parent         => $sambaParent);
    push (@args, samAccountName => $uid);
    push (@args, givenName      => $givenName);
    push (@args, initials       => $initials) if ($initials);
    push (@args, sn             => $surname);
    push (@args, displayName    => $displayName) if ($displayName);
    push (@args, description    => $description) if ($description);
    push (@args, mail           => $mail) if ($mail);

    EBox::info("Creating user '$uid'");
    my $sambaUser = EBox::Samba::User->create(@args);
    my $uidNumber = $sambaUser->xidNumber();
    unless (defined $uidNumber) {
        throw EBox::Exceptions::Internal("Could not get the xidNumber from SAMBA for user $uid");
    }
    $entry->replace('uidNumber' => $uidNumber);
    $sambaUser->_linkWithUsersEntry($entry);
}

sub _preAddUserFailed
{
    my ($self, $entry, $parent) = @_;
    $self->_sambaReady() or
        return;

    my $uid = $entry->get_value('uid');
    try {
        my $sambaUser = undef;
        my $objectGUID = $entry->get_value('msdsObjectGUID');
        if ($objectGUID) {
            $sambaUser = new EBox::Samba::User(objectGUID => $objectGUID);
        } else {
            $sambaUser = new EBox::Samba::User(samAccountName => $uid);
        }
        return unless ($sambaUser and $sambaUser->exists());

        EBox::info("Aborted User creation, removing from samba");
        $sambaUser->deleteObject();
    } otherwise {
        my ($error) = @_;
        EBox::info("Error removing samba user $uid: $error");
    };
}

# Method: _addUser
#
#   This method sets the user password and enable the account
#
sub _addUser
{
    my ($self, $zentyalUser, $zentyalPassword) = @_;
    $self->_sambaReady() or
        return;

    my $samAccountName = $zentyalUser->get('uid');
    my $sambaUser = new EBox::Samba::User(samAccountName => $samAccountName);

    EBox::info("Setting '$samAccountName' password");
    if (defined($zentyalPassword)) {
        $sambaUser->changePassword($zentyalPassword);
    } else {
        my $keys = $zentyalUser->kerberosKeys();
        $sambaUser->setCredentials($keys);
    }

    # If server is first DC and roaming profiles are enabled, write
    # the attributes
    my $sambaSettings = $self->{samba}->model('GeneralSettings');
    my $dc = $sambaSettings->MODE_DC();
    if ($self->{samba}->mode() eq $dc) {
        my $netbiosName = $self->{samba}->netbiosName();
        my $realmName = EBox::Global->modInstance('users')->kerberosRealm();
        if ($self->{samba}->roamingProfiles()) {
            my $path = "\\\\$netbiosName.$realmName\\profiles";
            EBox::info("Enabling roaming profile for user '$samAccountName'");
            $sambaUser->setRoamingProfile(1, $path, 1);
        } else {
            $sambaUser->setRoamingProfile(0);
        }

        # Mount user home on network drive
        my $drivePath = "\\\\$netbiosName.$realmName";
        EBox::info("Setting home network drive for user '$samAccountName'");
        $sambaUser->setHomeDrive($self->{samba}->drive(), $drivePath, 1);
        $sambaUser->save();
    }

    unless ($zentyalUser->isDisabled()) {
        EBox::info("Enabling '$samAccountName' account");
        $sambaUser->setAccountEnabled(1);
    }
}

sub _addUserFailed
{
    my ($self, $zentyalUser) = @_;
    $self->_sambaReady() or
        return;

    try {
        my $uid = $zentyalUser->get('uid');
        my $sambaUser = new EBox::Samba::User(samAccountName => $uid);
        return unless $sambaUser->exists();
        EBox::info("Aborted user creation, removing from samba");
        $sambaUser->deleteObject();
    } otherwise {
    };
}

sub _modifyUser
{
    my ($self, $zentyalUser, $zentyalPwd) = @_;
    $self->_sambaReady() or
        return;

    my $dn = $zentyalUser->dn();
    EBox::debug("Updating user '$dn'");
    try {
        my $sambaUser = new EBox::Samba::User(samAccountName => $zentyalUser->get('uid'));
        return unless $sambaUser->exists();

        my $gn = $zentyalUser->get('givenName');
        my $sn = $zentyalUser->get('sn');
        my $description = $zentyalUser->description();
        my $mail = $zentyalUser->mail();
        $sambaUser->set('givenName', $gn, 1);
        $sambaUser->set('sn', $sn, 1);
        if ($description) {
            $sambaUser->set('description', $description, 1);
        } else {
            $sambaUser->delete('description', 1);
        }
        if ($mail) {
            $sambaUser->set('mail', $mail, 1);
        } else {
            $sambaUser->delete('mail', 1);
        }
        if (defined($zentyalPwd)) {
            $sambaUser->changePassword($zentyalPwd, 1);
        } else {
            my $keys = $zentyalUser->kerberosKeys();
            $sambaUser->setCredentials($keys);
        }
        if ($zentyalUser->isDisabled()) {
            $sambaUser->setAccountEnabled(0);
        } else {
            $sambaUser->setAccountEnabled(1);
        }
        $sambaUser->save();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error modifying user: $error");
    };
}

sub _delUser
{
    my ($self, $zentyalUser) = @_;
    $self->_sambaReady() or
        return;

    my $dn = $zentyalUser->dn();
    EBox::debug("Deleting user '$dn' from samba");
    try {
        my $samAccountName = $zentyalUser->get('uid');
        my $sambaUser = new EBox::Samba::User(samAccountName => $samAccountName);
        return unless $sambaUser->exists();
        $sambaUser->deleteObject();

        # Remove user from share ACL's
        my $shares = $self->{samba}->model('SambaShares');
        my $sharesIds = $shares->ids();
        foreach my $shareId (@{$sharesIds}) {
            my $shareRow = $shares->row($shareId);
            my $acls = $shareRow->subModel('access');
            my $aclsIds = $acls->ids();
            foreach my $aclId (@{$aclsIds}) {
                my $aclRow = $acls->row($aclId);
                my $type = $aclRow->elementByName('user_group');
                if ($type->selectedType() eq 'user' and
                    $type->printableValue() eq $samAccountName) {
                    $acls->removeRow($aclId);
                }
            }
        }
    } otherwise {
        my ($error) = @_;
        EBox::error("Error deleting user: $error");
    };
}

# Method: _preAddContact
#
#   This method adds the contact to samba LDAP.
#
sub _preAddContact
{
    my ($self, $entry, $parent) = @_;
    $self->_sambaReady() or
        return;

    my $name = $entry->get_value('cn');
    my $givenName = $entry->get_value('givenName');
    my $initials = $entry->get_value('initials');
    my $sn = $entry->get_value('sn');
    my $displayName = $entry->get_value('displayName');
    my $description = $entry->get_value('description');
    my $mail = $entry->get_value('mail');
    my $sambaParent = $self->{samba}->ldbObjectFromLDAPObject($parent);

    my @args = ();
    push (@args, name        => $name);
    push (@args, parent      => $sambaParent);
    push (@args, givenName   => $givenName) if ($givenName);
    push (@args, initials    => $initials) if ($initials);
    push (@args, sn          => $sn) if ($sn);
    push (@args, displayName => $displayName) if ($displayName);
    push (@args, description => $description) if ($description);
    push (@args, mail        => $mail) if ($mail);

    EBox::info("Creating contact '$name'");
    my $sambaContact = EBox::Samba::Contact->create(@args);
    $sambaContact->_linkWithUsersEntry($entry);
}

sub _preAddContactFailed
{
    my ($self, $entry, $parent) = @_;
    $self->_sambaReady() or
        return;

    try {
        my $sambaContact = undef;
        my $objectGUID = $entry->get_value('msdsObjectGUID');
        if ($objectGUID) {
            $sambaContact = new EBox::Samba::Contact(objectGUID => $objectGUID);
        } else {
            # TODO: Stop using ldbDNFromLDAPDN!!
            my $dn = $self->_ldbDNFromLDAPDN($entry->dn());
            $sambaContact = new EBox::Samba::Contact(dn => $dn);
        }
        return unless ($sambaContact and $sambaContact->exists());

        EBox::info("Aborted Contact creation, removing from samba");
        $sambaContact->deleteObject();
    } otherwise {
        my ($error) = @_;
        EBox::debug("Error removing contact " . $entry->dn() . ": $error");
    };
}

sub _modifyContact
{
    my ($self, $zentyalContact) = @_;
    $self->_sambaReady() or
        return;

    my $dn = $zentyalContact->dn();
    EBox::debug("Updating contact '$dn'");

    try {
        my $sambaContact = $self->{samba}->ldbObjectFromLDAPObject($zentyalContact);
        return unless $sambaContact->exists();

        my $givenName = $zentyalContact->get_value('givenName');
        my $initials = $zentyalContact->get_value('initials');
        my $sn = $zentyalContact->get_value('sn');
        my $displayName = $zentyalContact->get_value('displayName');
        my $description = $zentyalContact->get_value('description');
        my $mail = $zentyalContact->get_value('mail');

        if ($givenName) {
            $sambaContact->set('givenName', $givenName, 1);
        } else {
            $sambaContact->delete('givenName', 1);
        }
        if ($initials) {
            $sambaContact->set('initials', $initials, 1);
        } else {
            $sambaContact->delete('initials', 1);
        }
        if ($sn) {
            $sambaContact->set('sn', $sn, 1);
        } else {
            $sambaContact->delete('sn', 1);
        }
        if ($displayName) {
            $sambaContact->set('displayName', $displayName, 1);
        } else {
            $sambaContact->delete('displayName', 1);
        }
        if ($description) {
            $sambaContact->set('description', $description, 1);
        } else {
            $sambaContact->delete('description', 1);
        }
        if ($mail) {
            $sambaContact->set('mail', $mail, 1);
        } else {
            $sambaContact->delete('mail', 1);
        }
        $sambaContact->save();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error modifying contact: $error");
    };
}

sub _delContact
{
    my ($self, $zentyalContact) = @_;
    $self->_sambaReady() or
        return;

    my $dn = $zentyalContact->dn();
    EBox::debug("Deleting contact '$dn' from samba");
    try {
        my $sambaContact = $self->{samba}->ldbObjectFromLDAPObject($zentyalContact);
        return unless $sambaContact->exists();
        $sambaContact->deleteObject();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error deleting contact: $error");
    };
}

# Method: _preAddGroup
#
#
sub _preAddGroup
{
    my ($self, $entry, $parent) = @_;
    $self->_sambaReady() or
        return;

    my $name = $entry->get_value('cn');
    my $sambaParent = $self->{samba}->ldbObjectFromLDAPObject($parent);
    my $description = $entry->get_value('description');
    my $mail = $entry->get_value('mail');

    # The isSecurityGroup flag is not set here given that the zentyalObject doesn't exist yet, we will
    # update it later on the _addGroup callback. Maybe we would move this creation to _addGroup...
    my @args = ();
    push (@args, name          => $name);
    push (@args, parent        => $sambaParent);
    push (@args, 'description' => $description) if ($description);
    push (@args, 'mail'        => $mail) if ($mail);

    EBox::info("Creating group '$name'");
    my $sambaGroup = EBox::Samba::Group->create(@args);
    my $gidNumber = $sambaGroup->xidNumber();
    unless (defined $gidNumber) {
        throw EBox::Exceptions::Internal("Could not get the xidNumber from SAMBA for group $name");
    }
    $entry->replace('gidNumber' => $gidNumber);
    $sambaGroup->_linkWithUsersEntry($entry);
}

sub _preAddGroupFailed
{
    my ($self, $entry, $parent) = @_;
    $self->_sambaReady() or
        return;

    my $samAccountName = $entry->get_value('cn');
    try {
        my $sambaGroup = undef;
        my $objectGUID = $entry->get_value('msdsObjectGUID');
        if ($objectGUID) {
            $sambaGroup = new EBox::Samba::Group(objectGUID => $objectGUID);
        } else {
            $sambaGroup = new EBox::Samba::Group(samAccountName => $samAccountName);
        }
        return unless ($sambaGroup and $sambaGroup->exists());

        EBox::info("Aborted group creation, removing from samba");
        $sambaGroup->deleteObject();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error removig group $samAccountName: $error")
    };
}

# Method: _addGroup
#
# The kind of group is set at this stage.
#
sub _addGroup
{
    my ($self, $zentyalGroup) = @_;
    $self->_sambaReady() or
        return;

    my $samAccountName = $zentyalGroup->get('cn');
    my $sambaGroup = new EBox::Samba::Group(samAccountName => $samAccountName);
    if ($sambaGroup->exists()) {
        if ($zentyalGroup->isSecurityGroup()) {
            unless ($sambaGroup->isSecurityGroup()) {
                $sambaGroup->setSecurityGroup(1);
                my $gidNumber = $sambaGroup->xidNumber();
                unless (defined $gidNumber) {
                    throw EBox::Exceptions::Internal("Could not get gidNumber for group " . $zentyalGroup->name());
                }
                $zentyalGroup->set('gidNumber', $gidNumber);
            }
        } elsif ($sambaGroup->isSecurityGroup()) {
            $sambaGroup->setSecurityGroup(0);
        }
    } else {
        EBox::error("Error setting the kind of group for $samAccountName");
    };
}

sub _addGroupFailed
{
    my ($self, $zentyalGroup) = @_;
    $self->_sambaReady() or
        return;

    my $samAccountName = $zentyalGroup->get('cn');
    try {
        my $sambaGroup = new EBox::Samba::Group(samAccountName => $samAccountName);
        return unless $sambaGroup->exists();
        EBox::info("Aborted group creation, removing from samba");
        $sambaGroup->deleteObject();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error removig group $samAccountName: $error")
    };
}

sub _modifyGroup
{
    my ($self, $zentyalGroup) = @_;
    $self->_sambaReady() or
        return;

    my $dn = $zentyalGroup->dn();
    EBox::debug("Modifying group '$dn'");
    try {
        my $sambaGroup = new EBox::Samba::Group(samAccountName => $zentyalGroup->get('cn'));
        return unless $sambaGroup->exists();

        my $sambaMembersDNs = [];
        my $zentyalMembers = $zentyalGroup->users();
        foreach my $zentyalMember (@{$zentyalMembers}) {
            my $sambaUser = new EBox::Samba::User(samAccountName => $zentyalMember->get('uid'));
            push (@{$sambaMembersDNs}, $sambaUser->dn());
        }
        $sambaGroup->set('member', $sambaMembersDNs, 1);
        my $description = $zentyalGroup->get('description');
        if ($description) {
            $sambaGroup->set('description', $description, 1);
        } else {
            $sambaGroup->delete('description', 1);
        }
        my $mail = $zentyalGroup->get('mail');
        if ($mail) {
            $sambaGroup->set('mail', $mail, 1);
        } else {
            $sambaGroup->delete('mail', 1);
        }
        $sambaGroup->save();
    } otherwise {
        my ($error) = @_;
        EBox::error("Error modifying group: $error");
    };
}

sub _delGroup
{
    my ($self, $zentyalGroup) = @_;
    $self->_sambaReady() or
        return;

    my $dn = $zentyalGroup->dn();
    EBox::debug("Deleting group '$dn' from samba");
    try {
        my $samAccountName = $zentyalGroup->get('cn');
        my $sambaGroup = new EBox::Samba::Group(samAccountName => $samAccountName);
        return unless $sambaGroup->exists();
        $sambaGroup->deleteObject();

        # Remove group from shares ACLs
        my $shares = $self->{samba}->model('SambaShares');
        my $sharesIds = $shares->ids();
        foreach my $shareId (@{$sharesIds}) {
            my $shareRow = $shares->row($shareId);
            my $acls = $shareRow->subModel('access');
            my $aclsIds = $acls->ids();
            foreach my $aclId (@{$aclsIds}) {
                my $aclRow = $acls->row($aclId);
                my $type = $aclRow->elementByName('user_group');
                if ($type->selectedType() eq 'group' and
                    $type->printableValue() eq $samAccountName) {
                    $acls->removeRow($aclId);
                }
            }
        }
    } otherwise {
        my ($error) = @_;
        EBox::error("Error deleting group: $error");
    };
}

# User and group addons

# Method: _groupShareEnabled
#
#   Check if there is a share configured for the group
#
# Returns:
#
#   The share name or undef if it is not configured
#
sub _groupShareEnabled
{
    my ($self, $zentyalGroup) = @_;

    my $groupName = $zentyalGroup->get('cn');
    my $sharesModel = $self->{samba}->model('SambaShares');
    foreach my $id (@{$sharesModel->ids()}) {
        my $row = $sharesModel->row($id);
        my $shareName  = $row->valueByName('share');
        my $groupShare = $row->valueByName('groupShare');
        return $shareName if $groupShare eq $groupName;
    }

    return undef;
}

sub setGroupShare
{
    my ($self, $group, $shareName) = @_;

    if ((not defined $shareName) or ( $shareName =~ /^\s*$/)) {
        throw EBox::Exceptions::External("A name should be provided for the share.");
    }

    my $oldName = $self->_groupShareEnabled($group);
    return if ($oldName and $oldName eq $shareName);

    my $groupName = $group->get('cn');
    my $sharesModel = $self->{samba}->model('SambaShares');

    # Create or rename the share for the group
    my $row = $sharesModel->findValue(groupShare => $groupName);
    if ($row) {
        # Rename the share
        EBox::debug("Renaming the share for group '$groupName' from '$oldName' to '$shareName'");
        $row->elementByName('share')->setValue($shareName);
        $row->store();
    } else {
        # Add the share
        my %params = ( share => $shareName,
                       path_selected => 'zentyal',
                       zentyal => $shareName,
                       comment => "Share for group $groupName",
                       guest => 0,
                       groupShare => $groupName );
        EBox::debug("Adding share named '$shareName' for group '$groupName'");
        my $shareRowId = $sharesModel->addRow(%params, readOnly => 1, enabled => 1);
        my $shareRow = $sharesModel->row($shareRowId);
        # And set the access control
        my $accessModel = $shareRow->subModel('access');
        %params = ( user_group_selected => 'group',
                    group => $groupName,
                    permissions => 'readWrite' );
        $accessModel->addRow(%params);
    }
}

sub removeGroupShare
{
    my ($self, $zentyalGroup) = @_;

    my $groupName = $zentyalGroup->get('cn');
    my $sharesModel = $self->{samba}->model('SambaShares');
    my $row = $sharesModel->findValue(groupShare => $groupName);
    $sharesModel->removeRow($row->id()) if $row;
}

sub _groupAddOns
{
    my ($self, $zentyalGroup) = @_;

    return unless ($self->{samba}->configured() and
                   $self->{samba}->isEnabled() and
                   $self->{samba}->isProvisioned());

    my $share = $self->_groupShareEnabled($zentyalGroup);
    my $args =  {
        'groupname' => $zentyalGroup->dn(),
        'share'     => $share,
        'service'   => $self->{samba}->isEnabled(),
    };

    return {
        title => __('Sharing directory for this group'),
        path => '/samba/samba.mas',
        params => $args
       };
}

sub schemas
{
    return [
        EBox::Config::share() . '/zentyal-samba/zentyalsambalink.ldif',
    ];
}

sub multipleOUSupport
{
    return 1;
}

# Method: hiddenOUs
#
#   Returns the list of OUs to hide on the UI
#
sub hiddenOUs
{
    return [ 'Builtin' ];
}

1;
