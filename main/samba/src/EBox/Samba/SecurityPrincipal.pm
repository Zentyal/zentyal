# Copyright (C) 2013 Zentyal S.L.
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

# Class: EBox::Samba::SecurityPrincipal
#
#   This class is an abstraction for LDAP objects implementing the
#   SecurityPrincipal auxiliary class
#
package EBox::Samba::SecurityPrincipal;

use base 'EBox::Samba::OrganizationalPerson';

# Method: new
#
#   Class constructor
#
# Parameters:
#
#      samAccountName
#  or
#      SID
#
sub new
{
    my ($class, %params) = @_;

    unless ($params{entry} or $params{dn} or $params{ldif} or
            $params{samAccountName} or $params{sid}) {
        throw EBox::Exceptions::MissingArgument('Constructor argument');
    }

    my $self = {};
    if ($params{samAccountName}) {
        $self->{samAccountName} = $params{samAccountName};
    } elsif ($params{sid}) {
        $self->{sid} = $params{sid};
    } else {
        $self = $class->SUPER::new(%params);
    }
    bless ($self, $class);

    return $self;
}

# Method: _entry
#
#   Return Net::LDAP::Entry entry for the object
#
sub _entry
{
    my ($self) = @_;

    unless ($self->{entry}) {
        my $result = undef;
        if (defined $self->{samAccountName}) {
            my $attrs = {
                base => $self->_ldap->dn(),
                filter => "(samAccountName=$self->{samAccountName})",
                scope => 'sub',
                attrs => ['*', 'unicodePwd', 'supplementalCredentials'],
            };
            $result = $self->_ldap->search($attrs);
        } elsif (defined $self->{sid}) {
            my $attrs = {
                base => $self->_ldap->dn(),
                filter => "(objectSid=$self->{sid})",
                scope => 'sub',
                attrs => ['*', 'unicodePwd', 'supplementalCredentials'],
            };
            $result = $self->_ldap->search($attrs);
        } else {
            return $self->SUPER::_entry();
        }
        return undef unless defined $result;

        if ($result->count() > 1) {
            throw EBox::Exceptions::Internal(
                __x('Found {count} results for, expected only one.',
                    count => $result->count()));
        }

        $self->{entry} = $result->entry(0);
    }

    return $self->{entry};
}

sub sid
{
    my ($self) = @_;

    my $sid = $self->get('objectSid');
    my $sidString = $self->_sidToString($sid);
    return $sidString;
}

sub _sidToString
{
    my ($self, $sid) = @_;

    return undef
        unless unpack("C", substr($sid, 0, 1)) == 1;

    return undef
        unless length($sid) == 8 + 4 * unpack("C", substr($sid, 1, 1));

    my $sid_str = "S-1-";

    $sid_str .= (unpack("C", substr($sid, 7, 1)) +
                (unpack("C", substr($sid, 6, 1)) << 8) +
                (unpack("C", substr($sid, 5, 1)) << 16) +
                (unpack("C", substr($sid, 4, 1)) << 24));

    for my $loop (0 .. unpack("C", substr($sid, 1, 1)) - 1) {
        $sid_str .= "-" . unpack("I", substr($sid, 4 * $loop + 8, 4));
    }

    return $sid_str;
}

sub _stringToSid
{
    my ($self, $sidString) = @_;

    return undef
        unless uc(substr($sidString, 0, 4)) eq "S-1-";

    my ($auth_id, @sub_auth_id) = split(/-/, substr($sidString, 4));

    my $sid = pack("C4", 1, $#sub_auth_id + 1, 0, 0);

    $sid .= pack("C4", ($auth_id & 0xff000000) >> 24, ($auth_id &0x00ff0000) >> 16,
            ($auth_id & 0x0000ff00) >> 8, $auth_id &0x000000ff);

    for my $loop (0 .. $#sub_auth_id) {
        $sid .= pack("I", $sub_auth_id[$loop]);
    }

    return $sid;
}

sub _checkAccountName
{
    my ($self, $name, $maxLength) = @_;

    my $advice = undef;

    if ($name =~ m/\.$/) {
        $advice = __('Windows account names cannot end with a dot');
    } elsif ($name =~ m/^-/) {
        $advice = __('Windows account names cannot start with a dash');
    } elsif (not $name =~ /^[a-zA-Z\d\s_\-\.]+$/) {
        $advice = __('To avoid problems, the account name should ' .
                     'consist only of letters, digits, underscores, ' .
                      'spaces, periods, and dashes'
               );
    } elsif (length ($name) > $maxLength) {
        $advice = __x("Account name must not be longer than {maxLength} characters",
                       maxLength => $maxLength);
    }

    if ($advice) {
        throw EBox::Exceptions::InvalidData(
                'data' => __('account name'),
                'value' => $name,
                'advice' => $advice);
    }
}

sub _checkAccountNotExists
{
    my ($self, $samAccountName) = @_;

    my $obj = new EBox::Samba::LdbObject(samAccountName => $samAccountName);
    if ($obj->exists()) {
        my $dn = $obj->dn();
        throw EBox::Exceptions::DataExists(
            'data' => __('Account name'),
            'value' => "$samAccountName ($dn)");
    }
}

sub getXidNumberFromRID
{
    my ($self) = @_;

    my $sid = $self->sid();
    my $rid = (split (/-/, $sid))[7];

    return $rid + 50000;
}

1;
