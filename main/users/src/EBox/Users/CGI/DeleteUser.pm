# Copyright (C) 2008-2013 Zentyal S.L.
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

package EBox::Users::CGI::DeleteUser;
use base 'EBox::CGI::ClientPopupBase';

use EBox::Global;
use EBox::Users;
use EBox::Gettext;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new('template' => '/users/deluser.mas', @_);
    bless($self, $class);
    return $self;
}

sub _process
{
    my ($self) = @_;
    $self->{'title'} = __('Users');

    $self->_requireParam('dn', 'dn');

    my @args;
    
    my $dn = $self->unsafeParam('dn');
    my $user = new EBox::Users::User(dn => $dn);

    # Prevent deletion of users Administrator, Guest
    my $samba = EBox::Global->modInstance('samba');
    my $sid = undef;
    if (defined ($samba)) {
        my $object = $samba->ldbObjectFromLDAPObject($user);
        if (defined ($object) and ($object->sid() =~ /^S-1-5-21-\d+-\d+-\d+-500$/)) {
            push (@args, 'forbid' => 1);
        }
        if (defined ($object) and ($object->sid() =~ /^S-1-5-21-\d+-\d+-\d+-501$/)) {
            push (@args, 'forbid' => 1);
        }
    }
    
    if ($self->unsafeParam('deluser')) {
        $self->{json} = { success => 0 };
        $user->deleteObject();
        $self->{json}->{success} = 1;
        $self->{json}->{redirect} = '/Users/Tree/Manage';
    } else {
        # show dialog
        my $usersandgroups = EBox::Global->getInstance()->modInstance('users');
        push(@args, 'user' => $user);
        my $editable = $usersandgroups->editableMode();
        push(@args, 'slave' => not $editable);
        my $warns = $usersandgroups->allWarnings('user', $user);
        push(@args, warns => $warns);
        $self->{params} = \@args;
    }


}



1;
