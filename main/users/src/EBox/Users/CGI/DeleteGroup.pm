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

package EBox::Users::CGI::DeleteGroup;

use base 'EBox::CGI::ClientPopupBase';

use EBox::Global;
use EBox::Users;
use EBox::Gettext;

sub new
{
    my $class = shift;
    my $self = $class->SUPER::new('template' => '/users/delgroup.mas', @_);
    bless($self, $class);
    return $self;
}

sub _process
{
    my ($self) = @_;

    $self->_requireParam('dn', 'dn');

    my $dn = $self->unsafeParam('dn');
    my $group = new EBox::Users::Group(dn => $dn);

    if ($self->unsafeParam('delgroup')) {
        $self->{json} = { success => 0 };
        $group->deleteObject();
        $self->{json}->{success} = 1;
        $self->{json}->{redirect} = '/Users/Tree/Manage';
    } else {
        # show confirmation dialog
        my @args;
        my $users = EBox::Global->getInstance()->modInstance('users');
        push(@args, 'group' => $group);
        my $editable = $users->editableMode();
        push(@args, 'slave' => not $editable);
        my $warns = $users->allWarnings('group', $group);
        push(@args, warns => $warns);
        $self->{params} = \@args;
    }
}

1;
