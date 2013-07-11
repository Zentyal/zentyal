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

package EBox::Ldap::Test;
use base 'EBox::Test::LDAPClass';

use EBox::Global::TestStub;

use Test::More;

sub class
{
    'EBox::Ldap'
}

sub instance : Test(3)
{
    my ($self) = @_;
    my $class = $self->class;

    can_ok($self, 'instance');

    my $ldapInstance = undef;
    ok($ldapInstance = $class->instance(), '... and the constructor should succeed');
    isa_ok($ldapInstance, $class, '... and the object it returns');
}

sub ldapCon : Test(4)
{
    my ($self) = @_;
    my $class = $self->class;

    my $ldapInstance = $class->instance();

    can_ok($ldapInstance, 'ldapCon');

    my $ldapCon = undef;
    ok($ldapCon = $ldapInstance->ldapCon(), 'Got the ldapConnection');
    isa_ok($ldapCon, 'Net::LDAP');
    isa_ok($ldapCon, 'Test::Net::LDAP::Mock');
}

1;

END {
    EBox::Ldap::Test->runtests();
}
