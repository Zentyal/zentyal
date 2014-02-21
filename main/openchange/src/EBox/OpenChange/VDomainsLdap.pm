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

package EBox::OpenChange::VDomainsLdap;
use base qw(EBox::LdapVDomainBase);

use EBox::Gettext;

sub new
{
    my ($class, $openchangeMod) = @_;
    my $self  = { openchangeMod => $openchangeMod };
    bless($self, $class);
    return $self;
}

sub _delVDomainAbort
{
    my ($self, $vdomain) = @_;
    if (not $self->{openchangeMod}->isProvisioned()) {
        # no outgoing domain really set
        return;
    }

    my $outgoing  = $self->{openchangeMod}->model('Provision')->outgoingDomain();
    if ($vdomain eq $outgoing) {
        throw EBox::Exceptions::External(
            __x('The virtual mail domain {dom} cannot  be removed because is openchange outgoing domain', dom => $vdomain)
           );
    }

}

1;
