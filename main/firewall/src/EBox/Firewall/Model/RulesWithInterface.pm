# Copyright (C) 2012-2012 Zentyal S.L.
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

# Auxlilaire base class for firewall rules which use interface

use strict;
use warnings;

package EBox::Firewall::Model::RulesWithInterface;


sub interfacePopulateSub
{
    my ($self) = @_;
    my $global = $self->global();

    return sub {
        my $net = EBox::Global->modInstance('network');
        my $ifaces = $net->allIfaces();

        my @options;
        foreach my $iface (@{$ifaces}) {
            if ($iface =~ m/:/) {
                # viface ignoring
                next;
            }

            my $printableValue =  $net->ifaceAlias($iface);
            my @vifacesNames = @{ $net->vifaceNames($iface) };
            if (@vifacesNames) {
                $printableValue = join ', ', ($printableValue, @vifacesNames);
            }

            push(@options, { 'value' => $iface,
                             'printableValue' => $printableValue  });
        }

        return \@options;
    };
}

1;
