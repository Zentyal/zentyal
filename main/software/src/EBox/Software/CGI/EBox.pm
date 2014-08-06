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

package EBox::Software::CGI::EBox;

use base 'EBox::CGI::ClientBase';

use EBox::Global;
use EBox::Gettext;
use TryCatch::Lite;

## arguments:
##  title [required]
sub new {
    my $class = shift;
    my $self;
    if (EBox::Global->first()) {
        $self = $class->SUPER::new('title' => __('Choose Zentyal packages to install'),
                'template' => 'software/ebox.mas',
                @_);
    } else {
        $self = $class->SUPER::new('title' => __('Zentyal components'),
                'template' => 'software/ebox.mas',
                @_);
    }
    bless($self, $class);
    return $self;
}

sub _process
{
    my ($self) = @_;

    my $software = EBox::Global->modInstance('software');

    my $updateList = 0;
    my $updateListError = 0;
    my $updateListErrorMsg = undef;
    if (defined($self->param('updatePkgs'))) {
        $updateList = 1;
        try {
            unless ($software->updatePkgList()) {
                $updateListError = 1;
            }
        } catch ($e) {
            $updateListError = 1;
            $updateListErrorMsg = "$e";
        }
    }

    my @pkgs = @{$software->listEBoxPkgs()};
    @pkgs = map { $_->{description} =~ s/^Zentyal - //; $_ } @pkgs;
    @pkgs = sort { $a->{description} cmp $b->{description} } @pkgs;

    my @bigpkgs = (
        { name => 'zentyal-samba', description => 'Domain Controller and File Sharing' },
        { name => 'zentyal-mail', description => 'Mail and Groupware' }
    );

    my @mediumpkgs = (
        { name => 'zentyal-dns', description => 'DNS Server' },
        { name => 'zentyal-dhcp', description => 'DHCP Server' },
        { name => 'zentyal-firewall', description => 'Firewall' }
    );

    my %filterpkgs = map { ("zentyal-$_") => 1 } qw(samba mail openchange sogo dns dhcp firewall network objects services ntp);

    my @array = ();
    push(@array, 'bigpkgs'     => \@bigpkgs);
    push(@array, 'mediumpkgs'  => \@mediumpkgs);
    push(@array, 'allpkgs'     => \@pkgs);
    push(@array, 'filterpkgs'     => \%filterpkgs);
    push(@array, 'updateStatus' => $software->updateStatus(1));
    push(@array, 'QAUpdates'    => $software->QAUpdates());
    push(@array, 'isOffice'     => $software->isInstalled('zentyal-office'));
    push(@array, 'isUtm'        => $software->isInstalled('zentyal-security'));
    push(@array, 'isInfrastructure'    => $software->isInstalled('zentyal-infrastructure'));
    push(@array, 'isGateway'    => $software->isInstalled('zentyal-gateway'));
    push(@array, 'isCommunication'    => $software->isInstalled('zentyal-communication'));
    push(@array, 'updateList'    => $updateList);
    push(@array, 'updateListError'    => $updateListError);
    push(@array, 'updateListErrorMsg'    => $updateListErrorMsg);
    push(@array, 'brokenPackages'     => $software->listBrokenPkgs());

    $self->{params} = \@array;
}

sub _menu
{
    my ($self) = @_;

    if (EBox::Global->first()) {
        my $software = EBox::Global->modInstance('software');
        return $software->firstTimeMenu(0);
    } else {
        return $self->SUPER::_menu(@_);
    }
}

sub _top
{
    my $self = shift;

    if (EBox::Global->first()) {
        return $self->_topNoAction();
    } else {
        return $self->SUPER::_top(@_);
    }
}

1;
