# Copyright (C) 2012 eBox Technologies S.L.
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

# Class: EBox::SysInfo::Model::HostName
#
#   This model is used to configure the host name and domain
#
package EBox::SysInfo::Model::HostName;
use base 'EBox::Model::DataForm';

use Error qw(:try);

use EBox::Gettext;
use EBox::SysInfo::Types::DomainName;
use EBox::Types::Host;

use Data::Validate::Domain qw(is_domain);

use constant RESOLV_FILE => '/etc/resolv.conf';

use constant MIN_HOSTNAME_LENGTH => 1;
use constant MAX_HOSTNAME_LENGTH => 15;

use constant MIN_HOSTDOMAIN_LENGTH => 2;
use constant MAX_HOSTDOMAIN_LENGTH => 64 - 1 - MAX_HOSTNAME_LENGTH;

sub new
{
    my $class = shift;

    my $self = $class->SUPER::new(@_);
    bless ($self, $class);

    return $self;
}

sub _table
{
    my ($self) = @_;

    my @tableHead = (new EBox::Types::Host( fieldName     => 'hostname',
                                            printableName => __('Hostname'),
                                            defaultValue  => \&_getHostname,
                                            editable      => 1),

                     new EBox::SysInfo::Types::DomainName( fieldName     => 'hostdomain',
                                                           printableName => __('Domain'),
                                                           defaultValue  => \&_getHostdomain,
                                                           editable      => 1,
                                                           help          => __('You will need to restart all the services or reboot the system to apply the hostname change.')));

    my $dataTable =
    {
        'tableName' => 'HostName',
        'printableTableName' => __('Hostname and Domain'),
        'modelDomain' => 'SysInfo',
        'defaultActions' => [ 'editField' ],
        'tableDescription' => \@tableHead,
        'confirmationDialog' => {
              submit => sub {
                  my ($self, $params) = @_;
                  my $newHostname   = $params->{hostname};
                  my $oldHostname   = $self->value('hostname');
                  my $newHostdomain   = $params->{hostdomain};
                  my $oldHostdomain   = $self->value('hostdomain');
                  if (($newHostdomain eq $oldHostdomain) and ($newHostname eq $oldHostname))  {
                      # only dialog if it is a hostname or hostdomain change
                      return undef;
                  }


                  my $title = __('Change hostname');
                  my $msg = __x('Are you sure you want to change the hostname to {new}?. You may need to restart all the services or reboot the system to enforce the change',
                              new => $newHostname . '.' . $newHostdomain
                             );
                  if ($newHostdomain =~ m/\.local$/i) {
                      $msg .= q{<p>};
                      $msg .= __("Additionally, using a domain ending in '.local' can conflict with other protocols like zeroconf and is, in general, discouraged.");
                      $msg .= q{</p>}
                  }
                  return  {
                      title => $title,
                      message => $msg,
                     }
                 }
            }
    };

    return $dataTable;
}

sub badHostname
{
    my $shortHostname = _getHostname();
    my $longHostname = `hostname`;
    chomp $longHostname;

    my $msg;
    if ($shortHostname ne $longHostname) {
        if ($longHostname =~ m{\.}) {
            $msg = __x("Your hostname '{hn}' contain dots. This can cause problems with some services. Please, change your hostname",
                       hn => $longHostname);
        } else {
            $msg = __x("Your hostname has different short ('{sn}') and long  ('{ln}') names. This can cause problems with some services. Please, change your hostname",
                     sn => $shortHostname,
                     ln => $longHostname
             );
        }
    }
    return $msg;
}

sub _getHostname
{
    my $hostname = `hostname --short`;
    chomp ($hostname);
    return $hostname;
}

sub _getHostdomain
{
    my $options = {
        domain_allow_underscore => 1,
        domain_allow_single_label => 0,
        domain_private_tld => qr /^[a-zA-Z]+$/,
    };

    my $hostdomain = `hostname --domain`;
    chomp ($hostdomain);
    unless (is_domain($hostdomain, $options)) {
        my ($searchdomain) = @{_readResolv()};
        $hostdomain = $searchdomain if (is_domain($searchdomain, $options));
    }

    $hostdomain = 'zentyal-domain.lan' unless (is_domain($hostdomain, $options));

    return $hostdomain;
}

sub _readResolv
{
    my $resolvFH;
    unless (open ($resolvFH, RESOLV_FILE)) {
        EBox::warn ("Couldn't open " . RESOLV_FILE);
        return [];
    }

    my $searchdomain = undef;
    my @dns = ();
    for my $line (<$resolvFH>) {
        $line =~ s/^\s+//g;
        my @toks = split (/\s+/, $line);
        if ($toks[0] eq 'nameserver') {
            push (@dns, $toks[1]);
        } elsif ($toks[0] eq 'search') {
            $searchdomain = $toks[1];
        }
    }
    close ($resolvFH);

    return [$searchdomain, @dns];
}

sub validateTypedRow
{
    my ($self, $action, $changed, $all) = @_;

    my $oldHostName = $self->hostnameValue();
    my $newHostName = defined $changed->{hostname} ? $changed->{hostname}->value() : $all->{hostname}->value();

    my $oldDomainName = $self->hostdomainValue();
    my $newDomainName = defined $changed->{hostdomain} ? $changed->{hostdomain}->value() : $all->{hostdomain}->value();

    $self->_checkDNSName($newHostName, 'Host name');
    unless (length ($newHostName) >= MIN_HOSTNAME_LENGTH and
            length ($newHostName) <= MAX_HOSTNAME_LENGTH) {
        throw EBox::Exceptions::InvalidData(
            data => __('Host name'),
            value => $newHostName,
            advice => __x('The length must be between {min} and {max} characters',
                          min => MIN_HOSTNAME_LENGTH,
                          max => MAX_HOSTNAME_LENGTH));
    }

    foreach my $label (split (/\./, $newDomainName)) {
        $self->_checkDNSName($label, 'Host domain');
    }
    unless (length ($newDomainName) >= MIN_HOSTDOMAIN_LENGTH and
            length ($newDomainName) <= MAX_HOSTDOMAIN_LENGTH) {
        throw EBox::Exceptions::InvalidData(
            data => __('Host domain'),
            value => $newDomainName,
            advice => __x('The length must be between {min} and {max} characters',
                          min => MIN_HOSTDOMAIN_LENGTH,
                          max => MAX_HOSTDOMAIN_LENGTH));
    }

    # After our validation, notify observers that this value is about to change
    my $newFqdn = $newHostName . '.' . $newDomainName;
    my $oldFqdn = $oldHostName . '.' . $oldDomainName;

    my $domainChanged = $newDomainName ne $oldDomainName;
    my $hostNameChanged = $newHostName ne $oldHostName;
    my $global = EBox::Global->getInstance();
    my @observers = @{$global->modInstancesOfType('EBox::SysInfo::Observer')};
    foreach my $obs (@observers) {
        $obs->hostDomainChanged($oldDomainName, $newDomainName) if $domainChanged;
        $obs->hostNameChanged($oldHostName, $newHostName) if $hostNameChanged;
        $obs->fqdnChanged($oldFqdn, $newFqdn) if ($hostNameChanged or $domainChanged);
    }
}

sub _checkDNSName
{
    my ($self, $label, $type) = @_;

    unless ($label =~ m/[a-zA-Z0-9\-]+/) {
        throw EBox::Exceptions::InvalidData(
            data => __($type),
            value => $label,
            advice => __('DNS names can contain only alphabetical characters (a-z), ' .
                         'numeric characters (0-9) and the minus sign (-)'));
    }
}

sub updatedRowNotify
{
    my ($self, $row, $oldRow, $force) = @_;

    my $newHostName   = $self->row->valueByName('hostname');
    my $oldHostName   = defined $oldRow ? $oldRow->valueByName('hostname') : $newHostName;
    my $newDomainName = $self->row->valueByName('hostdomain');
    my $oldDomainName = defined $oldRow ? $oldRow->valueByName('hostdomain') : $newDomainName;
    my $newFqdn = $newHostName . '.' . $newDomainName;
    my $oldFqdn = $oldHostName . '.' . $oldDomainName;

    my $domainChanged = $newDomainName ne $oldDomainName;
    my $hostNameChanged = $newHostName ne $oldHostName;
    my $global = EBox::Global->getInstance();
    my @observers = @{$global->modInstancesOfType('EBox::SysInfo::Observer')};
    foreach my $obs (@observers) {
        $obs->hostDomainChangedDone($oldDomainName, $newDomainName) if $domainChanged;
        $obs->hostNameChangedDone($oldHostName, $newHostName) if $hostNameChanged;
        $obs->fqdnChangedDone($oldFqdn, $newFqdn);
    }
}

sub viewCustomizer
{
    my ($self) = @_;

    my $customizer = $self->SUPER::viewCustomizer();

    my $msg = $self->badHostname();
    my $type;
    if ($msg) {
        $type = 'error';
    } else {
        my $hostname = $self->value('hostname');
        if ( length ($hostname) <= MAX_HOSTNAME_LENGTH) {
            if (EBox::Global->modExists('samba')) {
                $msg = __('Your hostname has more than 15 characters. Its netbios name will be truncated.');
                $type = 'warning';
            }
        }
    }

    if ($msg) {
        $customizer->setPermanentMessage($msg, $type);
    }

    return $customizer;
}

1;
