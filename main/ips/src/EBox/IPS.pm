# Copyright (C) 2009-2013 eBox Technologies S.L.
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

# Class: EBox::IPS
#
#      Class description
#

package EBox::IPS;

use strict;
use warnings;

use base qw(EBox::Module::Service EBox::LogObserver EBox::FirewallObserver);

use Error qw(:try);

use EBox::Gettext;
use EBox::Service;
use EBox::Sudo;
use EBox::Exceptions::Internal;
use EBox::Exceptions::Sudo::Command;
use EBox::IPS::LogHelper;
use EBox::IPS::FirewallHelper;
use List::Util;

use constant SURICATA_CONF_FILE => '/etc/suricata/suricata-debian.yaml';
use constant SURICATA_DEFAULT_FILE => '/etc/default/suricata';
use constant SURICATA_INIT_FILE => '/etc/init/zentyal.suricata.conf';
use constant SNORT_RULES_DIR => '/etc/snort/rules';
use constant SURICATA_RULES_DIR => '/etc/suricata/rules';

# Group: Protected methods

# Constructor: _create
#
#        Create an module
#
# Overrides:
#
#        <EBox::Module::Service::_create>
#
# Returns:
#
#        <EBox::IPS> - the recently created module
#
sub _create
{
    my $class = shift;
    my $self = $class->SUPER::_create(name => 'ips',
                                      printableName => __('IDS/IPS'),
                                      @_);
    bless($self, $class);
    return $self;
}

# Method: _daemons
#
# Overrides:
#
#       <EBox::Module::Service::_daemons>
#
sub _daemons
{
    return [
        {
         'name' => 'zentyal.suricata',
         'precondition' => \&_suricataNeeded,
        }
    ];
}

# Method: _suricataNeeded
#
#     Returns true if there are interfaces to listen, false otherwise.
#
sub _suricataNeeded
{
    my ($self) = @_;

    return (@{$self->enabledIfaces()} > 0);
}

# Method: enabledIfaces
#
#   Returns array reference with the enabled interfaces that
#   are not unset or trunk.
#
sub enabledIfaces
{
    my ($self) = @_;

    my $net = EBox::Global->modInstance('network');
    my $ifacesModel = $self->model('Interfaces');
    my @ifaces;
    foreach my $row (@{$ifacesModel->enabledRows()}) {
        my $iface = $ifacesModel->row($row)->valueByName('iface');
        my $method = $net->ifaceMethod($iface);
        next if ($method eq 'notset' or $method eq 'trunk');
        push (@ifaces, $iface);
    }

    return \@ifaces;
}

# Method: nfQueueNum
#
#     Get the NFQueue number for perform inline IPS.
#
# Returns:
#
#     Int - between 0 and 65535
#
# Exceptions:
#
#     <EBox::Exceptions::Internal> - thrown if the value to return is
#     greater than 65535
#
sub nfQueueNum
{
    my ($self) = @_;

    # As l7filter may take as much as interfaces are up, a security
    # measure is set to + 10 of enabled interfaces
    my $netMod = $self->global()->modInstance('network');
    my $queueNum = scalar(@{$netMod->ifaces()}) + 10;
    if ( $queueNum > 65535 ) {
        throw EBox::Exceptions::Internal('There are too many interfaces to set a valid NFQUEUE number');
    }
    return $queueNum;
}

sub _setRules
{
    my ($self) = @_;

    my $snortDir = SNORT_RULES_DIR;
    my $suricataDir = SURICATA_RULES_DIR;
    my @cmds = ("mkdir -p $suricataDir", "rm -f $suricataDir/*");

    my $rulesModel = $self->model('Rules');
    my @rules;

    foreach my $id (@{$rulesModel->enabledRows()}) {
        my $row = $rulesModel->row($id);
        my $name = $row->valueByName('name');
        if ($self->usingASU()) {
            $name = "emerging-$name";
        }
        my $decision = $row->valueByName('decision');
        if ($decision =~ /log/) {
            push (@cmds, "cp $snortDir/$name.rules $suricataDir/");
            push (@rules, $name);
        }
        if ($decision =~ /block/) {
            push (@cmds, "cp $snortDir/$name.rules $suricataDir/$name-block.rules");
            push (@cmds, "sed -i 's/^alert /drop /g' $suricataDir/$name-block.rules");
            push (@rules, "$name-block");
        }
    }

    EBox::Sudo::root(@cmds);

    return \@rules;
}

# Method: _setConf
#
#        Regenerate the configuration
#
# Overrides:
#
#       <EBox::Module::Service::_setConf>
#
sub _setConf
{
    my ($self) = @_;

    my $rules = $self->_setRules();

    $self->writeConfFile(SURICATA_CONF_FILE, 'ips/suricata-debian.yaml.mas',
                         [ rules => $rules ]);

    $self->writeConfFile(SURICATA_DEFAULT_FILE, 'ips/suricata.mas',
                         [ enabled => $self->isEnabled() ]);

    $self->writeConfFile(SURICATA_INIT_FILE, 'ips/suricata.upstart.mas',
                         [ nfQueueNum => $self->nfQueueNum() ]);

}

# Group: Public methods

# Method: menu
#
#       Add an entry to the menu with this module
#
# Overrides:
#
#       <EBox::Module::menu>
#
sub menu
{
    my ($self, $root) = @_;
    $root->add(new EBox::Menu::Item('url' => 'IPS/Composite/General',
                                    'text' => $self->printableName(),
                                    'separator' => 'Gateway',
                                    'order' => 228));
}

# Method: usedFiles
#
#        Indicate which files are required to overwrite to configure
#        the module to work. Check overriden method for details
#
# Overrides:
#
#        <EBox::Module::Service::usedFiles>
#
sub usedFiles
{
    return [
        {
            'file' => SURICATA_CONF_FILE,
            'module' => 'ips',
            'reason' => __('Add rules to suricata configuration')
        },
        {
            'file' => SURICATA_DEFAULT_FILE,
            'module' => 'ips',
            'reason' => __('Enable start of suricata daemon')
        }
    ];
}

# Method: logHelper
#
# Overrides:
#
#       <EBox::LogObserver::logHelper>
#
sub logHelper
{
    my ($self) = @_;

    return (new EBox::IPS::LogHelper);
}

# Method: tableInfo
#
# Overrides:
#
#       <EBox::LogObserver::tableInfo>
#
sub tableInfo
{
    my ($self) = @_ ;

    my $titles = {
                  'timestamp'   => __('Date'),
                  'priority'    => __('Priority'),
                  'description' => __('Description'),
                  'source'      => __('Source'),
                  'dest'        => __('Destination'),
                  'protocol'    => __('Protocol'),
                  'event'       => __('Event'),
                 };

    my @order = qw(timestamp priority description source dest protocol event);

    return [{
            'name' => __('IPS'),
            'tablename' => 'ips_event',
            'titles' => $titles,
            'order' => \@order,
            'timecol' => 'timestamp',
            'events' => { 'alert' => __('Alert') },
            'eventcol' => 'event',
            'filter' => ['priority', 'description', 'source', 'dest'],
            'consolidate' => $self->_consolidate(),
           }];
}

sub _consolidate
{
    my ($self) = @_;

    my $table = 'ips_alert';

    my $spec = {
        accummulateColumns  => { alert => 0 },
        consolidateColumns => {
                                event => {
                                          conversor => sub { return 1; },
                                          accummulate => 'alert',
                                         },
                              },
    };

    return { $table => $spec };
}

# Method: usingASU
#
#    Get if the module is using ASU or not.
#
#    If a parameter is given, then it sets the value
#
# Parameters:
#
#    usingASU - Boolean Set if we are using ASU or not
#
# Returns:
#
#    Boolean - indicating whether we are using ASU or not
#
sub usingASU
{
    my ($self, $usingASU) = @_;

    my $key = 'using_asu';
    if (defined($usingASU)) {
        $self->st_set_bool($key, $usingASU);
    } else {
        if ( $self->st_entry_exists($key) ) {
            $usingASU = $self->st_get_bool($key);
        } else {
            # For now, checking emerging is in rules
            my $rulesDir = SNORT_RULES_DIR . '/';
            my @rules = <${rulesDir}emerging-*.rules>;
            $usingASU = (scalar(@rules) > 0);
        }
    }
    return $usingASU;
}

# Method: rulesNum
#
#     Get the number of available IPS rules
#
# Parameters:
#
#     force - Boolean indicating we are forcing to calculate again
#
# Returns:
#
#     Int - the number of available IPS rules
#
sub rulesNum
{
    my ($self, $force) = @_;

    my $key = 'rules_num';
    $force = 0 unless defined($force);

    my $rulesNum;
    if ( $force or (not $self->st_entry_exists($key)) ) {
        my @files;
        my $rulesDir = SNORT_RULES_DIR . '/';
        if ( $self->usingASU() ) {
            @files = <${rulesDir}emerging-*.rules>;
        } else {
            @files = <${rulesDir}*.rules>;
        }
        # Count the number of rules removing blank lines and comment lines
        my @numRules = map { `sed -e '/^#/d' -e '/^\$/d' $_ | wc -l` } @files;
        $rulesNum = List::Util::sum(@numRules);
        $self->st_set_int($key, $rulesNum);
    } else {
        $rulesNum = $self->st_get_int($key);
    }
    return $rulesNum;
}

sub firewallHelper
{
    my ($self) = @_;

    # TODO: check also if IPS mode is enabled
    if ($self->isEnabled()) {
        return EBox::IPS::FirewallHelper->new();
    }

    return undef;
}

1;
