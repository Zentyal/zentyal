# Copyright (C) 2013 Zentyal S. L.
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

package EBox::OpenChange::Model::Provision;

use base 'EBox::Model::DataForm';

use EBox::Gettext;
use EBox::DBEngineFactory;
use EBox::MailUserLdap;
use EBox::Types::Text;
use EBox::Types::Select;
use EBox::Types::MultiStateAction;
use EBox::Types::Action;
use EBox::Samba::User;
use EBox::Exceptions::NotImplemented;

use Error qw( :try );

# Method: new
#
#   Constructor, instantiate new model
#
sub new
{
    my $class = shift;

    my $self = $class->SUPER::new(@_);
    bless ($self, $class);

    return $self;
}

# Method: _table
#
#   Returns model description
#
sub _table
{
    my ($self) = @_;

    my $tableDesc = [
        new EBox::Types::Select(
            fieldName => 'mode',
            printableName => __('Provision type'),
            editable => sub { $self->parentModule->isEnabled() and
                              not $self->parentModule->isProvisioned() },
            populate => \&_modeOptions),
        new EBox::Types::Text(
            fieldName => 'firstorganization',
            printableName => __('First Organization'),
            defaultValue => 'First Organization',
            editable => sub { $self->parentModule->isEnabled() and
                              not $self->parentModule->isProvisioned() }),
        new EBox::Types::Text(
            fieldName => 'firstorganizationunit',
            printableName => __('First Organization Unit'),
            defaultValue => 'First Organization Unit',
            editable => sub { $self->parentModule->isEnabled() and
                              not $self->parentModule->isProvisioned() }),
        new EBox::Types::Boolean(
            fieldName => 'enableUsers',
            printableName => __('Enable all users after provision'),
            defaultValue => 1,
            editable => sub { $self->parentModule->isEnabled() and
                              not $self->parentModule->isProvisioned() }),
        new EBox::Types::Boolean(
            fieldName => 'registerAsMain',
            printableName => __('Set this server as the primary server'),
            defaultValue => 0,
            editable => sub { $self->parentModule->isEnabled() and
                              not $self->parentModule->isProvisioned() }),
    ];

    my $customActions = [
        new EBox::Types::MultiStateAction(
            acquirer => \&_acquireProvisioned,
            model => $self,
            states => {
                provisioned => {
                    name => 'deprovision',
                    printableValue => __('Deprovision'),
                    handler => \&_doDeprovision,
                    message => __('Database deprovisioned'),
                    enabled => sub { $self->parentModule->isEnabled() },
                },
                notProvisioned => {
                    name => 'provision',
                    printableValue => __('Provision'),
                    handler => \&_doProvision,
                    message => __('Database provisioned'),
                    enabled => sub { $self->parentModule->isEnabled() },
                },
            }
        ),
    ];


    my $dataForm = {
        tableName          => 'Provision',
        printableTableName => __('Provision'),
        pageTitle          => __('OpenChange Server Provision'),
        modelDomain        => 'OpenChange',
        #defaultActions     => [ 'editField' ],
        customActions      => $customActions,
        tableDescription   => $tableDesc,
        # FIXME help               => __(''),
    };

    return $dataForm;
}

# Method: precondition
#
#   Check samba is configured and provisioned
#
sub precondition
{
    my ($self) = @_;

    my $samba = $self->global->modInstance('samba');
    unless ($samba->configured()) {
        $self->{preconditionFail} = 'notConfigured';
        return undef;
    }
    unless ($samba->isProvisioned()) {
        $self->{preconditionFail} = 'notProvisioned';
        return undef;
    }
    unless ($self->parentModule->isEnabled()) {
        $self->{preconditionFail} = 'notEnabled';
        return undef;
    }

    # Check the samba domain is present in the Mail Virtual Domains model
    my $mailModule = $self->global->modInstance('mail');
    my $VDomainsModel = $mailModule->model('VDomains');
    my $adDomain = $samba->getProvision->getADDomain('localhost');
    my $adDomainFound = 0;
    foreach my $id (@{$VDomainsModel->ids()}) {
        my $row = $VDomainsModel->row($id);
        my $vdomain = $row->valueByName('vdomain');
        if (lc $vdomain eq lc $adDomain) {
            $adDomainFound = 1;
            last;
        }
    }
    unless ($adDomainFound) {
        $self->{preconditionFail} = 'vdomainNotFound';
        return undef;
    }

    # Check there are not unsaved changes
    if ($self->global->unsaved()) {
        $self->{preconditionFail} = 'unsavedChanges';
        return undef;
    }

    return 1;
}

# Method: preconditionFailMsg
#
#   Show the precondition failure message
#
sub preconditionFailMsg
{
    my ($self) = @_;

    if ($self->{preconditionFail} eq 'notConfigured') {
        my $samba = EBox::Global->modInstance('samba');
        return __x('You must enable the {x} module in the module ' .
                  'status section before provisioning {y} module database.',
                  x => $samba->printableName(),
                  y => $self->parentModule->printableName());
    }
    if ($self->{preconditionFail} eq 'notProvisioned') {
        my $samba = $self->global->modInstance('samba');
        return __x('You must provision the {x} module database before ' .
                  'provisioning the {y} module database.',
                  x => $samba->printableName(),
                  y => $self->parentModule->printableName());
    }
    if ($self->{preconditionFail} eq 'notEnabled') {
        return __x('You must enable the {x} module before provision the ' .
                   'database', x => $self->parentModule->printableName());
    }
    if ($self->{preconditionFail} eq 'vdomainNotFound') {
        my $samba = $self->global->modInstance('samba');
        return __x('The virtual domain {x} is not defined. You can add ' .
                   'it in the {ohref}Virtual Domains page{chref}.',
                   x => $samba->getProvision->getADDomain('localhost'),
                   ohref => "<a href='/Mail/View/VDomains'>",
                   chref => '</a>');
    }
    if ($self->{preconditionFail} eq 'unsavedChanges') {
        return __x('There are unsaved changes. Please save them before '.
                   'provision');
    }
}

sub viewCustomizer
{
    my ($self) = @_;

    my $customizer = new EBox::View::Customizer();
    $customizer->setModel($self);

    my $standaloneParams = [qw/dn/];
    my $adParams = [qw/dcHostname dcUser dcPassword dcPassword2/];

    my $onChange = {
        mode => {
            first => {
                show => ['firstorganization', 'firstorganizationunit', 'enableUsers'],
                hide => ['registerAsMain'],
            },
            additional => {
                show => ['registerAsMain'],
                hide => ['firstorganization', 'firstorganizationunit', 'enableUsers'],
            },
        },
    };
    $customizer->setOnChangeActions($onChange);
    return $customizer;
}

sub _modeOptions
{
    my ($self) = @_;

    my $modes = [];

    push (@{$modes}, {value => 'first', printableValue => __('First Exchange Server') });
    push (@{$modes}, {value => 'additional', printableValue => __('Additional Exchange Server') });

    return $modes;
}

sub _acquireProvisioned
{
    my ($self, $id) = @_;

    my $provisioned = $self->parentModule->isProvisioned();
    return ($provisioned) ? 'provisioned' : 'notProvisioned';
}

sub _doProvisionAdditional
{
    my ($self, $action, $id, %params) = @_;

    my $registerAsMain = $params{registerAsMain};
    try {
        my $cmd = '/opt/samba4/sbin/openchange_provision --additional';
        if ($registerAsMain) {
            $cmd .= ' --primary-server ';
        }
        my $output = EBox::Sudo::root($cmd);
        EBox::debug(join('', @{$output}));

        $cmd = '/opt/samba4/sbin/openchange_provision --openchangedb';
        $output = EBox::Sudo::root($cmd);
        EBox::debug(join('', @{$output}));

        $self->parentModule->setProvisioned(1);
        $self->setMessage($action->message(), 'note');
    } otherwise {
        my ($error) = @_;

        throw EBox::Exceptions::External("Error provisioninig: $error");
        $self->parentModule->setProvisioned(0);
    } finally {
        $self->global->modChange('mail');
        $self->global->modChange('samba');
        $self->global->modChange('openchange');
    };
}

sub _doProvision
{
    my ($self, $action, $id, %params) = @_;

    my $mode = $params{mode};
    my $firstOrganization = $params{firstorganization};
    my $firstOrganizationUnit = $params{firstorganizationunit};
    my $enableUsers = $params{enableUsers};

    $self->setValue('mode', $mode);
    $self->setValue('firstorganization', $firstOrganization);
    $self->setValue('firstorganizationunit', $firstOrganizationUnit);
    $self->setValue('enableUsers', $enableUsers);

    if ($mode eq 'additional') {
        $self->_doProvisionAdditional($action, $id, %params);
        return;
    }

    try {
        my $cmd = '/opt/samba4/sbin/openchange_provision ' .
                  "--standalone " .
                  "--firstorg='$firstOrganization' " .
                  "--firstou='$firstOrganizationUnit' ";
        my $output = EBox::Sudo::root($cmd);
        $output = join('', @{$output});

        $cmd = '/opt/samba4/sbin/openchange_provision --openchangedb';
        my $output2 = EBox::Sudo::root($cmd);
        $output .= "\n" . join('', @{$output2});

        $self->parentModule->setProvisioned(1);
        EBox::info("Openchange provisioned:\n$output");
        $self->setMessage($action->message(), 'note');
    } otherwise {
        my ($error) = @_;

        $self->parentModule->setProvisioned(0);
        throw EBox::Exceptions::External("Error provisioninig: $error");
    } finally {
        $self->global->modChange('mail');
        $self->global->modChange('samba');
        $self->global->modChange('openchange');
    };

    if ($enableUsers) {
        my $mailUserLdap = new EBox::MailUserLdap();
        my $sambaModule = $self->global->modInstance('samba');
        my $adDomain = $sambaModule->getProvision->getADDomain('localhost');
        my $usersModule = $self->global->modInstance('users');
        my $users = $usersModule->users();
        foreach my $ldapUser (@{$users}) {
            my $samAccountName = undef;
            try {
                $samAccountName = $ldapUser->get('uid');
                next unless defined $samAccountName;

                my $ldbUser = new EBox::Samba::User(
                    samAccountName => $samAccountName);
                next unless $ldbUser->exists();

                my $critical = $ldbUser->get('isCriticalSystemObject');
                next if (defined $critical and $critical eq 'TRUE');

                # Skip users with already defined mailbox
                my $mailbox = $ldapUser->get('mailbox');
                unless (defined $mailbox and length $mailbox) {
                    EBox::info("Creating user '$samAccountName' mailbox");
                    # Call API to create mailbox in zentyal
                    $mailUserLdap->setUserAccount($ldapUser,
                                                  $ldapUser->get('uid'),
                                                  $adDomain);
                }

                # Skip already enabled users
                my $ac = $ldbUser->get('msExchUserAccountControl');
                unless (defined $ac and $ac == 0) {
                    my $cmd = "/opt/samba4/sbin/openchange_newuser ";
                    $cmd .= " --create " if (not defined $ac);
                    $cmd .= " --enable '$samAccountName' ";
                    my $output = EBox::Sudo::root($cmd);
                    $output = join('', @{$output});
                    EBox::info("Enabling user '$samAccountName':\n$output");
                }
            } otherwise {
                my ($error) = @_;
                EBox::error("Error enabling user $samAccountName: $error");
                # Try next user
            };
        }
    }
}

sub _doDeprovision
{
    my ($self, $action, $id, %params) = @_;

    try {
        my $cmd = '/opt/samba4/sbin/openchange_provision ' .
                  '--deprovision';
        my $output = EBox::Sudo::root($cmd);
        $output = join('', @{$output});

        $cmd = 'rm -rf /opt/samba4/private/openchange.ldb';
        my $output2 = EBox::Sudo::root($cmd);
        $output .= "\n" . join('', @{$output2});

        # Drop SOGo database and db user. To avoid error if it does not exists,
        # the user is created and granted harmless privileges before drop it
        my $db = EBox::DBEngineFactory::DBEngine();
        my $dbName = $self->parentModule->_sogoDbName();
        my $dbUser = $self->parentModule->_sogoDbUser();
        $db->sqlAsSuperuser(sql => "DROP DATABASE IF EXISTS $dbName");
        $db->sqlAsSuperuser(sql => "GRANT USAGE ON *.* TO $dbUser");
        $db->sqlAsSuperuser(sql => "DROP USER $dbUser");

        $self->parentModule->setProvisioned(0);
        EBox::info("Openchange deprovisioned:\n$output");
        $self->setMessage($action->message(), 'note');
    } otherwise {
        my ($error) = @_;

        throw EBox::Exceptions::External("Error deprovisioninig: $error");
        $self->parentModule->setProvisioned(1);
    } finally {
        $self->global->modChange('mail');
        $self->global->modChange('samba');
        $self->global->modChange('openchange');
    };
}

1;
