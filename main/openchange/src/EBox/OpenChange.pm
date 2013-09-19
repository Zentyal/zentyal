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

package EBox::OpenChange;

use base qw(EBox::Module::Service EBox::LdapModule);

use EBox::Gettext;
use EBox::Config;
use EBox::OpenChange::LdapUser;
use EBox::DBEngineFactory;
use String::Random;

use constant SOGO_PORT => 20000;
use constant SOGO_DEFAULT_PREFORK => 1;

use constant SOGO_DEFAULT_FILE => '/etc/default/sogo';
use constant SOGO_CONF_FILE => '/etc/sogo/sogo.conf';
use constant SOGO_PID_FILE => '/var/run/sogo/sogo.pid';
use constant SOGO_LOG_FILE => '/var/log/sogo/sogo.log';


# Method: _create
#
#   The constructor, instantiate module
#
sub _create
{
    my $class = shift;
    my $self = $class->SUPER::_create(name => 'openchange',
                                      printableName => 'OpenChange',
                                      @_);
    bless ($self, $class);
    return $self;
}

# Method: initialSetup
#
# Overrides:
#
#   EBox::Module::Base::initialSetup
#
sub initialSetup
{
    my ($self, $version) = @_;

    unless ($version) {
    }
}

# Method: enableActions
#
#   Override EBox::Module::Service::enableService to notify samba
#
sub enableService
{
    my ($self, $status) = @_;

    $self->SUPER::enableService($status);
    if ($self->changed()) {
        # Mark mail as changed to make dovecot listen IMAP protocol at least
        # on localhost
        my $mail = $self->global->modInstance('mail');
        $mail->setAsChanged();

        # Mark samba as changed to write smb.conf
        my $samba = $self->global->modInstance('samba');
        $samba->setAsChanged();
    }
}

sub _daemons
{
    my ($self) = @_;

    my $daemons = [];
    push (@{$daemons}, {
        name => 'sogo',
        type => 'init.d',
        precondition => sub { $self->isProvisioned() },
        pidfiles => [SOGO_PID_FILE]});
    return $daemons;
}

sub usedFiles
{
    my $files = [];

    my $sogoDefaultFile = {
        file => SOGO_DEFAULT_FILE,
        reason => __('To configure sogo daemon'),
        module => 'openchange'
    };

    my $sogoConfFile = {
        file => SOGO_CONF_FILE,
        reason => __('To configure sogo parameters'),
        module => 'openchange'
    };

    push (@{$files}, $sogoDefaultFile);
    push (@{$files}, $sogoConfFile);

    return $files;
}

sub _setConf
{
    my ($self) = @_;

    $self->_writeSOGoDefaultFile();
    $self->_writeSOGoConfFile();
    $self->_setupSOGoDatabase();
    $self->_enableInnoDBIfNeeded();
}

sub _writeSOGoDefaultFile
{
    my ($self) = @_;

    my $array = [];
    my $prefork = EBox::Config::configkey('sogod_prefork');
    unless (length $prefork) {
        $prefork = SOGO_DEFAULT_PREFORK;
    }
    push (@{$array}, prefork => $prefork);
    $self->writeConfFile(SOGO_DEFAULT_FILE,
        'openchange/sogo.mas',
        $array, { uid => 0, gid => 0, mode => '755' });
}

sub _writeSOGoConfFile
{
    my ($self) = @_;

    my $array = [];

    my $sysinfo = $self->global->modInstance('sysinfo');
    my $timezoneModel = $sysinfo->model('TimeZone');
    my $sogoTimeZone = $timezoneModel->row->printableValueByName('timezone');

    my $samba = $self->global->modInstance('samba');
    my $dcHostName = $samba->ldb->rootDse->get_value('dnsHostName');
    my (undef, $sogoMailDomain) = split (/\./, $dcHostName, 2);

    push (@{$array}, sogoPort => SOGO_PORT);
    push (@{$array}, sogoLogFile => SOGO_LOG_FILE);
    push (@{$array}, sogoPidFile => SOGO_PID_FILE);
    push (@{$array}, sogoTimeZone => $sogoTimeZone);
    push (@{$array}, sogoMailDomain => $sogoMailDomain);

    my $mail = $self->global->modInstance('mail');
    my $retrievalServices = $mail->model('RetrievalServices');
    my $sieveEnabled = $retrievalServices->value('managesieve');
    my $sieveServer = ($sieveEnabled ? 'sieve://127.0.0.1:4190' : '');
    my $imapServer = '127.0.0.1:143';
    my $smtpServer = '127.0.0.1:25';
    push (@{$array}, imapServer => $imapServer);
    push (@{$array}, smtpServer => $smtpServer);
    push (@{$array}, sieveServer => $sieveServer);

    my $dbName = $self->_sogoDbName();
    my $dbUser = $self->_sogoDbUser();
    my $dbPass = $self->_sogoDbPass();
    push (@{$array}, dbName => $dbName);
    push (@{$array}, dbUser => $dbUser);
    push (@{$array}, dbPass => $dbPass);
    push (@{$array}, dbHost => '127.0.0.1');
    push (@{$array}, dbPort => 3306);

    push (@{$array}, ldapBaseDN => $self->ldap->dn());
    push (@{$array}, ldapBindDN => $self->ldap->roRootDn());
    push (@{$array}, ldapBindPwd => $self->ldap->getRoPassword());
    push (@{$array}, ldapHost => $self->ldap->LDAPI());

    my (undef, undef, undef, $gid) = getpwnam('sogo');
    $self->writeConfFile(SOGO_CONF_FILE,
        'openchange/sogo.conf.mas',
        $array, { uid => 0, gid => $gid, mode => '640' });
}

sub _setupSOGoDatabase
{
    my ($self) = @_;

    my $dbUser = $self->_sogoDbUser();
    my $dbPass = $self->_sogoDbPass();
    my $dbName = $self->_sogoDbName();
    my $dbHost = '127.0.0.1';

    my $db = EBox::DBEngineFactory::DBEngine();
    $db->sqlAsSuperuser(sql => "CREATE DATABASE IF NOT EXISTS $dbName");
    $db->sqlAsSuperuser(sql => "GRANT ALL ON $dbName.* TO $dbUser\@$dbHost " .
                               "IDENTIFIED BY \"$dbPass\";");
    $db->sqlAsSuperuser(sql => 'flush privileges;');
}

sub _enableInnoDBIfNeeded
{
    my ($self) = @_;

    if (system ("mysql -e \"SHOW VARIABLES LIKE 'have_innodb'\" | grep -q DISABLED") == 0) {
        EBox::Sudo::root(
            "sed -i 's/innodb = off/innodb = on/' /etc/mysql/conf.d/zentyal.cnf",
            "restart mysql"
        );
    }
}

# Method: menu
#
#   Add an entry to the menu with this module.
#
sub menu
{
    my ($self, $root) = @_;

    my $separator = 'Communications';
    my $order = 900;

    my $folder = new EBox::Menu::Folder(
        name => 'OpenChange',
        icon => 'openchange',
        text => $self->printableName(),
        separator => $separator,
        order => $order);
    $folder->add(new EBox::Menu::Item(
        url       => 'OpenChange/View/Provision',
        text      => __('Provision'),
        order     => 0));
    $root->add($folder);
}

sub _ldapModImplementation
{
    return new EBox::OpenChange::LdapUser();
}

sub isProvisioned
{
    my ($self) = @_;

    my $state = $self->get_state();
    my $provisioned = $state->{isProvisioned};
    if (defined $provisioned and $provisioned) {
        return 1;
    }
    return 0;
}

sub setProvisioned
{
    my ($self, $provisioned) = @_;

    my $state = $self->get_state();
    $state->{isProvisioned} = $provisioned;
    $self->set_state($state);
}

sub _sogoDbName
{
    my ($self) = @_;

    return 'sogo';
}

sub _sogoDbUser
{
    my ($self) = @_;

    my $dbUser = EBox::Config::configkey('sogo_dbuser');
    return (length $dbUser > 0 ? $dbUser : 'sogo');
}

sub _sogoDbPass
{
    my ($self) = @_;

    # Return value if cached
    if (defined $self->{sogo_db_password}) {
        return $self->{sogo_db_password};
    }

    # Cache and return value if user configured
    my $dbPass = EBox::Config::configkey('sogo_dbpass');
    if (length $dbPass) {
        $self->{sogo_db_password} = $dbPass;
        return $dbPass;
    }

    # Otherwise, read from file
    my $path = EBox::Config::conf() . "sogo_db.passwd";

    # If file does not exists, generate random password and stash to file
    if (not -f $path) {
        my $generator = new String::Random();
        my $pass = $generator->randregex('\w\w\w\w\w\w\w\w');

        my ($login, $password, $uid, $gid) = getpwnam(EBox::Config::user());
        EBox::Module::Base::writeFile($path, $pass,
            { mode => '0600', uid => $uid, gid => $gid });
        $self->{sogo_db_password} = $pass;
        return $pass;
    }

    unless (defined ($self->{sogo_db_password})) {
        open (PASSWD, $path) or
            throw EBox::Exceptions::External('Could not get SOGo DB password');
        my $pwd = <PASSWD>;
        close (PASSWD);

        $pwd =~ s/[\n\r]//g;
        $self->{sogo_db_password} = $pwd;
    }

    return $self->{sogo_db_password};
}

1;
