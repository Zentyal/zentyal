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

package EBox::OpenChange::LdapUser;

use base qw(EBox::LdapUserBase);

use EBox::Global;
use EBox::Ldap;
use EBox::Gettext;
use EBox::Samba::User;

sub new
{
    my $class = shift;

    my $self  = {};
    $self->{ldap} = EBox::Ldap->instance();
    $self->{openchange} = EBox::Global->modInstance('openchange');

    bless ($self, $class);
    return $self;
}

sub _userAddOns
{
    my ($self, $user) = @_;

    unless ($self->{openchange}->configured() and
            $self->{openchange}->isProvisioned()) {
        return;
    }

    # If the user does not have a mailbox in the AD domain, do not show
    my $sambaModule = EBox::Global->modInstance('samba');
    my $adDomain = $sambaModule->getProvision->getADDomain('localhost');
    my $mail = $user->get('mail');
    unless (defined $mail and length $mail) {
        return;
    }
    my (undef, $mailDomain) = split (/@/, $mail);
    if (lc $mailDomain ne $adDomain) {
        return;
    }

    my $active = $self->enabled($user) ? 1 : 0;
    my $args = {
        user     => $user,
        active   => $active,
    };

    return {
        title =>  __('OpenChange Account'),
        path => '/openchange/openchange.mas',
        params => $args
    };
}

sub enabled
{
    my ($self, $user) = @_;

    my $samAccountName = $user->get('uid');
    my $ldbUser = new EBox::Samba::User(samAccountName => $samAccountName);
    unless ($ldbUser->exists()) {
        throw EBox::Exceptions::Internal(
            "LDB user '$samAccountName' does not exists");
    }

    my $msExchUserAccountControl = $ldbUser->get('msExchUserAccountControl');
    return 0 unless defined $msExchUserAccountControl;

    if (defined $msExchUserAccountControl and $msExchUserAccountControl == 2) {
        # Account disabled
        return 0;
    }
    if (defined $msExchUserAccountControl and $msExchUserAccountControl == 0) {
        # Account enabled
        return 1;
    }
    throw EBox::Exceptions::External(
        __x('Unknown value for msExchUserAccountControl: {x}',
            x => $msExchUserAccountControl));
}

sub setAccountEnabled
{
    my ($self, $ldapUser, $option) = @_;

    my $ldbUser = new EBox::Samba::User(samAccountName => $ldapUser->get('uid'));
    unless (defined $ldbUser and $ldbUser->exists()) {
        throw EBox::Exceptions::Internal("Cannot LDB instantiate user");
    }

    my $samAccountName = $ldbUser->get('samAccountName');
    my $msExchUserAccountControl = $ldbUser->get('msExchUserAccountControl');

    my $cmd = '/opt/samba4/sbin/openchange_newuser ';
    $cmd .= ' --create ' unless (defined $msExchUserAccountControl);
    if ($option) {
        $cmd .= ' --enable ';
    } else {
        $cmd .= ' --disable ';
    }
    $cmd .= " '$samAccountName' ";
    EBox::Sudo::root($cmd);

    return 0;
}

sub _addUser
{
    my ($self, $user, $password) = @_;

    unless ($self->{openchange}->configured() and
            $self->{openchange}->isProvisioned()) {
        return;
    }

    my $model = $self->{openchange}->model('OpenChangeUser');
    return unless ($model->enabledValue());

    my $mail = EBox::Global->modInstance('mail');
    my $mailUserModel = $mail->model('MailUser');
    return unless ($mailUserModel->enabledValue());

    my $sambaModule = EBox::Global->modInstance('samba');
    my $adDomain = $sambaModule->getProvision->getADDomain('localhost');
    my $vDomain = $mailUserModel->domainValue();
    return unless (lc $vDomain eq lc $adDomain);

    $self->setAccountEnabled($user, 1);
}

sub _delUserWarning
{
    my ($self, $user) = @_;

    return unless ($self->{openchange}->configured());

    my $samAccountName = $user->get('uid');
    my $ldbUser = new EBox::Samba::User(samAccountName => $samAccountName);
    unless ($ldbUser->exists()) {
        throw EBox::Exceptions::Internal(
            "LDB user '$samAccountName' does not exists");
    }
    my $msExchUserAccountControl = $ldbUser->get('msExchUserAccountControl');
    return unless defined $msExchUserAccountControl;

    my $txt = __('This user has a openchange account.');

    return $txt;
}

# Method: defaultUserModel
#
#   Overrides <EBox::UsersAndGrops::LdapUserBase::defaultUserModel>
#   to return our default user template
#
sub defaultUserModel
{
    return 'openchange/OpenChangeUser';
}

1;
