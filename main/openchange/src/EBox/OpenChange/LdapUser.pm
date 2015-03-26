# Copyright (C) 2013-2014 Zentyal S.L.
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
use EBox::Sudo;

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

    my $active = $self->enabled($user) ? 1 : 0;
    my $args = {
        user     => $user,
        hasMail  => $user->get('mail') ? 1 : 0,
        active   => $active,
    };

    return {
        title =>  __('OpenChange Account'),
        path => '/openchange/openchange.mas',
        params => $args
    };
}

sub noMultipleOUSupportComponent
{
    my ($self) = @_;
    return $self->standardNoMultipleOUSupportComponent(__('OpenChange Account'));
}

sub enabled
{
    my ($self, $user) = @_;

    my $msExchUserAccountControl = $user->get('msExchUserAccountControl');
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
        __x('Unknown value for {control}: {x}',
            control => 'msExchUserAccountControl', x => $msExchUserAccountControl));
}

sub setAccountEnabled
{
    my ($self, $user, $enabled) = @_;
    my $samAccountName = $user->get('samAccountName');
    my $msExchUserAccountControl = $user->get('msExchUserAccountControl');
    my $mail = $user->get('mail');

    my $cmd = 'openchange_newuser ';
    $cmd .= ' --create ' unless (defined $msExchUserAccountControl);
    if ($enabled) {
        $cmd .= ' --enable ';
    } else {
        $cmd .= ' --disable ';
    }
    if (defined $mail and length $mail) {
        $cmd .= " --mail $mail ";
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

    $self->setAccountEnabled($user, 1);
}

sub _delUserWarning
{
    my ($self, $user) = @_;

    return unless ($self->{openchange}->configured());

    my $samAccountName = $user->get('samAccountName');
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

sub _delUser
{
    my ($self, $user) = @_;
    # remove user from sogo database
    my $samAccountName = $user->get('samAccountName');
    EBox::Sudo::silentRoot("sogo-tool remove '$samAccountName'");
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

sub _groupAddOns
{
    my ($self, $group) = @_;

    unless ($self->{openchange}->configured() and
            $self->{openchange}->isProvisioned()) {
        return;
    }

    my $active = $self->groupEnabled($group) ? 1 : 0;
    my $args = {
        group     => $group,
        hasMail  => $group->get('mail') ? 1 : 0,
        active   => $active,
    };

    return {
        title =>  __('OpenChange Account'),
        path => '/openchange/openchange_group.mas',
        params => $args
    };
}

sub groupEnabled
{
    my ($self, $group) = @_;
    my $legacyExchangeDN=  $group->get('legacyExchangeDN');
    return $legacyExchangeDN ? 1 : 0;
}

sub setGroupAccountEnabled
{
    my ($self, $group, $enabled) = @_;
    my $samAccountName = $group->get('samAccountName');
    my $mail = $group->get('mail');

    my $cmd = 'openchange_group ';
    if ($enabled) {
        $cmd .= ' --create ';
    } else {
        $cmd .= ' --delete ';
    }
    if (defined $mail and length $mail) {
        $cmd .= " --mail $mail ";
    }
    $cmd .= " '$samAccountName' ";
    EBox::Sudo::root($cmd);

    return 0;
}

sub _modifyGroup
{
    my ($self, $group) = @_;

    return unless (EBox::Global->modInstance('mail')->configured());

    if (not $self->groupEnabled($group)) {
        return;
    }

    my $samAccountName = $group->get('samAccountName');
    my $cmd = "openchange_group --update '$samAccountName'";
    EBox::Sudo::root($cmd);
}

sub _delGroupWarning
{
    my ($self, $group) = @_;

    return unless ($self->{openchange}->configured());

    if (not $self->groupEnabled($group)) {
        return;
    }

    my $txt = __('This group has a openchange account.');
    return $txt;
}

1;
