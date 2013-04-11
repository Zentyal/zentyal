# Copyright (C) 2008-2012 eBox Technologies S.L.
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

package EBox::Squid::Model::AccessRules;

use base 'EBox::Model::DataTable';

use EBox;
use EBox::Global;
use EBox::Exceptions::Internal;
use EBox::Gettext;
use EBox::Types::Text;
use EBox::Types::Select;
use EBox::Types::Union;
use EBox::Types::Union::Text;
use EBox::Squid::Types::TimePeriod;

use Net::LDAP;
use Net::LDAP::Control::Sort;
use Authen::SASL qw(Perl);
use Authen::Krb5::Easy qw(kinit kdestroy kerror kcheck);

use constant MAX_DG_GROUP => 99; # max group number allowed by dansguardian

# Method: _table
#
#
sub _table
{
    my ($self) = @_;

    my @tableHeader = (
        new EBox::Squid::Types::TimePeriod(
                fieldName => 'timePeriod',
                printableName => __('Time period'),
                help => __('Time period when the rule is applied'),
                editable => 1,
        ),
        new EBox::Types::Union(
            fieldName     => 'source',
            printableName => __('Source'),
            filter        => \&_filterSourcePrintableValue,
            subtypes => [
                new EBox::Types::Select(
                    fieldName     => 'object',
                    foreignModel  => $self->modelGetter('objects', 'ObjectTable'),
                    foreignField  => 'name',
                    foreignNextPageField => 'members',
                    printableName => __('Network Object'),
                    editable      => 1,
                    optional      => 0,
                ),
                new EBox::Types::Select(
                    fieldName     => 'group',
                    printableName => __('Users Group'),
                    populate      => \&_populateGroups,
                    editable      => 1,
                    optional      => 0,
                    disableCache  => 1,
                ),
                new EBox::Types::Union::Text(
                    fieldName => 'any',
                    printableName => __('Any'),
                )
            ]
        ),
        new EBox::Types::Union(
            fieldName     => 'policy',
            printableName => __('Decision'),
            filter        => \&_filterProfilePrintableValue,
            subtypes => [
                new EBox::Types::Union::Text(
                    fieldName => 'allow',
                    printableName => __('Allow All'),
                ),
                new EBox::Types::Union::Text(
                    fieldName => 'deny',
                    printableName => __('Deny All'),
                ),
                new EBox::Types::Select(
                    fieldName => 'profile',
                    printableName => __('Apply Filter Profile'),
                    foreignModel  => $self->modelGetter('squid', 'FilterProfiles'),
                    foreignField  => 'name',
                    editable      => 1,
                )
            ]
        ),
    );

    my $dataTable =
    {
        tableName          => 'AccessRules',
        pageTitle          => __('HTTP Proxy'),
        printableTableName => __('Access Rules'),
        modelDomain        => 'Squid',
        defaultActions     => [ 'add', 'del', 'editField', 'changeView', 'clone', 'move' ],
        tableDescription   => \@tableHeader,
        class              => 'dataTable',
        order              => 1,
        rowUnique          => 1,
        automaticRemove    => 1,
        printableRowName   => __('rule'),
        help               => __('Here you can filter, block or allow access by user group or network object. Rules are only applied during the selected time period.'),
    };
}

sub _populateGroups
{
    my ($self) = @_;

    my $squid = $self->parentModule();
    my $mode = $squid->authenticationMode();
    if ($mode eq $squid->AUTH_MODE_EXTERNAL_AD()) {
        return $self->_populateGroupsFromExternalAD();
    } else {
        my $userMod = EBox::Global->modInstance('users');
        return [] unless ($userMod->isEnabled());

        my @groups;
        push (@groups, { value => '__USERS__', printableValue => __('All users') });
        foreach my $group (@{$userMod->groups()}) {
            my $name = $group->name();
            push (@groups, { value => $name, printableValue => $name });
        }
        return \@groups;
    }
    return [];
}

sub _adLdap
{
    my ($self) = @_;

    unless (defined $self->{adLdap}) {
    my $squid = $self->parentModule();
    my $keytab = $squid->KEYTAB_FILE();
    my $sysinfo = EBox::Global->modInstance('sysinfo');
    my $hostSamAccountName = uc ($sysinfo->hostName()) . '$';

    EBox::info("Connecting to AD LDAP");
    my $confFile = $squid->SQUID_ZCONF_FILE();
    my $dcKey = $squid->AUTH_AD_DC_KEY();
    my $dc = EBox::Config::configkeyFromFile($dcKey, $confFile);

    my $ccache = EBox::Config::tmp() . 'squid-ad.ccache';
    $ENV{KRB5CCNAME} = $ccache;

    # Get credentials for computer account
    my $ok = kinit($keytab, $hostSamAccountName);
    unless (defined $ok and $ok == 1) {
        throw EBox::Exceptions::External(
            __x("Unable to get kerberos ticket to bind to LDAP: {x}",
                x => kerror()));
    }

    # Set up a SASL object
    my $sasl = new Authen::SASL(mechanism => 'GSSAPI');
    unless ($sasl) {
        throw EBox::Exceptions::External(
            __x("Unable to setup SASL object: {x}",
                x => $@));
    }

    # Set up an LDAP connection
    my $ldap = new Net::LDAP($dc);
    unless ($ldap) {
        throw EBox::Exceptions::External(
            __x("Unable to setup LDAP object: {x}",
                x => $@));
    }

    # Check GSSAPI support
    my $dse = $ldap->root_dse(attrs => ['defaultNamingContext', '*']);
    unless ($dse->supported_sasl_mechanism('GSSAPI')) {
        throw EBox::Exceptions::External(
            __("AD LDAP server does not support GSSAPI"));
    }

    # Finally bind to LDAP using our SASL object
    my $bindResult = $ldap->bind(sasl => $sasl);
    if ($bindResult->is_error()) {
        throw EBox::Exceptions::External(
            __x("Could not bind to AD LDAP server '{x}'. Error was '{y}'" .
                x => $dc, y => $bindResult->error_desc()));
    }
        $self->{adLdap} = $ldap;
    }

    return $self->{adLdap};
}

# Method: _sidToString
#
#   This method translate binary SIDs retrieved from AD LDAP to its string
#   representation.
#
#   FIXME This method is duplicated from samba module, file LdbObject.pm,
#         should be in a utility class at common or core
#
sub _sidToString
{
    my ($self, $sid) = @_;

    return undef
        unless unpack("C", substr($sid, 0, 1)) == 1;

    return undef
        unless length($sid) == 8 + 4 * unpack("C", substr($sid, 1, 1));

    my $sid_str = "S-1-";

    $sid_str .= (unpack("C", substr($sid, 7, 1)) +
                (unpack("C", substr($sid, 6, 1)) << 8) +
                (unpack("C", substr($sid, 5, 1)) << 16) +
                (unpack("C", substr($sid, 4, 1)) << 24));

    for my $loop (0 .. unpack("C", substr($sid, 1, 1)) - 1) {
        $sid_str .= "-" . unpack("I", substr($sid, 4 * $loop + 8, 4));
    }

    return $sid_str;
}

sub _populateGroupsFromExternalAD
{
    my ($self) = @_;

    my $squid = $self->parentModule();
    my $key = $squid->AUTH_AD_SKIP_SYSTEM_GROUPS_KEY();
    my $skip = EBox::Config::boolean($key);

    my $groups = [];
    my $ad = $self->_adLdap();
    my $dse = $ad->root_dse(attrs => ['defaultNamingContext', '*']);
    my $defaultNC = $dse->get_value('defaultNamingContext');
    my $sort = new Net::LDAP::Control::Sort(order => 'samAccountName');
    my $filter = $skip ?
        '(&(objectClass=group)(!(isCriticalSystemObject=*)))':
        '(objectClass=group)';
    my $res = $ad->search(base => $defaultNC,
                          scope => 'sub',
                          filter => $filter,
                          attrs => ['samAccountName', 'objectSid'],
                          control => [$sort]);
    foreach my $entry ($res->entries()) {
        my $samAccountName = $entry->get_value('samAccountName');
        my $sid = $self->_sidToString($entry->get_value('objectSid'));
        utf8::decode($samAccountName);
        push (@{$groups}, { value => $sid, printableValue => $samAccountName });
    }

    # TODO Make connection persistent?
    $ad->disconnect();
    delete $self->{adLdap};

    return $groups;
}

sub _adGroupMembers
{
    my ($self, $group) = @_;

    my $members = [];
    my $ldap = $self->_adLdap();
    my $dse = $ldap->root_dse(attrs => ['defaultNamingContext', '*']);
    my $defaultNC = $dse->get_value('defaultNamingContext');
    my $result = $ldap->search(base => $defaultNC,
                               scope => 'sub',
                               filter => "(&(objectClass=group)(objectSid=$group))",
                               attrs => ['member']);
    foreach my $groupEntry ($result->entries()) {
        my @members = $groupEntry->get_value('member');
        next unless @members;
        foreach my $memberDN (@members) {
            my $result2 = $ldap->search(base => $defaultNC,
                                        scope => 'sub',
                                        filter => "(&(objectClass=user)(distinguishedName=$memberDN))",
                                        attrs => ['samAccountName']);
            foreach my $userEntry ($result2->entries()) {
                my $samAccountName = $userEntry->get_value('samAccountName');
                next unless defined $samAccountName;
                push (@{$members}, $samAccountName);
            }
        }
    }

    return $members;
}

sub validateTypedRow
{
    my ($self, $action, $params_r, $actual_r) = @_;

    my $squid = $self->parentModule();


    my $source = exists $params_r->{source} ?
                      $params_r->{source}:  $actual_r->{source};
    my $sourceType  = $source->selectedType();
    my $sourceValue = $source->value();

    if ($squid->transproxy() and ($sourceType eq 'group')) {
        throw EBox::Exceptions::External(__('Source matching by user group is not compatible with transparent proxy mode'));
    }

    # check if it is a incompatible rule
     my $groupRules;
     my $objectProfile;
     if ($sourceType eq 'group') {
         $groupRules = 1;
     } else {
        my $policy = exists $params_r->{policy} ?  $params_r->{policy}->selectedType
                                                 :  $actual_r->{policy}->selectedType();
         if (($policy eq 'allow') or ($policy eq 'profile') ) {
             $objectProfile = 1;
         }
     }

    if ((not $groupRules) and (not $objectProfile)) {
        return;
    }

    my $ownId = $params_r->{id};
    my $ownTimePeriod = exists $params_r->{timePeriod} ?
                                     $params_r->{timePeriod} :  $actual_r->{timePeriod};
    foreach my $id (@{ $self->ids() }) {
        next if ($id eq $ownId);

        my $row = $self->row($id);
        my $rowSource = $row->elementByName('source');
        my $rowSourceType = $rowSource->selectedType();
        if ($objectProfile and ($rowSourceType eq 'group')) {
            throw EBox::Exceptions::External(
              __("You cannot add a 'Allow' or 'Profile' rule for an object or any address if you have group rules")
             );
        } elsif ($groupRules and ($rowSourceType ne 'group')) {
            if ($row->elementByName('policy')->selectedType() ne 'deny') {
                throw EBox::Exceptions::External(
                 __("You cannot add a group-based rule if you have an 'Allow' or 'Profile' rule for objects or any address")
               );
            }
        }

        if ($sourceValue eq $rowSource->value()) {
            # same object/group, check time overlaps
            my $rowTimePeriod = $row->elementByName('timePeriod');
            if ($ownTimePeriod->overlaps($rowTimePeriod)) {
                throw EBox::Exceptions::External(
                    __x('The time period of the rule ({t1}) overlaps with the time period of ({t2}) other rule for the same {sourceType}',
                        t1 => $ownTimePeriod->printableValue(),
                        t2 => $rowTimePeriod->printableValue(),
                        # XXX due to the bad case of subtype's printable names
                        # we need to do lcfirst of all words instead of doing so
                        # only in the first one
                        sourceType => join (' ', map { lcfirst $_ } split '\s+',  $source->subtype()->printableName()),
                       )
                   );
            }
        }

    }
}

sub rules
{
    my ($self) = @_;

    my $objectMod = $self->global()->modInstance('objects');
    my $userMod = $self->global()->modInstance('users');
    my $usersEnabled = $userMod->isEnabled();

    # we dont use row ids to make rule id shorter bz squid limitations with id length
    my $number = 0;
    my @rules;
    foreach my $id (@{$self->ids()}) {
        my $row = $self->row($id);
        my $source = $row->elementByName('source');

        my $rule = { number => $number};
        if ($source->selectedType() eq 'object') {
            my $object = $source->value();
            $rule->{object} = $object;
            $rule->{members} = $objectMod->objectMembers($object);
            my $addresses = $objectMod->objectAddresses($object);
            # ignore empty objects
            next unless @{$addresses};
            $rule->{addresses} = $addresses;
        } elsif ($source->selectedType() eq 'group') {
            my $mode = $self->parentModule->authenticationMode();
            if ($mode eq $self->parentModule->AUTH_MODE_INTERNAL()) {
                next unless ($usersEnabled);
                my $group = $source->value();
                $rule->{group} = $group;
                my $users;
                if ($group eq '__USERS__') {
                    $users = $userMod->users();
                } else {
                    $users = $userMod->group($group)->users();
                }

                if (not @{$users}) {
                    # ignore rules for empty groups
                    next;
                }
                $rule->{users} = [ (map {
                                          my $name =  $_->name();
                                          lc $name;
                                      } @{$users}) ];
            } elsif ($mode eq $self->parentModule->AUTH_MODE_EXTERNAL_AD()) {
                $rule->{adDN} = $source->value();
            }
        } elsif ($source->selectedType() eq 'any') {
            $rule->{any} = 1;
        }

        my $policyElement = $row->elementByName('policy');
        my $policyType =  $policyElement->selectedType();
        $rule->{policy} = $policyType;
        if ($policyType eq 'profile') {
            $rule->{profile} = $policyElement->value();
        }

        my $timePeriod = $row->elementByName('timePeriod');
        if (not $timePeriod->isAllTime) {
            if (not $timePeriod->isAllWeek()) {
                $rule->{timeDays} = $timePeriod->weekDays();
            }

            my $hours = $timePeriod->hourlyPeriod();
            if ($hours) {
                $rule->{timeHours} = $hours;
            }
        }

        push (@rules, $rule);
        $number += 1;
    }

    return \@rules;
}


sub squidFilterProfiles
{
    my ($self) = @_;

    my $enabledProfiles = $self->_enabledProfiles();
    my $filterProfiles = $self->parentModule()->model('FilterProfiles');
    my $acls = $filterProfiles->squidAcls($enabledProfiles);
    my $rulesStubs = $filterProfiles->squidRulesStubs($enabledProfiles, sharedAcls => $acls->{shared});
    return {
              acls => $acls->{all},
              rulesStubs => $rulesStubs,
           };
}

sub existsPoliciesForGroup
{
    my ($self, $group) = @_;
    foreach my $id (@{ $self->ids() }) {
        my $row = $self->row($id);
        my $source = $row->elementByName('source');
        next unless $source->selectedType() eq 'group';
        my $userGroup = $source->value();
        if ($group eq $userGroup) {
            return 1;
        }
    }

    return 0;
}

sub delPoliciesForGroup
{
    my ($self, $group) = @_;
    my @ids = @{ $self->ids() };
    foreach my $id (@ids) {
        my $row = $self->row($id);
        my $source = $row->elementByName('source');
        next unless $source->selectedType() eq 'group';
        my $userGroup = $source->printableValue();
        if ($group eq $userGroup) {
            $self->removeRow($id);
        }
    }
}

sub filterProfiles
{
    my ($self) = @_;
    my $filterProfilesModel = $self->parentModule()->model('FilterProfiles');
    my %profileIdByRowId = %{ $filterProfilesModel->idByRowId() };

    my $objectMod = $self->global()->modInstance('objects');
    my $userMod = $self->global()->modInstance('users');

    my @profiles;
    foreach my $id (@{$self->ids()}) {
        my $row = $self->row($id);

        my $profile = {};

        my $policy     = $row->elementByName('policy');
        my $policyType = $policy->selectedType();
        if ($policyType eq 'allow') {
            $profile->{number} = 2;
        } elsif ($policyType eq 'deny') {
            $profile->{number} = 1;
        } elsif ($policyType eq 'profile') {
            my $rowId = $policy->value();
            $profile->{number} = $profileIdByRowId{$rowId};
            $profile->{usesFilter} = $filterProfilesModel->usesFilterById($rowId);
        } else {
            throw EBox::Exceptions::Internal("Unknown policy type: $policyType");
        }
        $profile->{policy} = $policyType;
        my $timePeriod = $row->elementByName('timePeriod');
        unless ($timePeriod->isAllTime()) {
            $profile->{timePeriod} = 1;
            $profile->{begin} = $timePeriod->from();
            $profile->{end} = $timePeriod->to();
            $profile->{days} = $timePeriod->dayNumbers();
        }

        my $source = $row->elementByName('source');
        my $sourceType = $source->selectedType();
        $profile->{source} = $sourceType;
        if ($sourceType eq 'any') {
            $profile->{anyAddress} = 1;
            $profile->{address} = '0.0.0.0/0.0.0.0';
            push @profiles, $profile;
        } elsif ($sourceType eq 'object') {
            my $obj       = $source->value();
            my @addresses = @{ $objectMod->objectAddresses($obj, mask => 1) };
            foreach my $cidrAddress (@addresses) {
                # put a pseudo-profile for each address in the object
                my ($addr, $netmask) = ($cidrAddress->[0], EBox::NetWrappers::mask_from_bits($cidrAddress->[1]));
                my %profileCopy = %{$profile};
                $profileCopy{address} = "$addr/$netmask";
                push @profiles, \%profileCopy;
            }
        } elsif ($sourceType eq 'group') {
            my $group = $source->value();
            $profile->{group} = $group;
            my @users;
            if ($self->parentModule->authenticationMode() eq
                $self->parentModule->AUTH_MODE_EXTERNAL_AD()) {
                @users = @{$self->_adGroupMembers($group)};
            } else {
                my $members;
                if ($group eq '__USERS__') {
                    $members = $userMod->users();
                } else {
                    $members = $userMod->group($group)->users();
                }
                @users = map { $_->name() } @{$members};
            }
            @users or next;
            $profile->{users} = \@users;
            push @profiles, $profile;
        } else {
            throw EBox::Exceptions::Internal("Unknow source type: $sourceType");
        }
    }
    return \@profiles;
}

sub rulesUseAuth
{
    my ($self) = @_;

    foreach my $id (@{$self->ids()}) {
        my $row = $self->row($id);
        my $source = $row->elementByName('source');
        if ($source->selectedType() eq 'group') {
            return 1;
        }
    }

    return 0;
}

sub rulesUseFilter
{
    my ($self) = @_;
    my $profiles = $self->_enabledProfiles();
    my $filterProfiles = $self->parentModule()->model('FilterProfiles');
    return $filterProfiles->usesFilter($profiles);
}

sub _enabledProfiles
{
    my ($self) = @_;
    my %profiles;
    foreach my $id (@{ $self->ids()  }) {
        my $row = $self->row($id);
        my $policy = $row->elementByName('policy');
        if ($policy->selectedType eq 'profile') {
            $profiles{$policy->value()} = 1;
        }
    }
    return [keys %profiles];
}

sub _filterSourcePrintableValue
{
    my ($type) = @_;

    my $selected = $type->selectedType();
    my $value = $type->printableValue();

    if ($selected eq 'object') {
        return __x('Object: {o}', o => $value);
    } elsif ($selected eq 'group') {
        return __x('Group: {g}', g => $value);
    } else {
        return $value;
    }
}

sub _filterProfilePrintableValue
{
    my ($type) = @_;

    if ($type->selectedType() eq 'profile') {
        return __x("Apply '{p}' profile", p => $type->printableValue());
    } else {
        return $type->printableValue();
    }
}

1;
