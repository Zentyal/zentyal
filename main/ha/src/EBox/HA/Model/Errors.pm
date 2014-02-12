# Copyright (C) 2014 Zentyal S. L.
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

package EBox::HA::Model::Errors;

# Class: EBox::HA::Model::Errors
#
#     Model to show the current errors of the cluster
#

use base 'EBox::Model::DataTable';

use EBox::Gettext;
use EBox::HA::ClusterStatus;

# Group: Public methods

# Constructor: new
#
#    To store the list
#
sub new
{
    my $class = shift;

    my $self = $class->SUPER::new(@_);
    bless($self, $class);

    $self->{clusterStatus} = new EBox::HA::ClusterStatus($self->parentModule());

    return $self;
}

# Method: ids
#
#     Return the current list of node names
#
# Overrides:
#
#     <EBox::Model::DataTable::ids>
#
sub ids
{
    my ($self)  = @_;

    unless (defined($self->{clusterStatus}->errors())) {
        return [];
    }

    my @names = (0..(@{$self->{clusterStatus}->errors()} - 1));

    return \@names;
}

# Method: row
#
#     Return a node names
#
# Overrides:
#
#     <EBox::Model::DataTable::row>
#
sub row
{
    my ($self, $id)  = @_;

    my @errors = @{$self->{clusterStatus}->errors()};
    my %error = %{$errors[$id]};

    my $row = new EBox::Model::Row(dir => $self->directory(), confmodule => $self->parentModule());
    $row->setId($id);
    $row->setModel($self);
    $row->setReadOnly(1);

    my $tableDesc = $self->table()->{tableDescription};
    foreach my $type (@{$tableDesc}) {
        my $element = $type->clone();

        # To parse each field we call the method _parseNode_{field} stored
        # as a string in $parseFunction. No if/switch, so this can grow bigger
        my $parseFunction = "_parseError_" . $element->fieldName();
        $parseFunction = \&$parseFunction;
        $element->setValue($parseFunction->($self, %error));

        $row->addElement($element);
    }

    return $row;
}

# Group: Protected methods

# Method: _table
#
# Overrides:
#
#       <EBox::Model::DataTable::_table>
#
sub _table
{
    my ($self) = @_;

    my @fields = (
            new EBox::Types::Text(
                fieldName     => 'info',
                printableName => __('Cluster error'),
                ),
            new EBox::Types::Text(
                fieldName     => 'node',
                printableName => __('Node'),
                ),
            );

    my $dataTable =
    {
        tableName => 'Errors',
        defaultActions => [ 'changeView' ],
        modelDomain => 'HA',
        tableDescription => \@fields,
        withoutActions => 1,
        showPaginationForm => 0,
        showFilterForm => 0,
        noDataMsg => __('The cluster does not have any errors.'),
        help => undef,
    };

    return $dataTable;
}

# Group: Private methods

sub _parseError_info
{
    my ($self, %error) = @_;

    return $error{info} ? $error{info} : __('no error');
}

sub _parseError_node
{
    my ($self, %error) = @_;

    return $error{node} ? $error{node} : __('noname');
}

1;
