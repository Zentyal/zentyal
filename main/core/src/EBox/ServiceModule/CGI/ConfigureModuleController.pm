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


# package EBox::CGI::ServiceModule::ConfigureModuleController
#
#   This class is used as a controller to receive the green light
#   from users to configure which is needed to enable a module
#
package EBox::ServiceModule::CGI::ConfigureModuleController;

use strict;
use warnings;

use base 'EBox::CGI::ClientBase';

use EBox::ServiceManager;
use EBox::Global;
use EBox::Gettext;

use Error qw(:try);
use EBox::Exceptions::Base;



## arguments:
## 	title [required]
sub new
{
    my $class = shift;
    my $self = $class->SUPER::new( @_);

    bless($self, $class);
    return $self;
}



sub _process
{
    my ($self) = @_;

    $self->_requireParam('module');
    my $modName = $self->param('module');
    my $manager = new EBox::ServiceManager();
    my $module = EBox::Global->modInstance($modName);

    try {
        $module->configureModule();
    } otherwise {
        my ($excep) = @_;
        if ($excep->isa("EBox::Exceptions::External")) {
            throw EBox::Exceptions::External("Failed to enable: " .
                $excep->stringify());
        } else {
            throw EBox::Exceptions::Internal("Failed to enable: " .
                $excep->stringify());
        }
    };
    $self->{redirect} = "ServiceModule/StatusView";
}

1;


