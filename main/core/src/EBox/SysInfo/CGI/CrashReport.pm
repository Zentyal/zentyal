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

package EBox::SysInfo::CGI::CrashReport;

use base qw(EBox::CGI::ClientBase);

use EBox::Validate;
use EBox::Util::BugReport;
use EBox::Gettext;
use Error qw(:try);

my $CRASH_DIR = '/var/crash';

sub _process
{
    my ($self) = @_;

    my $action = $self->param('action');

    # FIXME: unhardcode samba if more daemon crashes are watched

    if ($action eq 'report') {
        my @files = @{EBox::Sudo::root("ls $CRASH_DIR | grep ^_opt_samba4")};
        foreach my $file (@files) {
            EBox::info("Sending crash report: $file");
            EBox::Sudo::root("/usr/share/zentyal/crash-report $CRASH_DIR/$file");
        }
    } elsif ($action eq 'discard') {
        EBox::Sudo::root('rm -f /var/crash/_opt_samba4_*');
    }
}

sub requiredParameters
{
    my ($self) = @_;

    return [ 'action' ];
}

1;
