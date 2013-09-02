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

package EBox::Samba::SmbClient;
use base 'Samba::Smb';

use EBox::Exceptions::Internal;
use EBox::Exceptions::MissingArgument;
use EBox::Gettext;
use EBox::Samba::AuthKrbHelper;

use Error qw(:try);
use Fcntl qw(O_RDONLY O_CREAT O_TRUNC O_RDWR);
use Samba::Credentials;
use Samba::LoadParm;
use Samba::Smb;

sub new
{
    my ($class, %params) = @_;

    my $target = delete $params{target};
    unless (defined $target) {
        throw EBox::Exceptions::MissingArgument('target');
    }

    my $service = delete $params{service};
    unless (defined $service) {
        throw EBox::Exceptions::MissingArgument('service');
    }

    my $krbHelper = new EBox::Samba::AuthKrbHelper(%params);

    my $lp = new Samba::LoadParm();
    $lp->load_default();

    my $creds = new Samba::Credentials($lp);
    $creds->kerberos_state(CRED_MUST_USE_KERBEROS);
    $creds->guess();

    my $self = $class->SUPER::new($lp, $creds);
    try {
        $self->connect($target, $service);
    } otherwise {
        my ($ex) = @_;
        throw EBox::Exceptions::External("Error connecting with SMB server: $ex");
    };

    $self->{krbHelper} = $krbHelper;
    $self->{loadparm} = $lp;
    $self->{credentials} = $creds;

    bless ($self, $class);
    return $self;
}

sub read_file
{
    my ($self, $path) = @_;

    # Open file and get the size
    my $fd = $self->open($path, O_RDONLY, Samba::Smb::DENY_NONE);
    my $finfo = $self->getattr($fd);
    my $fileSize = $finfo->{size};

    # Read to buffer
    my $buffer;
    my $chunkSize = 4096;
    my $pendingBytes = $fileSize;
    my $readBytes = 0;
    while ($pendingBytes > 0) {
        my $tmpBuffer;
        $chunkSize = ($pendingBytes < $chunkSize) ?
                      $pendingBytes : $chunkSize;
        my $nRead = $self->read($fd, $tmpBuffer, $readBytes, $chunkSize);
        $buffer .= $tmpBuffer;
        $readBytes += $nRead;
        $pendingBytes -= $nRead;
    }

    # Close and return buffer
    $self->close($fd);

    return $buffer;
}

sub write_file
{
    my ($self, $dst, $buffer) = @_;

    my $openFlags = O_CREAT | O_TRUNC | O_RDWR;
    my $fd = $self->open($dst, $openFlags, Samba::Smb::DENY_NONE);

    my $size = length ($buffer);
    my $wrote = $self->write($fd, $buffer, $size);
    if ($wrote == -1) {
        throw EBox::Exceptions::Internal(
            "Can not write $dst: $!");
    }
    $self->close($fd);

    unless ($wrote == $size) {
        throw EBox::Exceptions::Internal(
            "Error writting to $dst. Sizes does not match");
    }
}

sub copy_file_to_smb
{
    my ($self, $src, $dst) = @_;

    my @srcStat = stat ($src);
    unless ($#srcStat) {
        throw EBox::Exceptions::Internal("Can not stat $src");
    }
    my $srcSize = $srcStat[7];
    my $pendingBytes = $srcSize;
    my $writtenBytes = 0;

    my $openFlags = O_CREAT | O_TRUNC | O_RDWR;
    my $fd = $self->open($dst, $openFlags, Samba::Smb::DENY_NONE);
    my $ret = open(SRC, $src);
    if ($ret == 0) {
        throw EBox::Exceptions::Internal("Can not open $src: $!");
    }

    my $buffer = undef;
    my $chunkSize = 4096;
    while ($pendingBytes > 0) {
        $chunkSize = ($pendingBytes < $chunkSize) ?
                      $pendingBytes : $chunkSize;
        my $read = sysread (SRC, $buffer, $chunkSize);
        unless (defined $read) {
            throw EBox::Exceptions::Internal("Can not read $src: $!");
        }
        $pendingBytes -= $read;

        my $bufferSize = length($buffer);
        my $wrote = $self->write($fd, $buffer, $bufferSize);
        unless ($wrote == $bufferSize) {
            throw EBox::Exceptions::Internal(
                "Wrote bytes does not match buffer size");
        }
        $writtenBytes += $wrote;
    }
    close SRC;
    $self->close($fd);

    unless ($writtenBytes == $srcSize and $pendingBytes == 0) {
        throw EBox::Exceptions::Internal(
            "Error copying $src to $dst. Sizes does not match");
    }
}

1;
