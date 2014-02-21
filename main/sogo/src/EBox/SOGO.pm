# Copyright (C) 2013 Zentyal S.L.

use strict;
use warnings;

package EBox::SOGO;

use base qw(EBox::Module::Service);

use EBox::Gettext;
use EBox::Service;
use EBox::Sudo;
use EBox::Config;
use EBox::WebServer;

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
#        <EBox::WebMail> - the recently created module
#
sub _create
{
    my $class = shift;
    my $self = $class->SUPER::_create(name => 'sogo',
                                      printableName => __('OpenChange Webmail'),
                                      @_);
    bless($self, $class);
    return $self;
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

    if ($self->isEnabled()) {
        EBox::Sudo::root("a2ensite zentyal-sogo");
    } else {
        EBox::Sudo::root("a2dissite zentyal-sogo");
    }
}

# Group: Public methods

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
    my ($self) = @_;

    my $sogoApacheConf = EBox::WebServer::GLOBAL_CONF_DIR . 'zentyal-sogo';
    return [
        { 'file' => $sogoApacheConf, 'module' => 'webmail', 'reason' => __('To configure the webmail on the webserver.') }
    ];
}

# Method: actions
#
#        Explain the actions the module must make to configure the
#        system. Check overriden method for details
#
# Overrides:
#
#        <EBox::Module::Service::actions>
sub actions
{
    return [
            {
             'action' => __('Create MySQL webmail database.'),
             'reason' => __('This database will store the data needed by the webmail service.'),
             'module' => 'sogo'
            },
            {
             'action' => __('Add webmail link to www data directory.'),
             'reason' => __('WebMail UI will be accesible at http://ip/webmail/.'),
             'module' => 'sogo'
            },
    ];
}

# Method: enableActions
#
#        Run those actions explain by <actions> to enable the module
#
# Overrides:
#
#        <EBox::Module::Service::enableActions>
#
sub enableActions
{
    my ($self) = @_;

    my $mail = EBox::Global->modInstance('mail');
    unless ($mail->imap() or $mail->imaps()) {
        throw EBox::Exceptions::External(__x('Webmail module needs IMAP or IMAPS service enabled if ' .
                                             'using Zentyal mail service. You can enable it at ' .
                                             '{openurl}Mail -> General{closeurl}.',
                                             openurl => q{<a href='/Mail/Composite/General'>},
                                             closeurl => q{</a>}));
    }

    # Execute enable-module script
    $self->SUPER::enableActions();

    # Force apache restart
    EBox::Global->modChange('webserver');
}

sub _daemons
{
    return [ { 'name' => 'sogo', 'type' => 'init.d' } ];
}

1;
