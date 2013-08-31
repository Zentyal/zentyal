// Copyright (C) 2004-2013 Zentyal S.L. licensed under the GPLv2
"use strict";

Zentyal.namespace('Help');

Zentyal.Help.helpShown = false;

Zentyal.Help.showHelp = function () {
    Zentyal.Help.helpShown = true;
    $('.help').slideToggle('fast');
};

Zentyal.Help.initHelp = function () {
    if($('.help').length > 0) {
        $('#helpbutton').show();
    }
};

Zentyal.Help.initHelp();
$('body').bind('DOMNodeInserted', Zentyal.Help.initHelp, false);

