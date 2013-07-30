// Copyright (C) 2004-2013 Zentyal S.L. licensed under the GPLv2

// code used by progress.mas

"use strict";

Zentyal.namespace('ProgressIndicator');

Zentyal.ProgressIndicator.updateProgressBar = function(progressbar, ticks, totalTicks) {
    var percent;
    if (totalTicks > 0) {
        percent = Math.ceil((ticks/totalTicks)*100);
        if( percent > 100)
            percent = 100;
        if(percent < 0)
            percent = 0;
    } else {
        percent = 0;
    }

    if (progressbar.progressbar('option').max !== totalTicks) {
        progressbar.progressbar('option', 'max', totalTicks);
    }
    progressbar.progressbar('value', ticks);
    $('#percent', progressbar).html(percent+"%");
};

Zentyal.ProgressIndicator.updatePage  = function(xmlHttp, progressbar, timerId, nextStepTimeout, nextStepUrl, showNotesOnFinish) {
    var response;
    if (xmlHttp.responseText.length === 0) {
        return;
    }
    response = $.parseJSON(xmlHttp.responseText);

    if (xmlHttp.readyState == 4) {
        if (response.state == 'running') {
            var ticks = 0;
            var totalTicks = 0;
            if (('message' in response) && response.message.length > 0 ) {
                $('#currentItem').html(response.message);
            }
            if ( ('ticks' in response) && (response.ticks >= 0)) {
                $('#ticks').html(response.ticks);
                ticks = response.ticks;
            }
            if ( ('totalTicks' in response) && (response.totalTicks > 0)) {
                $('#totalTicks').html(response.totalTicks);
                totalTicks = response.totalTicks;
            }

            if ( totalTicks > 0 ) {
                Zentyal.ProgressIndicator.updateProgressBar(progressbar, ticks, totalTicks);
            }
        } else if (response.state == 'done') {
            clearInterval(timerId);
            if ( nextStepTimeout > 0 ) {
              Zentyal.ProgressIndicator.loadWhenAvailable(nextStepUrl, nextStepTimeout);
            }

          if (showNotesOnFinish) {
            if (('errorMsg' in response) && (response.errorMsg)) {
                $('#warning-progress-messages').html(response.errorMsg);

                $('#done_note').removeClass('note').addClass('warning');
                $('#warning-progress').show();
                $('#warning-progress-messages').show();
            }

              $('#progressing').hide();
              $('#done').show();
          }

            // Used to tell selenium we are done
            // with saving changes
            $('ajax_request_cookie').val(1337);
        } else if (response.state == 'error') {
            clearInterval(timerId);
            if (showNotesOnFinish) {
                $('#progressing').hide();
            }

            $('#error-progress').show();
            if ('errorMsg' in response) {
                $('#error-progress-message').html(response.errorMsg);
            }
        }
    }
};

Zentyal.ProgressIndicator.updateProgressIndicator = function(progressId, currentItemUrl,  reloadInterval, nextStepTimeout, nextStepUrl, showNotesOnFinish) {
    var time = 0,
    progressbar = $('#progress_bar');
    progressbar.progressbar({ max: false, value: 0});
    var requestParams = "progress=" + progressId ;
    var callServer = function() {
        $.ajax({
            url: currentItemUrl,
            data: requestParams,
            type : 'POST',
            complete: function (xhr) {
                Zentyal.ProgressIndicator.updatePage(xhr, progressbar, timerId, nextStepTimeout, nextStepUrl, showNotesOnFinish);
            }
        });
        time++;
        if (time >= 10) {
            time = 0;
            if (window.showAds) {
                showAds(1);
            }
        }
    };

    var timerId = setInterval(callServer, reloadInterval*1000);
};

Zentyal.ProgressIndicator.loadWhenAvailable = function(url, secondsTimeout) {
    var loadMethod = function() {
        $.ajax({
            url: url,
            success: function(text) {
                if (text) {
                    clearInterval(timerId);
                    window.location.replace(url);
                }
            }
        });
   };

    var timerId = setInterval(loadMethod, secondsTimeout*1000);
};
