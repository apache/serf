/*
 */
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <SecurityInterface/SFCertificateTrustPanel.h>

#import "serf.h"

@interface SecTrans_Buckets : NSObject
{
}
+ (OSStatus) evaluate:(SecTrustRef)trust
          trustResult:(SecTrustResultType *)trustResult;

+ (apr_status_t) showTrustCertificateDialog:(SecTrustRef)trust
                                    message:(const char *)message
                                  ok_button:(const char *)ok_button
                              cancel_button:(const char *)cancel_button;
@end

@implementation SecTrans_Buckets

/* Evaluate the trust object asynchronously. When the results are received,
   store them in the provided resultPtr address. */
+ (OSStatus) evaluate:(SecTrustRef)trust
          trustResult:(SecTrustResultType *)resultPtr
{
    dispatch_queue_t queue;
    OSStatus osstatus;

    SecTrustCallback block = ^(SecTrustRef trust, SecTrustResultType trustResult)
    {
        *resultPtr = trustResult;
    };

    queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0l);
    osstatus = SecTrustEvaluateAsync(trust, queue, block);

    return osstatus;
}

+ (apr_status_t) showTrustCertificateDialog:(SecTrustRef)trust
                                    message:(const char *)message
                                  ok_button:(const char *)ok_button
                              cancel_button:(const char *)cancel_button
{
    NSString *MessageLbl = [[NSString alloc] initWithUTF8String:message];
    NSString *OkButtonLbl = [[NSString alloc] initWithUTF8String:ok_button];
    NSString *CancelButtonLbl;

    if (cancel_button)
        CancelButtonLbl = [[NSString alloc] initWithUTF8String:cancel_button];

    SFCertificateTrustPanel *panel;
    NSApplication *app = [NSApplication sharedApplication];

    panel = [SFCertificateTrustPanel sharedCertificateTrustPanel];

    /* Put the dialog in front of the application, and give it the focus. */
    [app setActivationPolicy:NSApplicationActivationPolicyRegular];
    [app activateIgnoringOtherApps:YES];

    [panel setShowsHelp:YES];
    [panel setDefaultButtonTitle:OkButtonLbl];
    if (cancel_button)
        [panel setAlternateButtonTitle:CancelButtonLbl];

    NSInteger result = [panel runModalForTrust:trust
                                       message:MessageLbl];

    [panel release];
    [MessageLbl release];
    [OkButtonLbl release];
    if (cancel_button)
        [CancelButtonLbl release];

    if (result)
        return APR_SUCCESS;
    else
        return SERF_ERROR_SSL_USER_DENIED_CERT;
}
@end
