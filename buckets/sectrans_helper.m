/*
 */
#import <Foundation/Foundation.h>

@interface SecTrans_Buckets : NSObject
{
}
+ (OSStatus) evaluate:(SecTrustRef)trust
          trustResult:(SecTrustResultType *)trustResult;

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

@end
